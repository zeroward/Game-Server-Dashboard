"""Disposable, offline tunnel deployment checks. No real token/account/DNS changes."""
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import uuid

root = Path(__file__).resolve().parents[1]
project = "waypoint-tunnel-test-" + secrets.token_hex(4)

def run(*args, env=None, check=True):
    return subprocess.run(args, cwd=root, env=env, text=True, capture_output=True, check=check)

with tempfile.TemporaryDirectory(prefix="waypoint-tunnel-test-") as directory:
    path = Path(directory)
    token = base64.b64encode(json.dumps({
        "a": "0" * 32, "t": str(uuid.uuid4()),
        "s": base64.b64encode(secrets.token_bytes(32)).decode()
    }).encode()).decode()
    # Nonworking token; private directory and read-only bind readable by UID 65532.
    token_file = path / "token"
    token_file.write_text(token)
    token_file.chmod(0o444)
    env = dict(os.environ, TUNNEL_HOSTNAME="portal.example.invalid",
               TUNNEL_TOKEN_FILE=str(token_file), TUNNEL_SUBNET="172.30.249.0/29",
               TUNNEL_CONNECTOR_IP="172.30.249.2", TUNNEL_PORTAL_IP="172.30.249.3",
               VPN_ENDPOINT="vpn.example.invalid:51820", VPN_BIND_IP="127.0.0.1",
               VPN_UDP_PORT="0", APP_ENV="development",
               BASE_URL="http://localhost:8080", TRUSTED_PROXIES="")
    def compose(*args, offline=False, check=True):
        cmd = ["docker", "compose", "--env-file", "/dev/null", "-p", project,
               "-f", "compose.yaml"]
        if offline:
            cmd += ["-f", str(path / "offline.yaml")]
        return run(*cmd, *args, env=env, check=check)

    cfg = json.loads(compose("config", "--format", "json").stdout)
    portal, connector = cfg["services"]["portal"], cfg["services"]["cloudflared"]
    assert not portal.get("ports") and not connector.get("ports")
    assert portal["environment"]["APP_ENV"] == "production"
    assert portal["environment"]["BASE_URL"] == "https://portal.example.invalid"
    assert portal["environment"]["TRUSTED_PROXIES"] == "172.30.249.2/32"
    assert set(portal["networks"]) == set(connector["networks"]) == {"tunnel"}
    assert connector["user"] == "65532:65532" and connector["read_only"]
    assert connector["cap_drop"] == ["ALL"]
    assert len(connector["volumes"]) == 1
    mount = connector["volumes"][0]
    assert mount["read_only"] and mount["target"] == "/run/secrets/cloudflare-token"
    assert mount["bind"]["create_host_path"] is False
    assert token not in json.dumps(cfg), "Token leaked into Compose configuration"
    assert not connector.get("environment", {}).get("TUNNEL_TOKEN")
    assert set(cfg["services"]["gateway"]["networks"]) == {"vpn-egress"}
    assert portal["environment"]["VPN_ENABLED"] == "true"
    assert cfg["services"]["gateway"]["ports"][0]["protocol"] == "udp"
    print("PASS consolidated Compose configuration; no portal ports; exact proxy trust; isolated secret mount", flush=True)

    missing_env = dict(env)
    missing_env.pop("TUNNEL_HOSTNAME")
    missing = run("docker", "compose", "--env-file", "/dev/null", "-f", "compose.yaml",
                  "config", "-q", env=missing_env, check=False)
    assert missing.returncode != 0, "Missing hostname silently accepted"
    print("PASS missing hostname fails configuration", flush=True)

    # Internal network prevents even test connector traffic from reaching Cloudflare.
    (path / "offline.yaml").write_text(
        "networks:\n  tunnel:\n    internal: true\n  vpn-egress:\n    internal: true\n"
        "services:\n  cloudflared:\n    restart: 'no'\n"
        "  portal:\n    healthcheck:\n      interval: 1s\n")
    try:
        compose("up", "-d", "--no-build", offline=True)
        portal_id = compose("ps", "-q", "portal", offline=True).stdout.strip()
        connector_id = compose("ps", "-q", "cloudflared", offline=True).stdout.strip()
        assert portal_id and connector_id
        gateway_id = compose("ps", "-q", "gateway", offline=True).stdout.strip()
        assert gateway_id, "Full-stack startup omitted gateway"
        assert "First-time setup:" in (run("docker", "logs", portal_id).stderr), "Fresh volume did not initialize"
        gateway_info = json.loads(run("docker", "inspect", gateway_id).stdout)[0]
        assert {cap.removeprefix("CAP_") for cap in gateway_info["HostConfig"]["CapAdd"]} == {"NET_ADMIN"}
        assert set(gateway_info["NetworkSettings"]["Networks"]) == {project + "_vpn-egress"}
        control = compose("exec", "-T", "portal", "/waypoint", "health", offline=True)
        assert control.returncode == 0
        for container in (portal_id, connector_id):
            info = json.loads(run("docker", "inspect", container).stdout)[0]
            assert not info["HostConfig"].get("PortBindings")
            assert info["Config"]["User"] == "65532:65532"
            assert info["HostConfig"]["ReadonlyRootfs"]
        probe = """
(async()=>{
 let r=await fetch('http://portal:8080/healthz');
 if(r.status!==200||await r.text()!=='ok\\n')throw Error('origin health failed');
 r=await fetch('http://portal:8080/account/login');
 if(r.status!==200)throw Error('login origin unreachable');
 if(!r.headers.get('cache-control').includes('no-store'))throw Error('cache protection');
 const c=r.headers.getSetCookie().join(';');
 if(!c.includes('Secure')||!c.includes('HttpOnly'))throw Error('insecure cookies');
 console.log('PASS private bridge origin resolution, health, production cookies and no-store');
})().catch(e=>{console.error(e.message);process.exit(1)});
"""
        output = run("docker", "run", "--rm", "--network", project + "_tunnel",
                     "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                     "--entrypoint", "node", "waypoint-browser-tests:latest", "-e", probe)
        print(output.stdout.strip(), flush=True)
        time.sleep(2)
        logs = run("docker", "logs", connector_id)
        logs = logs.stdout + logs.stderr
        assert token not in logs, "Token appeared in connector logs"
        assert "permission denied" not in logs.lower()
        assert "provided tunnel token is not valid" not in logs.lower()
        ready = run("docker", "exec", connector_id, "cloudflared", "tunnel",
                    "--metrics", "127.0.0.1:2000", "ready", check=False)
        assert ready.returncode != 0, "Offline connector incorrectly reports ready"
        if not json.loads(run("docker", "inspect", connector_id).stdout)[0]["State"]["Running"]:
            assert any(reason in logs.lower() for reason in ("lookup", "dns", "network is unreachable")), "Connector failed before offline networking"
        print("PASS real non-root connector accepts token file; outbound-blocked startup is not ready", flush=True)
    finally:
        compose("down", "-v", "--remove-orphans", offline=True, check=False)
