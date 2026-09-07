"""Operator-side disposable container test; never included in the running application."""
import base64
import io
import zipfile
import datetime
import sys
import http.cookiejar
import os
import pty
import re
import secrets
import select
import subprocess
import time
import urllib.parse
import urllib.request

image = "waypoint:local"
suffix = secrets.token_hex(5)
volume = "waypoint-smoke-" + suffix
container = "waypoint-smoke-" + suffix
vpn_mode = "--vpn" in sys.argv
control_volume=volume+"-control"
gateway_volume=volume+"-gateway"
delivery_volume=volume+"-delivery"
gateway_container=container+"-gateway"
gateway_network=container+"-network"
password = secrets.token_urlsafe(24)

def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()

def interactive(*args):
    master, slave = pty.openpty()
    proc = subprocess.Popen(["docker", "run", "--rm", "-it", "-v", volume + ":/data", image, *args], stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    prompts = []
    if args == ("admin", "create"):
        prompts.append((b"Administrator username: ", b"smoke-owner\n"))
    prompts.extend([(b"Password (12+ characters): ", password.encode() + b"\n"), (b"Repeat password: ", password.encode() + b"\n")])
    buffer = b""
    deadline = time.monotonic() + 30
    try:
        while prompts and time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 1)
            if ready:
                buffer += os.read(master, 8192)
            expected, response = prompts[0]
            if expected in buffer:
                os.write(master, response)
                buffer = b""
                prompts.pop(0)
        if prompts:
            raise RuntimeError("Interactive CLI did not present expected prompt")
        assert proc.wait(timeout=30) == 0, "Interactive CLI failed"
    finally:
        if proc.poll() is None:
            proc.kill()
        os.close(master)

def request(opener, base, path, form=None):
    data = None if form is None else urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(base + path, data=data)
    if data is not None:
        req.add_header("Origin", base)
    with opener.open(req, timeout=10) as response:
        return response.read().decode(), dict(response.headers)

def signin(opener, base):
    body, _ = request(opener, base, "/account/login")
    token = re.search(r'name="gorilla.csrf.Token" value="([^"]+)"', body).group(1)
    body, _ = request(opener, base, "/account/login", {"username": "smoke-owner", "password": password, "gorilla.csrf.Token": token})
    assert "Make yourself at home" in body, "Sign in failed"

try:
    docker("volume", "create", volume)
    assert docker("image", "inspect", image, "--format", "{{.Config.User}}") == "65532:65532"
    docker("run", "--rm", "-v", volume + ":/data", image, "migrate")
    docker("run", "--rm", "-v", volume + ":/data", image, "migrate")
    interactive("admin", "create")
    docker("run", "--rm", "-v", volume + ":/data", image, "seed-demo")
    docker("run", "--rm", "-v", volume + ":/data", image, "seed-demo")
    vpn_args=[]
    if vpn_mode:
        docker("volume","create",control_volume)
        docker("volume","create",gateway_volume)
        docker("volume","create",delivery_volume)
        docker("network","create","--internal",gateway_network)
        vpn_args=["-v",control_volume+":/control","-v",delivery_volume+":/delivery","-e","VPN_DELIVERY_DIR=/delivery","-e","VPN_ENABLED=true","-e","VPN_CONTROL_DIR=/control","-e","VPN_ENDPOINT=vpn.example.invalid:51820"]
    docker("run", "-d", *vpn_args, "--name", container, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp:rw,size=16m", "-v", volume + ":/data", "-p", "127.0.0.1::8080", image)
    address = docker("port", container, "8080/tcp")
    base = "http://" + address
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    for _ in range(30):
        try:
            body, _ = request(opener, base, "/healthz")
            if body == "ok\n":
                break
        except OSError:
            pass
        time.sleep(.1)
    docker("exec", container, "/waypoint", "health")
    signin(opener, base)
    body, headers = request(opener, base, "/")
    assert body.count('class="service-card"') == 4, "Seed not idempotent"
    assert "no-store" in headers["Cache-Control"]
    if vpn_mode:
        docker("run","-d","--name",gateway_container,"--network",gateway_network,"--cap-drop=ALL","--cap-add=NET_ADMIN","--security-opt=no-new-privileges","--read-only","--sysctl","net.ipv4.ip_forward=1","--sysctl","net.ipv6.conf.all.disable_ipv6=1","-v",control_volume+":/control:ro","-v",gateway_volume+":/gateway","waypoint-gateway:local")
        for _ in range(100):
            body,_=request(opener,base,"/admin/vpn")
            if "Gateway confirmed the current policy." in body:break
            time.sleep(.15)
        assert "Gateway confirmed the current policy." in body,"Authenticated control socket failed"
        def vpn_form(fields):
            body,_=request(opener,base,"/admin/vpn")
            fields["gorilla.csrf.Token"]=re.search(r'name="gorilla.csrf.Token" value="([^"]+)"',body).group(1)
            return request(opener,base,"/admin/vpn",fields)[0]
        vpn_form({"action":"target","service":"3","label":"Smoke destination","cidr":"192.0.2.99/32","protocol":"tcp","ports":"443","enabled":"yes"})
        body,_=request(opener,base,"/my-devices")
        token=re.search(r'name="gorilla.csrf.Token" value="([^"]+)"',body).group(1)
        request(opener,base,"/my-devices",{"action":"automatic","name":"Smoke device","target":"1","reason":"Smoke test only","gorilla.csrf.Token":token})
        expiry=(datetime.datetime.now()+datetime.timedelta(days=2)).strftime("%Y-%m-%d")
        vpn_form({"action":"decide","grant":"1","version":"1","target_version":"1","state":"Approved","expires":expiry,"explanation":"Explicit smoke approval","confirm":"yes"})
        for _ in range(100):
            body,_=request(opener,base,"/admin/vpn")
            if "Gateway confirmed the current policy." in body and docker("exec",gateway_container,"wg","show","wg0","peers"):break
            time.sleep(.15)
        assert docker("exec",gateway_container,"wg","show","wg0","peers"),"Gateway did not apply explicit approval"
    docker("restart", container)
    base = "http://" + docker("port", container, "8080/tcp")
    body = ""
    for _ in range(30):
        try:
            body, _ = request(opener, base, "/")
            if "Make yourself at home" in body:
                break
        except OSError:
            pass
        time.sleep(.1)
    assert "Make yourself at home" in body, "Session/database did not survive restart"
    if vpn_mode:
        for _ in range(100):
            body,_=request(opener,base,"/my-devices")
            if "Gateway confirmed the current policy." in body:break
            time.sleep(.15)
        assert "Smoke device" in body and "192.0.2.99/32" in body,"Device policy did not survive restart"
        assert "Gateway confirmed the current policy." in body,"Gateway did not reconnect to replaced control socket"
        assert "Download connection pack" in body,"Pending encrypted pack did not survive restart"
        token=re.search(r'name="gorilla.csrf.Token" value="([^"]+)"',body).group(1)
        req=urllib.request.Request(base+"/my-devices/1/pack",data=urllib.parse.urlencode({"gorilla.csrf.Token":token}).encode(),headers={"Origin":base})
        with opener.open(req,timeout=10) as response:
            assert response.headers["Content-Type"]=="application/zip"
            assert "no-store" in response.headers["Cache-Control"]
            with zipfile.ZipFile(io.BytesIO(response.read())) as pack:
                assert pack.namelist()==["wp1.conf","READ-ME.txt"]
                config=pack.read("wp1.conf").decode()
        private=re.search(r"PrivateKey = ([^\n]+)",config).group(1)
        # Feed private bytes through stdin only; never print or put them in argv.
        public=subprocess.check_output(["docker","exec","-i",gateway_container,"wg","pubkey"],input=private+"\n",text=True).strip()
        assert public in docker("exec",gateway_container,"wg","show","wg0","peers").splitlines(),"Imported key does not match installed peer"
        assert "AllowedIPs = 192.0.2.99/32" in config
        try:
            opener.open(req,timeout=10)
            raise AssertionError("One-time pack downloaded twice")
        except urllib.error.HTTPError as error:
            assert error.code==409
        body,_=request(opener,base,"/my-devices")
        assert "Connection pack downloaded" in body and private not in body
        print("PASS private-volume control authentication; real gateway approval; encrypted pack survives restart; WireGuard key compatibility; owner one-time ZIP; control socket reconnection")
    password = secrets.token_urlsafe(24)
    interactive("admin", "recover", "--username", "smoke-owner")
    body, _ = request(opener, base, "/admin")
    assert "Welcome back." in body, "Recovery did not invalidate previous session"
    signin(opener, base)
    print("PASS non-root image; migration idempotence; interactive bootstrap/recovery; demo idempotence; isolated startup/health; login; no-store headers; restart persistence; session invalidation")
except Exception:
    print(docker("logs", "--tail", "20", container))
    raise
finally:
    if vpn_mode:
        subprocess.run(["docker","rm","-f",gateway_container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["docker", "volume", "rm", volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if vpn_mode:
        for name in (control_volume,gateway_volume,delivery_volume):
            subprocess.run(["docker","volume","rm",name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(["docker","network","rm",gateway_network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
