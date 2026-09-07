"""Exercise production startup upgrades/failures in disposable offline containers."""
import json
from pathlib import Path
import secrets
import subprocess
import time

root = Path(__file__).resolve().parents[1]
image = "waypoint:local"
schema = (root / "internal/portal/schema.sql").read_text()
vpn = (root / "internal/portal/vpn.sql").read_text()
packs = (root / "internal/portal/packs.sql").read_text()

def docker(*args, check=True, input=None):
    return subprocess.run(["docker", *args], text=True, capture_output=True, check=check, input=input)

for case in ("upgrade-v1", "upgrade-v2", "failed-migration", "newer-schema"):
    name = "waypoint-startup-" + secrets.token_hex(5)
    volume = name + "-data"
    version = 2 if case == "upgrade-v2" else 5 if case == "newer-schema" else 1
    sql = schema + (vpn if version >= 2 else "") + (packs if version >= 3 else "")
    sql += "CREATE TABLE migrations(version INTEGER PRIMARY KEY);"
    sql += "".join("INSERT INTO migrations VALUES(%d);" % n for n in range(1, version + 1))
    sql += "CREATE TABLE retained_fixture(value TEXT); INSERT INTO retained_fixture VALUES('preserve on startup');"
    if case == "failed-migration":
        sql += "CREATE TABLE vpn_grants(legacy TEXT); INSERT INTO vpn_grants VALUES('existing content');"
    helper = """
import json,sqlite3,sys
db=sqlite3.connect('/data/waypoint.db')
payload=json.load(sys.stdin)
if 'sql' in payload:
 db.executescript(payload['sql']);db.commit()
else:
 print(json.dumps({q:db.execute(q).fetchall() for q in payload['queries']}))
db.close()
"""
    def db(payload):
        result=docker("run","--rm","-i","--network","none","--user","65532:65532",
                      "--cap-drop","ALL","--security-opt","no-new-privileges:true",
                      "-v",volume+":/data","--entrypoint","python3","waypoint-browser-tests:latest",
                      "-c",helper,input=json.dumps(payload))
        return json.loads(result.stdout) if result.stdout else None
    try:
        docker("create","--name",name,"--network","none","--read-only","--cap-drop","ALL",
               "--security-opt","no-new-privileges:true","--tmpfs","/tmp:size=16m",
               "-v",volume+":/data",image)
        db({"sql":sql})
        docker("start",name)
        expected_failure=case in ("failed-migration","newer-schema")
        for _ in range(60):
            state=json.loads(docker("inspect",name).stdout)[0]["State"]
            if not state["Running"]:
                break
            if not expected_failure and docker("exec",name,"/waypoint","health",check=False).returncode == 0:
                break
            time.sleep(.1)
        logs=docker("logs",name);logs=logs.stdout+logs.stderr
        if expected_failure:
            assert not state["Running"] and state["ExitCode"]!=0
            assert "startup migration failed" in logs and "Waypoint listening" not in logs
        else:
            assert docker("exec",name,"/waypoint","health",check=False).returncode==0
            docker("stop",name)
        queries=["SELECT max(version) FROM migrations","SELECT value FROM retained_fixture"]
        if case=="failed-migration":
            queries+=["SELECT count(*) FROM sqlite_master WHERE name='vpn_devices'","SELECT legacy FROM vpn_grants"]
        values=db({"queries":queries})
        assert values[queries[0]]==[[version if expected_failure else 4]]
        assert values[queries[1]]==[["preserve on startup"]]
        if case=="failed-migration":
            assert values[queries[2]]==[[0]] and values[queries[3]]==[["existing content"]]
        print("PASS "+case+": production startup, ledger and data preservation",flush=True)
    finally:
        docker("rm","-f",name,check=False)
        docker("volume","rm",volume,check=False)
