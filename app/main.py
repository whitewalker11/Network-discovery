import asyncio, ipaddress, json, os, re, socket, sqlite3, time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import paramiko
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
DB = DATA / "scanner.db"
DATA.mkdir(exist_ok=True)

CIDR = os.getenv("SCAN_CIDR", "192.168.1.0/24")
PORTS = [int(x) for x in os.getenv("PORTS", "22,53,80,443,445,3389,5000,8000,8001,8080,8081,8088,9000,9100").split(",") if x.strip()]
CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "128"))
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "0"))
TCP_TIMEOUT = float(os.getenv("TCP_TIMEOUT", "0.45"))
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "1.5"))
MAX_HOSTS = int(os.getenv("MAX_HOSTS", "4096"))
SSH_USER = os.getenv("SSH_USER", "").strip()
SSH_KEY_PATH = Path(os.getenv("SSH_KEY_PATH", "/run/scanner-ssh/id_ed25519"))
SSH_KNOWN_HOSTS = DATA / "ssh_known_hosts"

state = {"running": False, "cancel": False, "started_at": None, "finished_at": None, "scanned": 0, "total": 0, "found": 0, "error": None, "method": None}
scan_lock = asyncio.Lock()


def now(): return datetime.now(timezone.utc).isoformat()

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = db()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS devices (
      ip TEXT PRIMARY KEY, mac TEXT, hostname TEXT, vendor TEXT, device_type TEXT,
      status TEXT NOT NULL DEFAULT 'offline', first_seen TEXT, last_seen TEXT,
      last_scan TEXT, open_ports TEXT NOT NULL DEFAULT '[]', services TEXT NOT NULL DEFAULT '[]',
      discovery_method TEXT, response_ms REAL
    );
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT, cidr TEXT, started_at TEXT, finished_at TEXT,
      total INTEGER, found INTEGER, method TEXT, status TEXT, error TEXT
    );
    CREATE TABLE IF NOT EXISTS onboarded_devices (
      ip TEXT PRIMARY KEY, installed_at TEXT NOT NULL, last_metrics_at TEXT NOT NULL,
      agent_path TEXT NOT NULL, metrics TEXT NOT NULL, mac TEXT NOT NULL DEFAULT '',
      hostname TEXT NOT NULL DEFAULT '', device_type TEXT NOT NULL DEFAULT 'Unknown'
    );
    ''')
    columns={r['name'] for r in c.execute("PRAGMA table_info(onboarded_devices)").fetchall()}
    for name, definition in (("mac", "TEXT NOT NULL DEFAULT ''"), ("hostname", "TEXT NOT NULL DEFAULT ''"), ("device_type", "TEXT NOT NULL DEFAULT 'Unknown'")):
        if name not in columns:
            c.execute(f"ALTER TABLE onboarded_devices ADD COLUMN {name} {definition}")
    c.commit(); c.close()


def hosts_for(cidr: str):
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses > MAX_HOSTS + 2:
        raise ValueError(f"Network has {net.num_addresses} addresses; MAX_HOSTS={MAX_HOSTS}")
    return [str(x) for x in net.hosts()]


def local_arp_scan(cidr: str):
    if not SCAPY_OK: return {}
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.num_addresses > 2048: return {}
        scapy_conf.verb = 0
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(net)), timeout=2, retry=1)
        return {r.psrc: r.hwsrc for _, r in ans}
    except Exception:
        return {}

async def tcp_probe(ip, port):
    start = time.perf_counter()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), TCP_TIMEOUT)
        w.close()
        try: await w.wait_closed()
        except Exception: pass
        return port, (time.perf_counter()-start)*1000
    except Exception:
        return port, None

async def reverse_dns(ip):
    try:
        return (await asyncio.to_thread(socket.gethostbyaddr, ip))[0]
    except Exception:
        return ""

async def http_probe(ip, port):
    scheme = "https" if port in (443,8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        async with httpx.AsyncClient(verify=False, timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
            r = await client.get(url)
            title = ""
            low = r.text[:50000].lower()
            a, b = low.find("<title>"), low.find("</title>")
            if a >= 0 and b > a: title = r.text[a+7:b].strip()[:160]
            return {"port": port, "url": str(r.url), "status": r.status_code, "server": r.headers.get("server", ""), "title": title}
    except Exception:
        return None


def classify(hostname, ports, services):
    s = ((hostname or "") + " " + " ".join(x.get("server", "") for x in services)).lower()
    if 3389 in ports: return "Windows / RDP"
    if 445 in ports: return "Windows / SMB"
    if 22 in ports and any(p in ports for p in (80,443,8000,8080,8081,9000,9100)): return "Linux / Edge"
    if 22 in ports: return "Linux / SSH"
    if 80 in ports or 443 in ports or services: return "Web / Network device"
    return "Unknown"


def upsert(d):
    c = db()
    c.execute('''INSERT INTO devices(ip,mac,hostname,vendor,device_type,status,first_seen,last_seen,last_scan,open_ports,services,discovery_method,response_ms)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac,hostname=excluded.hostname,device_type=excluded.device_type,status='online',last_seen=excluded.last_seen,last_scan=excluded.last_scan,open_ports=excluded.open_ports,services=excluded.services,discovery_method=excluded.discovery_method,response_ms=excluded.response_ms''',
      (d['ip'],d.get('mac',''),d.get('hostname',''),d.get('vendor',''),d.get('device_type','Unknown'), 'online',d.get('first_seen',now()),d['last_seen'],d['last_scan'],json.dumps(d['open_ports']),json.dumps(d['services']),d['discovery_method'],d.get('response_ms')))
    c.commit(); c.close()


def mark_all_offline(cidr):
    # Only devices belonging to this scanned network are considered offline.
    net = ipaddress.ip_network(cidr, strict=False)
    c = db(); rows = c.execute("SELECT ip FROM devices").fetchall()
    for r in rows:
        try:
            if ipaddress.ip_address(r['ip']) in net:
                c.execute("UPDATE devices SET status='offline' WHERE ip=?", (r['ip'],))
        except Exception: pass
    c.commit(); c.close()

async def inspect_host(ip, mac=""):
    ports = []
    results = await asyncio.gather(*(tcp_probe(ip,p) for p in PORTS))
    timings = [ms for p,ms in results if ms is not None]
    for p, ms in results:
        if ms is not None: ports.append(p)
    hostname = await reverse_dns(ip)
    services = []
    for p in ports:
        if p in (80,443,8000,8001,8080,8081,8088,9000,9100,5000):
            x = await http_probe(ip,p)
            if x: services.append(x)
    return {"ip":ip,"mac":mac,"hostname":hostname,"open_ports":sorted(ports),"services":services,
            "device_type":classify(hostname,ports,services),"discovery_method":"arp+tcp" if mac else "tcp",
            "response_ms":min(timings) if timings else None}

async def run_scan(cidr=None):
    global state
    cidr = cidr or CIDR
    hosts = hosts_for(cidr)
    arp = await asyncio.to_thread(local_arp_scan, cidr)
    # If ARP is available, use it as the primary host-discovery signal; TCP probing then fingerprints services.
    targets = sorted(set(arp.keys()) | set(hosts if not arp else arp.keys()), key=lambda x: ipaddress.ip_address(x))
    state.update(running=True,cancel=False,started_at=now(),finished_at=None,scanned=0,total=len(targets),found=0,error=None,method='ARP + TCP' if arp else 'TCP')
    mark_all_offline(cidr)
    c = db(); cur = c.execute("INSERT INTO scans(cidr,started_at,total,method,status) VALUES(?,?,?,?,?)",(cidr,state['started_at'],len(targets),state['method'],'running')); scan_id=cur.lastrowid; c.commit(); c.close()
    sem = asyncio.Semaphore(CONCURRENCY)
    found = 0
    async def one(ip):
        nonlocal found
        async with sem:
            if state['cancel']: return
            d = await inspect_host(ip, arp.get(ip,''))
            state['scanned'] += 1
            if d['mac'] or d['open_ports']:
                found += 1; state['found'] = found
                d['last_seen']=now(); d['last_scan']=now()
                c2=db(); old=c2.execute("SELECT first_seen FROM devices WHERE ip=?",(ip,)).fetchone(); c2.close()
                d['first_seen'] = old['first_seen'] if old else now()
                upsert(d)
    try:
        await asyncio.gather(*(one(ip) for ip in targets))
        status='cancelled' if state['cancel'] else 'completed'
        err=None
    except Exception as e:
        status='failed'; err=str(e); state['error']=err
    state.update(running=False,finished_at=now())
    c=db(); c.execute("UPDATE scans SET finished_at=?,found=?,status=?,error=? WHERE id=?",(state['finished_at'],state['found'],status,err,scan_id)); c.commit(); c.close()

async def periodic():
    while True:
        await asyncio.sleep(max(SCAN_INTERVAL, 5))
        if SCAN_INTERVAL and not state['running']:
            try: await run_scan()
            except Exception as e: state['error']=str(e)

class ScanRequest(BaseModel): cidr: str | None = None
class OnboardRequest(BaseModel):
    username: str
    password: str | None = None

@asynccontextmanager
async def lifespan(app):
    init_db()
    task=None
    if SCAN_INTERVAL > 0: task=asyncio.create_task(periodic())
    yield
    if task: task.cancel()

app=FastAPI(title="AI Observability Network Scanner", version="1.0.0", lifespan=lifespan)

@app.get("/")
async def index(): return FileResponse(ROOT/"static"/"index.html")

@app.get("/api/health")
async def health(): return {"ok":True,"scapy":SCAPY_OK,"time":now()}

@app.get("/api/config")
async def config(): return {"cidr":CIDR,"ports":PORTS,"concurrency":CONCURRENCY,"interval":SCAN_INTERVAL,"max_hosts":MAX_HOSTS,"arp_available":SCAPY_OK,"ssh_user":SSH_USER}

@app.get("/api/scan/status")
async def scan_status(): return state

@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    if state['running']: raise HTTPException(409,"A scan is already running")
    cidr=req.cidr or CIDR
    try: hosts_for(cidr)
    except ValueError as e: raise HTTPException(400,str(e))
    asyncio.create_task(run_scan(cidr)); return {"started":True,"cidr":cidr}

@app.post("/api/scan/cancel")
async def cancel_scan():
    state['cancel']=True; return {"cancel_requested":True}

@app.get("/api/devices")
async def devices(status: str | None=None):
    c=db(); q="""SELECT d.*,(o.ip IS NOT NULL) AS onboarded,o.installed_at AS agent_installed_at,
      o.last_metrics_at AS agent_last_metrics_at FROM devices d
      LEFT JOIN onboarded_devices o ON o.ip=d.ip"""; args=[]
    q += " WHERE o.ip IS NULL"
    if status: q += " AND d.status=?"; args.append(status)
    q += " ORDER BY d.status='online' DESC, d.last_seen DESC"
    rows=c.execute(q,args).fetchall(); c.close()
    return [{**dict(r),"onboarded":bool(r['onboarded']),"open_ports":json.loads(r['open_ports']),"services":json.loads(r['services'])} for r in rows]

@app.get("/api/devices/{ip}")
async def device(ip: str):
    c=db(); r=c.execute("SELECT * FROM devices WHERE ip=?",(ip,)).fetchone(); c.close()
    if not r: raise HTTPException(404,"Device not found")
    x=dict(r); x['open_ports']=json.loads(x['open_ports']); x['services']=json.loads(x['services']); return x

def install_sample_agent(ip: str, username: str, password: str | None):
    agent_source=(ROOT/"agent"/"sample_agent.py").read_text(encoding="utf-8")
    remote_script=(
        "set -eu\n"
        "agent_dir=\"$HOME/.local/share/network-scanner\"\n"
        "mkdir -p \"$agent_dir\"\n"
        "cat > \"$agent_dir/sample_agent.py\" <<'SCANNER_AGENT_PY'\n"
        f"{agent_source}"
        "SCANNER_AGENT_PY\n"
        "chmod 700 \"$agent_dir/sample_agent.py\"\n"
        "python3 \"$agent_dir/sample_agent.py\"\n"
    )
    client=paramiko.SSHClient()
    SSH_KNOWN_HOSTS.touch(exist_ok=True)
    client.load_host_keys(str(SSH_KNOWN_HOSTS))
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        auth={"password":password} if password else {"key_filename":str(SSH_KEY_PATH)}
        client.connect(ip,username=username,timeout=5,auth_timeout=8,banner_timeout=8,
                       look_for_keys=False,allow_agent=False,**auth)
        stdin,stdout,stderr=client.exec_command("sh -s",timeout=35)
        stdin.write(remote_script)
        stdin.flush()
        stdin.channel.shutdown_write()
        output=stdout.read().decode("utf-8",errors="replace")
        error=stderr.read().decode("utf-8",errors="replace")
        status=stdout.channel.recv_exit_status()
        if status:
            detail=(error or output or "Remote command failed").strip()[-500:]
            raise HTTPException(502,f"Agent installation failed: {detail}")
        try:
            metrics=json.loads(output.strip().splitlines()[-1])
        except (IndexError,json.JSONDecodeError):
            raise HTTPException(502,"Agent installed but did not return valid metrics")
        return {"installed":True,"ip":ip,"agent_path":"~/.local/share/network-scanner/sample_agent.py","metrics":metrics}
    except paramiko.AuthenticationException:
        raise HTTPException(401,"SSH authentication failed; check the username and credentials")
    except (socket.timeout,TimeoutError):
        raise HTTPException(504,"SSH agent installation timed out")
    except paramiko.SSHException as e:
        raise HTTPException(502,f"SSH connection failed: {e}")
    finally:
        client.close()

@app.post("/api/devices/{ip}/onboard")
async def onboard_device(ip: str, req: OnboardRequest):
    c=db(); r=c.execute("SELECT ip,open_ports,mac,hostname,device_type FROM devices WHERE ip=?",(ip,)).fetchone(); c.close()
    if not r: raise HTTPException(404,"Device not found in inventory")
    open_ports=json.loads(r['open_ports'])
    if 22 not in open_ports:
        raise HTTPException(400,"Device has no discovered SSH service on port 22")
    username=req.username.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*\$?",username):
        raise HTTPException(400,"Enter a valid SSH username")
    if not req.password and not SSH_KEY_PATH.is_file():
        raise HTTPException(400,"Enter an SSH password or configure the key at ssh/id_ed25519")
    result=await asyncio.to_thread(install_sample_agent,ip,username,req.password or None)
    timestamp=now()
    metrics=result['metrics']
    mac=r['mac'] or metrics.get('mac_address','')
    hostname=r['hostname'] or metrics.get('hostname','')
    c=db()
    c.execute('''INSERT INTO onboarded_devices(ip,installed_at,last_metrics_at,agent_path,metrics,mac,hostname,device_type)
      VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET last_metrics_at=excluded.last_metrics_at,
      agent_path=excluded.agent_path,metrics=excluded.metrics,
      mac=CASE WHEN excluded.mac='' THEN onboarded_devices.mac ELSE excluded.mac END,
      hostname=CASE WHEN excluded.hostname='' THEN onboarded_devices.hostname ELSE excluded.hostname END,
      device_type=excluded.device_type''',
      (ip,timestamp,timestamp,result['agent_path'],json.dumps(metrics),mac,hostname,r['device_type'] or 'Unknown'))
    c.execute("""UPDATE devices SET mac=CASE WHEN mac='' THEN ? ELSE mac END,
      hostname=CASE WHEN hostname='' THEN ? ELSE hostname END,status='online',last_seen=? WHERE ip=?""",
      (mac,hostname,timestamp,ip))
    c.commit(); c.close()
    result['installed_at']=timestamp
    result['last_metrics_at']=timestamp
    return result

@app.get("/api/onboarded")
async def onboarded_devices():
    c=db()
    rows=c.execute('''SELECT o.ip,o.installed_at,o.last_metrics_at,o.agent_path,o.metrics,
      COALESCE(NULLIF(o.mac,''),d.mac,'') AS mac,
      COALESCE(NULLIF(o.hostname,''),d.hostname,'') AS hostname,
      COALESCE(NULLIF(o.device_type,'Unknown'),d.device_type,'Unknown') AS device_type,
      COALESCE(d.status,'unknown') AS reachability,d.open_ports,d.first_seen,d.last_seen
      FROM onboarded_devices o LEFT JOIN devices d ON d.ip=o.ip
      ORDER BY o.last_metrics_at DESC''').fetchall()
    c.close()
    return [{**dict(r),"metrics":json.loads(r['metrics']),"agent_status":"Installed",
             "open_ports":json.loads(r['open_ports'] or '[]')} for r in rows]

@app.get("/api/scans")
async def scans():
    c=db(); rows=c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 50").fetchall(); c.close(); return [dict(r) for r in rows]

@app.get("/api/stats")
async def stats():
    c=db(); total=c.execute("SELECT count(*) n FROM devices").fetchone()['n']; online=c.execute("SELECT count(*) n FROM devices WHERE status='online'").fetchone()['n']; ports=c.execute("SELECT open_ports FROM devices").fetchall(); c.close();
    port_count=sum(len(json.loads(x['open_ports'])) for x in ports)
    return {"devices":total,"online":online,"offline":total-online,"open_services":port_count}
