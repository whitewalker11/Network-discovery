# AI Observability Network Scanner — Full Working Service

A standalone, persistent network discovery service intended as Phase 1 of an on-prem / edge AI observability platform.

## What it does

- Validates a configured CIDR before scanning.
- Uses ARP discovery on supported local Ethernet networks when Scapy/raw packet access is available.
- Falls back to TCP reachability/service discovery.
- Probes a configurable TCP port set.
- Performs reverse DNS lookup.
- Performs basic HTTP/HTTPS service fingerprinting on common web ports.
- Classifies devices using benign signals (ports, hostname, HTTP server).
- Persists device inventory in SQLite.
- Tracks online/offline state and first/last seen timestamps.
- Persists scan history.
- Shows real-time progress in a white/green web UI.
- Supports scan cancellation.
- Supports manual scans and optional periodic scans.
- Can install and run a sample Linux metrics agent over SSH on demand.
- Keeps discovery separate from onboarding and telemetry.

## Run directly on Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SCAN_CIDR=192.168.1.0/24
uvicorn app.main:app --host 0.0.0.0 --port 8010
```

Open `http://localhost:8010`.

### Test the sample Linux agent

The **Onboard** button opens a popup for an SSH username and password. The password is used for that request only and is not saved. Leave it blank to use a key at `ssh/id_ed25519`; `SSH_USER` in `.env` can prefill the username. The key directory is excluded from Git and the Docker build context.

The button copies a dependency-free Python sample agent to `~/.local/share/network-scanner/sample_agent.py`, runs it once, and displays CPU, memory, disk, and network counters. The SSH user must be able to log in, and the target needs Python 3. The sample is not a background service and does not start automatically. The web app binds to localhost because the popup can carry SSH credentials.

For ARP discovery, run with the required raw-network privileges (normally as root or with suitable Linux capabilities).

## Run with Docker

Docker uses host networking so the scanner can see the host's physical LAN. This is important: Docker bridge networking can otherwise hide the LAN from ARP/discovery.

```bash
cp .env.example .env
# edit .env to the subnet you are authorized to administer
docker compose up --build
```

Open `http://localhost:8010`.

## API

- `GET /api/health`
- `GET /api/config`
- `GET /api/stats`
- `GET /api/scan/status`
- `POST /api/scan` body: `{ "cidr": "192.168.1.0/24" }`
- `POST /api/scan/cancel`
- `GET /api/devices`
- `GET /api/devices/{ip}`
- `GET /api/onboarded`
- `POST /api/devices/{ip}/onboard` accepts `{ "username": "…", "password": "…" }` (password optional with a configured key), installs/runs the sample Linux agent over SSH, and returns metrics.
- `GET /api/scans`

## Discovery model

```text
Network configuration
        ↓
ARP discovery (when available)
        ↓
TCP reachability / port detection
        ↓
DNS + HTTP/HTTPS fingerprinting
        ↓
Device classification
        ↓
Persistent inventory
        ↓
Future: user approval → enrollment → agent → NATS telemetry
```

The **Devices** section shows network reachability from the latest scan. The separate **Onboarded devices** section shows successful agent installs and the latest metrics returned by the sample agent. A device can be offline in discovery and still have an installed agent record. The scanner does not guess credentials or exploit services. Agent installation only occurs when a user clicks **Onboard**, using credentials entered in the popup or a configured SSH key. The sample agent runs once and returns its metrics; it does not establish ongoing telemetry.

## Production hardening next

For a production deployment, add authentication/RBAC, TLS, audit logging, signed enrollment tokens, PostgreSQL/ClickHouse instead of SQLite at scale, NATS JetStream integration, network-interface selection, configurable discovery profiles, vendor OUI database, and a separate onboarding service.

Only scan networks you own or are explicitly authorized to administer.
