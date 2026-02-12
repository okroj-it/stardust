<p align="center">
  <img src="https://img.shields.io/badge/%E2%9A%A1-Stardust-8b5cf6?style=for-the-badge&labelColor=0d1117" alt="Stardust" />
</p>

<h3 align="center">Orchestrating the Spiders from Mars</h3>

<p align="center">
  <em>A lightweight server monitoring & orchestration platform built in Zig.<br/>
  Deploy zero-dependency agents to your Linux fleet, collect real-time telemetry over WebSockets,<br/>
  open interactive SSH terminals, manage packages, and run Ansible playbooks — all from a single binary and a clean React dashboard.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Zig-0.15.2-f7a41d?style=flat-square&logo=zig&logoColor=white" alt="Zig" />
  <img src="https://img.shields.io/badge/React-19-61dafb?style=flat-square&logo=react&logoColor=white" alt="React" />
  <img src="https://img.shields.io/badge/TypeScript-5.9-3178c6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript" />
  <img src="https://img.shields.io/badge/Tailwind-4.1-06b6d4?style=flat-square&logo=tailwindcss&logoColor=white" alt="Tailwind" />
  <img src="https://img.shields.io/badge/SQLite-3-003b57?style=flat-square&logo=sqlite&logoColor=white" alt="SQLite" />
  <img src="https://img.shields.io/badge/Ansible-optional-ee0000?style=flat-square&logo=ansible&logoColor=white" alt="Ansible" />
  <img src="https://img.shields.io/badge/license-MIT-22c55e?style=flat-square" alt="MIT License" />
</p>

<p align="center">
  <sub><em>"Ground Control to Major Tom — commencing countdown, engines on."</em></sub>
</p>

---

## Nomenclature

Every component draws from David Bowie's *Space Oddity* and *Ziggy Stardust* mythology.

| Component | Codename | Role | Reference |
|:----------|:---------|:-----|:----------|
| Server | **Ground Control** | HTTP/WS server, REST API, telemetry hub | *"This is Ground Control to Major Tom"* |
| Agent | **Spider** | Zero-dependency monitoring agent deployed to nodes | *"The Spiders from Mars"* |
| Web UI | **The Capsule** | React dashboard for fleet overview and management | *"Sitting in a tin can, far above the world"* |
| Deployer | **Major Tom** | SSH-based agent deployment & lifecycle manager | *"Commencing countdown, engines on"* |
| Web Terminal | **Space Oddity** | Browser-based SSH terminal via PTY relay | *"Here am I floating round my tin can"* |
| Ansible | **Ziggy** | Optional Ansible orchestration engine | *"Ziggy played guitar"* |

---

## Architecture

```
                    ┌──────────────────┐
                    │   The Capsule    │
                    │  React + xterm   │
                    └────────┬─────────┘
                             │ HTTPS + WSS
                             ▼
                    ┌──────────────────┐       WebSocket (TLS)       ┌─────────────┐
                    │  Ground Control  │◄──────────────────────────►│   Spider     │
                    │    Zig + zap     │                             │  (per node)  │
                    │                  │──── SSH (Major Tom) ────►  │  zero-dep    │
                    │                  │──── SSH PTY (Oddity) ───►  │              │
                    └────────┬─────────┘                             └─────────────┘
                             │
                    ┌────────▼─────────┐       ┌─────────────────┐
                    │  SQLite (zqlite) │       │    Ansible       │
                    │  nodes, users,   │       │  (optional)      │
                    │  credentials     │       │  galaxy + plays  │
                    └──────────────────┘       └─────────────────┘
```

Ground Control is a **single Zig binary** that serves the embedded React frontend, exposes a REST API, and maintains persistent WebSocket connections to every Spider. Major Tom handles the full agent lifecycle — uploading binaries over SSH, installing systemd services, and managing credentials with AES-GCM-256 encryption.

Spiders are **statically-linked, zero-dependency** Zig binaries that run on any Linux box. They collect system telemetry and stream it back to Ground Control in real time.

When Ansible is detected on the host, **Ziggy** lights up — generating dynamic inventories from your node database and letting you run playbooks across your fleet with streaming output, all from The Capsule.

---

## Features

### Monitoring & Telemetry

| Metric | Source | Details |
|:-------|:-------|:--------|
| CPU | `/proc/stat` | Per-core usage %, I/O wait % |
| Memory | `/proc/meminfo` | Total, free, available, buffers, cached, active, inactive |
| Swap | `/proc/meminfo` | Total, used, free, usage % |
| Load | `/proc/loadavg` | 1/5/15 min averages, running/total processes |
| Disk I/O | `/proc/diskstats` | Reads/writes, sectors, queue depth, I/O time |
| Filesystems | `statvfs` | Per-mount usage, total/free/available, FS type |
| Network | `/proc/net/dev` | Per-interface RX/TX bytes, packets, errors, drops |
| Temperatures | `/sys/class/thermal/` | Per-zone sensor readings in Celsius |
| Connections | `/proc/net/tcp{,6}` | Established, listen, time\_wait, close\_wait counts |
| Uptime | `/proc/uptime` | System uptime in seconds |

### System Identification

Spiders auto-detect and report: **OS** (name, version, ID), **kernel**, **architecture**, **CPU model & cores**, **total RAM**, and **package manager** (apt, dnf, yum, pacman, apk).

### Deployment (Major Tom)

- **One-click onboarding** — SSH into a target, upload Spider binary, install systemd service, verify connection
- **Clean teardown** — Stop service, uninstall unit, remove binary, wipe credentials from database
- **Encrypted credentials** — SSH keys and sudo passwords encrypted at rest with AES-GCM-256 (bcrypt-pbkdf derived keys)
- **Architecture-aware** — Detects target arch before deployment

### Package Management

- **Unified interface** for `apt`, `dnf`, `yum`, `pacman`, and `apk`
- **Check for updates** — See available upgrades in a sortable table
- **Upgrade / Full Upgrade** — Run upgrades with live streaming terminal output
- **Cache refresh** — Update package indexes remotely

### Web Terminal (Space Oddity)

- **Browser-based SSH** — Full interactive shell directly from The Capsule, no local SSH client needed
- **PTY relay** — Ground Control proxies WebSocket frames to SSH stdin/stdout with forced PTY allocation
- **Nerd Font support** — Powerline glyphs and icons render correctly (loads symbol font from CDN as fallback)
- **TUI-compatible** — `mc`, `htop`, `vim`, and other curses applications work out of the box (`TERM=xterm-256color`)
- **Auto-sizing** — Terminal dimensions sync on connect and window resize
- **Secure sessions** — JWT-authenticated, temporary key files (mode `0600`) cleaned up on disconnect, key material zeroed in memory

### Ansible Integration (Ziggy)

> *Conditionally enabled — if `ansible-playbook` is found on the Ground Control host, the feature lights up automatically. Otherwise it stays invisible.*

- **Auto-detection** — Searches `$PATH`, pipx venvs, and common install locations
- **Dynamic inventory** — Generated on-the-fly from your node database with decrypted SSH credentials
- **Playbook editor** — Write YAML directly in The Capsule with syntax-highlighted textarea
- **Requirements.yml** — Install Galaxy roles and collections before playbook runs
- **Node targeting** — Select specific nodes or run against the entire fleet
- **Streaming output** — Watch `ansible-playbook` output in real time via polling
- **Secure cleanup** — All temp files (inventory, keys, playbooks, requirements) deleted after runs; passwords zeroed in memory

### Authentication & Security

- **JWT authentication** — HMAC-SHA256 signed tokens with configurable expiry
- **Password management** — bcrypt-hashed passwords, changeable from The Capsule
- **API protection** — All management endpoints require valid bearer tokens
- **Credential encryption** — AES-GCM-256 for SSH keys and sudo passwords at rest
- **Secure memory** — `std.crypto.secureZero` on all decrypted secrets after use

### Dashboard (The Capsule)

- **Embedded UI** — Compiled into the server binary, no separate web server needed
- **Real-time metrics** — Sub-second telemetry with auto-refreshing node cards
- **Node detail panel** — Per-core CPU bars, sparkline charts, filesystem gauges, connection counts
- **Historical data** — SQLite-backed telemetry archive with time-series queries
- **Responsive layout** — Grid view for fleet overview, detail panel for deep dives
- **Dark theme** — Purpose-built dark interface with subtle gradients and animations

---

## Quick Start

### Prerequisites

- [**Zig 0.15.2+**](https://ziglang.org/download/) — compiler for server and agent
- [**Node.js**](https://nodejs.org/) (or [Bun](https://bun.sh/)) — for building the frontend

### Build

```bash
# 1. Build the frontend
cd frontend && npm install && npm run build && cd ..

# 2. Build server + agent
zig build -Dcpu=baseline -Doptimize=ReleaseSafe
```

> **Note:** `-Dcpu=baseline` ensures compatibility with older x86\_64 CPUs. Omit it if all your machines have modern instruction sets.

Binaries land in `zig-out/bin/`:

| Binary | Size | Description |
|:-------|:-----|:------------|
| `stardust-server` | ~12 MB | Ground Control (server + embedded UI) |
| `stardust-spider` | ~6.5 MB | Spider agent (zero dependencies, static) |

### Configuration

| Variable | Required | Default | Description |
|:---------|:---------|:--------|:------------|
| `STARDUST_SECRET` | **Yes** | — | Master encryption key (>= 16 chars). Enables deployment, auth, and credential encryption. |
| `STARDUST_ADMIN_USER` | No | `admin` | Initial admin username |
| `STARDUST_ADMIN_PASS` | No | `admin` | Initial admin password |

```bash
export STARDUST_SECRET="your-secret-key-minimum-16-chars"
```

### Run

```bash
./zig-out/bin/stardust-server \
  --port 8933 \
  --db stardust.db \
  --agent-binary zig-out/bin/stardust-spider \
  --server-url wss://your-domain.example/ws
```

Open `http://localhost:8933` to access The Capsule.

### Server Flags

```
  --port PORT          HTTP/WS listen port (default: 8080)
  --db PATH            SQLite database path (default: stardust.db)
  --agent-binary PATH  Path to Spider binary for deployment
  --server-url URL     Public WS URL baked into Spider config (default: ws://localhost:8080/ws)
  -h, --help           Show help
```

### Spider Flags

```
  --stdout             Print stats to stdout as JSON (testing mode)
  --server URL         Ground Control WebSocket URL (e.g. wss://host/ws)
  --token TOKEN        Authentication token
  --agent-id ID        Unique Spider identifier
  --interval MS        Collection interval in milliseconds (default: 5000)
  -h, --help           Show help
```

> Spiders are normally deployed automatically by Major Tom. Manual invocation is only needed for testing.

---

## Deploy a Spider

From The Capsule, click **Add Node** and provide:

1. **Hostname / IP** and SSH port
2. **SSH user** and **private key**
3. **Sudo password** (optional — needed for package management and privileged Ansible tasks)

Major Tom will:
1. Test SSH connectivity and detect architecture
2. Upload the Spider binary
3. Install a systemd service (`stardust-spider.service`)
4. Start the service and verify the WebSocket connection

The node appears on the dashboard within seconds.

---

## Ansible Integration

If `ansible-playbook` is installed on the Ground Control host (via system packages, pip, or pipx), Stardust auto-detects it at startup and enables the **Ansible** button in The Capsule.

### How It Works

1. **Inventory** — Generated dynamically from your node database. SSH keys are decrypted to temporary files (mode `0600`), sudo passwords are injected as host vars.
2. **Requirements** — Optional `requirements.yml` runs `ansible-galaxy install --force` before the playbook.
3. **Execution** — `ansible-playbook` runs with `ANSIBLE_NOCOLOR=1` and `--force-handlers`. Output streams to The Capsule in real time.
4. **Cleanup** — All temporary files (inventory, keys, playbooks, requirements) are deleted. Passwords are securely zeroed in memory.

### Supported Install Locations

Stardust searches for `ansible-playbook` in:

| Location | Example |
|:---------|:--------|
| `$PATH` | `/usr/bin/ansible-playbook` |
| pipx venv | `~/.local/share/pipx/venvs/ansible/bin/ansible-playbook` |
| `/usr/local/bin` | System-wide manual install |
| `/usr/bin` | Package manager install |

---

## TLS / Reverse Proxy

Ground Control binds **plain HTTP** internally. In production, place it behind a TLS-terminating reverse proxy so that:

- The Capsule is served over **HTTPS**
- Spiders connect via **`wss://`** (TLS WebSocket) rather than plain `ws://`
- Auth tokens and SSH credentials are never sent in the clear

Pass `--server-url` with your public `wss://` endpoint — this address gets baked into each Spider's config at deploy time.

```bash
# Example: Ground Control on port 8933, Traefik terminates TLS on 443
./stardust-server --port 8933 --server-url wss://stardust.example.com/ws ...
```

> **Important:** WebSocket upgrade requires **HTTP/1.1**. If your reverse proxy defaults to h2, ensure the `/ws` route falls back to HTTP/1.1.

### Example Reverse Proxy Configs

<details>
<summary><strong>Traefik (Docker labels)</strong></summary>

```yaml
labels:
  - "traefik.http.routers.stardust.rule=Host(`stardust.example.com`)"
  - "traefik.http.routers.stardust.tls.certresolver=letsencrypt"
  - "traefik.http.services.stardust.loadbalancer.server.port=8933"
```

</details>

<details>
<summary><strong>Caddy</strong></summary>

```
stardust.example.com {
    reverse_proxy localhost:8933
}
```

</details>

<details>
<summary><strong>nginx</strong></summary>

```nginx
server {
    listen 443 ssl;
    server_name stardust.example.com;

    ssl_certificate     /etc/letsencrypt/live/stardust.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/stardust.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8933;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

</details>

---

## API Reference

All endpoints (except health and login) require `Authorization: Bearer <token>`.

### Auth

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/auth/login` | Authenticate, returns JWT |
| `POST` | `/api/auth/password` | Change password |

### Nodes

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/nodes` | List all nodes with live status |
| `POST` | `/api/nodes` | Add a new node |
| `GET` | `/api/nodes/:id` | Get node details |
| `PATCH` | `/api/nodes/:id` | Update node (credentials) |
| `DELETE` | `/api/nodes/:id` | Delete node from database |
| `GET` | `/api/nodes/:id/stats` | Latest telemetry snapshot |
| `GET` | `/api/nodes/:id/stats/history?count=N` | Historical snapshots |
| `POST` | `/api/nodes/check` | Pre-deployment SSH connectivity test |

### Deployment (Major Tom)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/nodes/:id/deploy?step=upload` | Upload Spider binary |
| `POST` | `/api/nodes/:id/deploy?step=install` | Install systemd service |
| `POST` | `/api/nodes/:id/deploy?step=start` | Start Spider service |
| `POST` | `/api/nodes/:id/deploy?step=connect` | Test SSH connection |
| `POST` | `/api/nodes/:id/deploy?step=stop` | Stop Spider service |
| `POST` | `/api/nodes/:id/deploy?step=uninstall` | Remove systemd unit |
| `POST` | `/api/nodes/:id/deploy?step=remove-binary` | Delete Spider binary |
| `POST` | `/api/nodes/:id/deploy?step=wipe-creds` | Wipe credentials from DB |
| `POST` | `/api/nodes/:id/deploy?step=detect-pkg-manager` | Detect package manager |

### Package Management

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/nodes/:id/deploy?step=pkg-refresh-start&pkg=apt` | Start cache refresh (streaming) |
| `POST` | `/api/nodes/:id/deploy?step=pkg-refresh-poll&job=ID&offset=N` | Poll job output |
| `POST` | `/api/nodes/:id/deploy?step=pkg-job-start&pkg=apt&action=check-updates` | Start package job |

Package actions: `check-updates`, `upgrade`, `full-upgrade`

### Ansible

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/capabilities` | Server feature flags (ansible, deployer, auth) |
| `GET` | `/api/ansible/status` | Ansible version and availability |
| `POST` | `/api/ansible/run` | Run playbook `{playbook, nodes?, requirements?}` |
| `POST` | `/api/ansible/poll?job=ID&offset=N` | Poll playbook output |

### System

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/health` | Health check (no auth) |

### WebSocket

| Endpoint | Description |
|:---------|:------------|
| `WS /ws` | Spider telemetry stream |
| `WS /ws/terminal` | Interactive SSH terminal (Space Oddity) |

Spider message types (`/ws`):
- `auth` — `{type, agent_id, token, version}`
- `sysinfo` — `{type, agent_id, os_id, arch, cpu_model, ...}`
- `stats` — Full SystemStats JSON payload every 5 seconds

Terminal protocol (`/ws/terminal`) — mixed text/binary framing:
- **Client → Server** (text): `{type:"auth", token, node_id, cols, rows}` · `{type:"resize", cols, rows}`
- **Client → Server** (binary): Raw terminal input (keystrokes)
- **Server → Client** (text): `{type:"ready"}` · `{type:"error", message}` · `{type:"closed"}`
- **Server → Client** (binary): Raw terminal output (PTY data)

---

## Tech Stack

| Layer | Technology | Purpose |
|:------|:-----------|:--------|
| Server | [Zig 0.15](https://ziglang.org/) + [zap](https://github.com/zigzap/zap) | HTTP/WS server, static binary |
| Database | SQLite via [zqlite](https://github.com/karlseguin/zqlite.zig) | Nodes, users, credentials, telemetry |
| Agent | Zig 0.15 (zero deps) | Static ~1MB binary for any Linux x86\_64 |
| Crypto | `std.crypto` | bcrypt-pbkdf, AES-GCM-256, HMAC-SHA256 |
| Frontend | [React 19](https://react.dev/) + [TypeScript 5.9](https://www.typescriptlang.org/) | Interactive dashboard |
| Styling | [Tailwind CSS 4](https://tailwindcss.com/) | Utility-first dark theme |
| Terminal | [xterm.js 6](https://xtermjs.org/) | Browser-based terminal emulator |
| Icons | [Lucide](https://lucide.dev/) | Consistent icon set |
| Animations | [Motion](https://motion.dev/) | Smooth UI transitions |
| Build | [Vite 7](https://vite.dev/) | Frontend bundling and HMR |
| Orchestration | [Ansible](https://www.ansible.com/) (optional) | Fleet-wide playbook execution |

---

## Project Structure

```
stardust/
├── src/
│   ├── server/
│   │   ├── main.zig          # Ground Control entry point
│   │   ├── api.zig           # REST API routes & handlers
│   │   ├── auth.zig          # JWT authentication
│   │   ├── crypto.zig        # AES-GCM-256 encryption engine
│   │   ├── db.zig            # SQLite database layer
│   │   ├── store.zig         # In-memory telemetry store
│   │   ├── ws_handler.zig    # WebSocket handler
│   │   ├── deployer.zig      # Major Tom (SSH deployment)
│   │   ├── terminal_handler.zig # Space Oddity (web terminal)
│   │   └── ansible.zig       # Ziggy (Ansible integration)
│   ├── agent/
│   │   ├── main.zig          # Spider entry point
│   │   ├── collector.zig     # Telemetry orchestrator
│   │   ├── sysinfo.zig       # System identification
│   │   ├── ws_client.zig     # WebSocket client (TLS)
│   │   └── proc/             # /proc & /sys parsers
│   │       ├── cpu.zig       ├── memory.zig
│   │       ├── swap.zig      ├── loadavg.zig
│   │       ├── disk.zig      ├── filesystem.zig
│   │       ├── network.zig   ├── thermal.zig
│   │       ├── connections.zig └── uptime.zig
│   └── common/               # Shared types & protocol
├── frontend/
│   └── src/
│       ├── App.tsx            # Main dashboard
│       ├── components/
│       │   ├── node-card.tsx       # Fleet overview cards
│       │   ├── node-detail.tsx     # Deep-dive metrics panel
│       │   ├── add-node-modal.tsx  # Onboarding wizard
│       │   ├── remove-node-modal.tsx
│       │   ├── terminal-modal.tsx  # Package management
│       │   ├── web-terminal.tsx   # SSH terminal (Space Oddity)
│       │   ├── ansible-modal.tsx   # Playbook runner
│       │   ├── login-page.tsx
│       │   └── profile-modal.tsx
│       ├── hooks/
│       │   └── use-stats.ts   # Real-time data hooks
│       └── lib/
│           ├── api.ts         # API client
│           └── auth.ts        # Token management
├── build.zig                  # Zig build system
├── build.zig.zon              # Dependencies
└── embedded_ui.zig            # UI asset embedding
```

---

## Production Deployment

```bash
# 1. Build
cd frontend && npm ci && npm run build && cd ..
zig build -Dcpu=baseline -Doptimize=ReleaseSafe

# 2. Deploy binary to your server
scp zig-out/bin/stardust-server you@server:/opt/stardust/

# 3. Configure and run
export STARDUST_SECRET="$(openssl rand -hex 32)"
export STARDUST_ADMIN_PASS="your-secure-password"

/opt/stardust/stardust-server \
  --port 8933 \
  --db /opt/stardust/stardust.db \
  --agent-binary /opt/stardust/stardust-spider \
  --server-url wss://stardust.yourdomain.com/ws
```

### Control Script

For managed deployments, use a control script:

```bash
#!/bin/bash
# ctl.sh — start | stop | restart | status | logs
case "$1" in
  start)   nohup ./stardust-server --port 8933 ... >> server.log 2>&1 & echo $! > .pid ;;
  stop)    kill "$(cat .pid)" && rm .pid ;;
  restart) $0 stop; sleep 1; $0 start ;;
  status)  kill -0 "$(cat .pid)" 2>/dev/null && echo "Running" || echo "Stopped" ;;
  logs)    tail -f server.log ;;
esac
```

---

<p align="center">
  <sub><em>"Planet Earth is blue, and there's nothing I can do."</em></sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/MIT-license-22c55e?style=flat-square" alt="MIT" />
</p>
