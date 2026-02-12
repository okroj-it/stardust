# Stardust

**Orchestrating the Spiders from Mars**

A lightweight server monitoring and deployment platform built in Zig.
Deploy zero-dependency agents to your Linux fleet, collect real-time telemetry over WebSockets, and manage packages — all from a single binary and a clean React dashboard.

---

*"Ground Control to Major Tom — commencing countdown, engines on."*

---

## Nomenclature

Every component draws from David Bowie's *Space Oddity* and *Ziggy Stardust* mythology.

| Component | Codename | Role | Reference |
|-----------|----------|------|-----------|
| Server | **Ground Control** | HTTP/WS server, API, telemetry hub | *"This is Ground Control to Major Tom"* |
| Agent | **Spider** | Zero-dependency monitoring agent deployed to nodes | *"The Spiders from Mars"* |
| Web UI | **The Capsule** | React dashboard for fleet overview | *"Sitting in a tin can, far above the world"* |
| Deployer | **Major Tom** | SSH-based agent deployment and lifecycle manager | *"Commencing countdown, engines on"* |

## Architecture

```
  The Capsule (React)
        |
        | HTTPS
        v
  Ground Control (Zig)  <----  WebSocket  ----  Spider (Zig)
        |                                         deployed via SSH
        v                                         by Major Tom
    SQLite (zqlite)
```

Ground Control is a single Zig binary that serves the embedded React frontend, exposes a REST API, and maintains persistent WebSocket connections to every Spider. Major Tom handles the full agent lifecycle — uploading binaries over SSH, installing systemd services, and managing credentials with bcrypt-pbkdf encryption.

Spiders are statically-linked, zero-dependency Zig binaries that run on any Linux box. They collect system telemetry (CPU, memory, disk, network, temperatures, connections) and stream it back to Ground Control in real time.

## Features

- **Real-time telemetry** — CPU, memory, swap, load, disk I/O, filesystems, network interfaces, temperatures, TCP connections
- **System identification** — OS, kernel, architecture, CPU model, RAM, package manager detection
- **Package management** — update, check upgrades, upgrade/full-upgrade with live streaming output (apt, dnf, yum, pacman, apk)
- **One-click deployment** — SSH into a target, upload the Spider binary, install as a systemd service, start and verify connection
- **Node removal** — clean teardown: stop service, uninstall, remove binary, wipe credentials
- **Encrypted credentials** — SSH keys encrypted at rest with bcrypt-pbkdf derived keys
- **JWT authentication** — protected API with token-based auth and password management
- **Embedded UI** — The Capsule is compiled into the server binary, no separate web server needed
- **Historical snapshots** — telemetry history stored in SQLite for trend analysis

## Quick Start

### Prerequisites

- [Zig 0.15.2+](https://ziglang.org/download/)
- Node.js (for building the frontend)

### Build

```bash
# Build the frontend
cd frontend && npm install && npm run build && cd ..

# Build server and agent
zig build -Dcpu=baseline -Doptimize=ReleaseSafe
```

Binaries land in `zig-out/bin/`:
- `stardust-server` — Ground Control
- `stardust-spider` — Spider agent

### Configuration

| Environment Variable | Required | Description |
|---------------------|----------|-------------|
| `STARDUST_SECRET` | Yes | Master encryption key (>= 16 chars). Enables deployment, auth, and credential encryption. |
| `STARDUST_ADMIN_USER` | No | Initial admin username (default: `admin`) |
| `STARDUST_ADMIN_PASS` | No | Initial admin password (default: `admin`) |

```bash
export STARDUST_SECRET="your-secret-key-here"
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

### Deploy a Spider

From The Capsule, click **Add Node** and provide:
- Hostname / IP
- SSH user and private key
- Optional sudo password

Major Tom will SSH in, upload the Spider binary, install a systemd service, and establish the WebSocket connection back to Ground Control.

### TLS / Reverse Proxy

Ground Control binds plain HTTP internally. In production, put it behind a TLS-terminating reverse proxy (e.g. [Traefik](https://traefik.io/), nginx, Caddy) so that:

- The Capsule is served over HTTPS
- Spiders connect via `wss://` (TLS WebSocket) rather than plain `ws://`
- Auth tokens and SSH credentials are never sent in the clear

Pass the `--server-url` flag with your public `wss://` endpoint — this is the address baked into each Spider's config at deploy time.

```bash
# Example: Ground Control on port 8933, Traefik terminates TLS on 443
./stardust-server --port 8933 --server-url wss://stardust.example.com/ws ...
```

Note: WebSocket upgrade requires HTTP/1.1. If your proxy defaults to h2, make sure the `/ws` route falls back to HTTP/1.1.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Server | Zig 0.15 + [zap](https://github.com/zigzap/zap) (HTTP/WS) |
| Database | SQLite via [zqlite](https://github.com/karlseguin/zqlite.zig) |
| Agent | Zig 0.15 (zero dependencies, static binary) |
| Frontend | React + TypeScript + Tailwind CSS |
| Crypto | bcrypt-pbkdf key derivation, HMAC-SHA256 JWT |
| Transport | TLS WebSocket (agent-to-server), SSH (deployment) |

---

*"Planet Earth is blue, and there's nothing I can do."*

## License

MIT
