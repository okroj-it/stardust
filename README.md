<p align="center">
  <img src="https://img.shields.io/badge/%E2%9A%A1-Stardust-8b5cf6?style=for-the-badge&labelColor=0d1117" alt="Stardust" />
</p>

<h3 align="center">Orchestrating the Spiders from Mars</h3>

<p align="center">
  <em>A lightweight server monitoring & orchestration platform built in Zig.<br/>
  Single binary. Zero-dependency agents. Real-time telemetry over WebSockets.</em>
</p>

<p align="center">
  <em>
  SSH terminals · fleet commands · package management · systemd services · process explorer<br/>
  log streaming · Docker/Podman containers · security posture scoring · Ansible playbooks<br/>
  drift detection · scheduled automation · event timeline · Prometheus metrics · node tagging
  </em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Zig-0.15.2-f7a41d?style=flat-square&logo=zig&logoColor=white" alt="Zig" />
  <img src="https://img.shields.io/badge/React-19-61dafb?style=flat-square&logo=react&logoColor=white" alt="React" />
  <img src="https://img.shields.io/badge/TypeScript-5.9-3178c6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript" />
  <img src="https://img.shields.io/badge/Tailwind-4.1-06b6d4?style=flat-square&logo=tailwindcss&logoColor=white" alt="Tailwind" />
  <img src="https://img.shields.io/badge/SQLite-3-003b57?style=flat-square&logo=sqlite&logoColor=white" alt="SQLite" />
  <img src="https://img.shields.io/badge/Ansible-optional-ee0000?style=flat-square&logo=ansible&logoColor=white" alt="Ansible" />
  <img src="https://img.shields.io/badge/Prometheus-compatible-e6522c?style=flat-square&logo=prometheus&logoColor=white" alt="Prometheus" />
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
| Fleet Command | **Starman** | Parallel ad-hoc command execution across nodes | *"There's a starman waiting in the sky"* |
| Service Manager | **Life on Mars** | Remote systemd service viewer and controller | *"Is there life on Mars?"* |
| Process Explorer | **Ashes to Ashes** | Browser-based process viewer with kill signals | *"Ashes to ashes, funk to funky"* |
| Log Streaming | **Sound and Vision** | Real-time log tailing (journalctl & files) | *"Don't you wonder sometimes, 'bout sound and vision?"* |
| Security Posture | **Heroes** | Per-node security audit with scoring | *"We can be heroes, just for one day"* |
| Container Manager | **Suffragette City** | Docker/Podman container viewer and controller | *"Wham bam, thank you ma'am"* |
| Scheduled Automation | **Station to Station** | Cron-based job scheduler with execution history | *"The return of the Thin White Duke"* |
| Event Timeline | **Changes** | Audit trail for every action and connection event | *"Ch-ch-ch-ch-Changes, turn and face the strange"* |
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
                    │                  │──── SSH (Starman) ────►  │              │
                    │                  │──── SSH (Life on Mars)─►  │              │
                    │                  │──── SSH (Ashes) ───────►  │              │
                    │                  │──── SSH (Sound&Vision)─►  │              │
                    │                  │──── SSH (Heroes) ──────►  │              │
                    │                  │──── SSH (Suffragette)──►  │              │
                    │                  │──── SSH (Station)────►  │              │
                    └────────┬─────────┘                             └─────────────┘
                             │
                    ┌────────▼─────────┐       ┌─────────────────┐
                    │  SQLite (zqlite) │       │    Ansible       │
                    │  nodes, users,   │
                    │  schedules,      │       │  (optional)      │
                    │  creds, events   │       │  galaxy + plays  │
                    └──────────────────┘       └─────────────────┘
```

Ground Control is a **single Zig binary** that serves the embedded React frontend, exposes a REST API, and maintains persistent WebSocket connections to every Spider. Major Tom handles the full agent lifecycle — uploading binaries over SSH, installing systemd services, and managing credentials with AES-GCM-256 encryption.

Spiders are **statically-linked, zero-dependency** Zig binaries that run on any Linux box. They collect system telemetry and stream it back to Ground Control in real time.

**Starman** lets you run ad-hoc shell commands across your entire fleet in parallel — type `uptime`, select your nodes, and watch output stream in from every machine at once.

**Life on Mars** gives you a per-node view of systemd services — both system-wide and user-scoped — with one-click start, stop, restart, enable, and disable actions, all without opening a terminal.

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
- **Architecture-aware** — Detects target arch via `uname -m` during pre-flight check and selects the correct Spider binary (x86\_64 or aarch64)

### Package Management

- **Unified interface** for `apt`, `dnf`, `yum`, `pacman`, and `apk`
- **Tabbed UI** — Upgrades, Installed, and Search tabs in one terminal-style modal
- **Check for updates** — See available upgrades in a sortable table
- **Upgrade / Full Upgrade** — Run upgrades with live streaming terminal output
- **List installed** — Browse all installed packages in a searchable, filterable table
- **Search** — Query the package cache and install packages directly from search results
- **Install / Remove** — One-click install and uninstall with real-time progress overlay
- **Cache refresh** — Update package indexes remotely
- **Shell injection prevention** — Package names and search queries validated server-side against a strict character allowlist

### Web Terminal (Space Oddity)

- **Browser-based SSH** — Full interactive shell directly from The Capsule, no local SSH client needed
- **PTY relay** — Ground Control proxies WebSocket frames to SSH stdin/stdout with forced PTY allocation
- **Nerd Font support** — Powerline glyphs and icons render correctly (loads symbol font from CDN as fallback)
- **TUI-compatible** — `mc`, `htop`, `vim`, and other curses applications work out of the box (`TERM=xterm-256color`)
- **Auto-sizing** — Terminal dimensions sync on connect and window resize
- **Secure sessions** — JWT-authenticated, temporary key files (mode `0600`) cleaned up on disconnect, key material zeroed in memory

### Fleet Command (Starman)

- **Parallel execution** — Run any shell command across multiple nodes simultaneously with per-node streaming output
- **Node targeting** — Select individual nodes, the entire fleet, or groups by tag from a checkbox grid
- **Sudo support** — Toggle sudo mode; per-node sudo passwords are decrypted from the database automatically
- **Live streaming** — Output streams in real time via single-request polling (one poll returns all nodes)
- **Per-node panels** — Collapsible output sections with status indicators (running/success/error) per node
- **Command history** — Last 10 commands saved in browser localStorage with dropdown recall
- **Secure execution** — SSH keys decrypted to temporary files (mode `0600`), cleaned up after execution; passwords zeroed in memory

### Service Manager (Life on Mars)

- **System & user scopes** — Toggle between `systemctl` (system services) and `systemctl --user` (user services) with a single click
- **Service listing** — View all services with color-coded state indicators (running, exited, failed, dead)
- **Quick actions** — Start, stop, and restart services directly from the table row
- **Detailed status** — Expand any service to see full `systemctl status` output with enable/disable controls
- **Client-side filtering** — Instant search across service names and descriptions
- **Secure execution** — System-scope commands use sudo with decrypted passwords; user-scope commands set `XDG_RUNTIME_DIR` for non-interactive SSH
- **Input validation** — Service names are validated server-side to prevent shell injection

### Process Explorer (Ashes to Ashes)

- **Live process table** — Browser-based top/htop view per node, powered by `ps aux` over SSH
- **Sortable columns** — Click to sort by CPU, memory, PID, user, RSS, or command (descending by CPU by default)
- **Client-side filtering** — Instant search across user, PID, and command name
- **Auto-refresh** — Toggle live mode for 3-second polling, just like a real `top`
- **Send signals** — SIGTERM (graceful), SIGKILL (force), or SIGHUP (reload) with a confirmation dialog
- **PID safety** — Server-side validation rejects PID 0 and 1; only signals 1, 9, and 15 are allowed
- **Expandable rows** — Click any process to see its full command line with arguments
- **Color-coded metrics** — CPU and memory usage highlighted by severity (green → amber → red)

### Log Streaming (Sound and Vision)

- **Journal or file** — Toggle between `journalctl` (system journal) and `tail -f` (arbitrary log file) from a single modal
- **Per-service filtering** — Optionally scope journal output to a specific systemd unit (e.g. `nginx.service`)
- **Configurable history** — Choose how many initial lines to load (1–10,000, default 100)
- **Live streaming** — Output streams in real time via 300ms polling with offset-based incremental delivery
- **Pause / resume** — Freeze the display without killing the SSH session; resume catches up from where you left off
- **Client-side filter** — Instant text search across all log lines while streaming
- **Auto-scroll** — Scrolls to bottom on new output; disengages when you scroll up manually
- **1MB buffer cap** — Server truncates old lines from the front at clean newline boundaries to prevent unbounded memory growth
- **Input validation** — Service names validated against `[a-zA-Z0-9._@-]`; file paths must start with `/` and reject shell metacharacters
- **Sudo support** — All commands wrapped with sudo for privileged journal entries and root-owned log files

### Security Posture (Heroes)

- **Per-node security score** — Automated 0–100 score computed from package updates, SSH hardening, firewall status, and auto-update configuration
- **Upgradable packages** — Lists all packages with available updates, showing current and available versions (apt, dnf, pacman, apk)
- **SSH config audit** — Checks six critical sshd settings: PasswordAuthentication, PermitRootLogin, PubkeyAuthentication, X11Forwarding, PermitEmptyPasswords, and MaxAuthTries — each graded pass/warn/fail
- **Firewall detection** — Auto-detects ufw, firewalld, or iptables; shows active/inactive status and raw rules
- **Open ports** — Lists all listening TCP ports with process names from `ss -tlnp`
- **Auto-update status** — Detects whether unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL/Fedora) is installed and enabled
- **Overview dashboard** — Score ring visualization, clickable summary cards for each category, and port badges
- **Tabbed detail views** — Packages table, SSH config cards with status badges, firewall rules display, and auto-update configuration

### Event Timeline (Changes)

- **Comprehensive audit trail** — Every meaningful action is recorded: Spider connect/disconnect, node add/remove, deployments, fleet commands, Ansible runs, service actions, process signals, drift snapshots, and security scans
- **Global timeline** — View all events across the fleet from the header Timeline button, with type-based icons and color coding
- **Per-node timeline** — Open filtered event history from any node's detail panel
- **Event type filtering** — Dropdown filter to focus on specific event categories (connected, disconnected, deploy, fleet, ansible, service, process, drift, security)
- **Cursor-based pagination** — "Load more" button fetches older events without duplicates or shifting pages
- **Auto-refresh** — New events appear automatically via 10-second polling
- **Auto-prune** — Events older than 30 days are cleaned up on server startup
- **Fire-and-forget recording** — Event insertion never blocks or fails the primary action

### Container Management (Suffragette City)

- **Docker & Podman support** — Automatically detects Docker or Podman on each node via SSH; falls back gracefully with a clean "no runtime" message
- **Container listing** — Shows all containers (running and stopped) with ID, name, image, state, status, and ports in a sortable table
- **State-aware actions** — Contextual buttons per container: Start/Stop/Restart/Pause/Unpause/Remove — only relevant actions appear based on current state
- **Container inspect** — Expand any row to view the full `docker inspect` JSON output, formatted and scrollable
- **Container logs** — Switch to the Logs tab to see the last 100 lines of container output
- **Color-coded states** — Running (emerald), exited (red), paused (amber), created (blue), restarting (cyan)
- **Filter and auto-refresh** — Search by container name/image/ID, toggle 5-second auto-refresh
- **Event recording** — Container actions (start, stop, restart, etc.) are recorded in the event timeline

### Scheduled Automation (Station to Station)

- **Cron-based scheduling** — Full 5-field cron expressions (minute, hour, day-of-month, month, day-of-week) supporting `*`, exact values, ranges (`1-5`), lists (`1,15,30`), and steps (`*/5`)
- **Three job types** — Shell commands (with optional sudo), Ansible playbooks, and package updates (upgrade or full-upgrade)
- **Flexible targeting** — Run against all nodes, a specific tag group, or hand-picked individual nodes
- **SQLite persistence** — Schedules and execution history survive server restarts; stale runs from crashes are marked as failed on startup
- **Background scheduler thread** — Wakes at each minute boundary, evaluates all enabled schedules, and dispatches matching jobs
- **Execution history** — Every run is recorded with start/finish timestamps, status (pending/running/ok/failed), and captured output
- **Cron presets** — Quick-select common schedules ("Every hour", "Every day at 3 AM", "Every Sunday at 3 AM", "1st of month") or enter custom expressions
- **Live preview** — Human-readable description updates as you configure the cron expression
- **Run Now** — Trigger any schedule immediately without waiting for the next cron match
- **Enable/disable** — Toggle schedules on and off without deleting them
- **Package manager aware** — Package update jobs detect the node's package manager (apt, dnf, yum, pacman, apk) and run the correct upgrade command
- **Event recording** — Schedule executions and failures are logged in the event timeline

### Ansible Integration (Ziggy)

> *Conditionally enabled — if `ansible-playbook` is found on the Ground Control host, the feature lights up automatically. Otherwise it stays invisible.*

- **Auto-detection** — Searches `$PATH`, pipx venvs, and common install locations
- **Dynamic inventory** — Generated on-the-fly from your node database with decrypted SSH credentials
- **Playbook editor** — Write YAML directly in The Capsule with syntax-highlighted textarea
- **Requirements.yml** — Install Galaxy roles and collections before playbook runs
- **Node targeting** — Select specific nodes, groups by tag, or run against the entire fleet
- **Streaming output** — Watch `ansible-playbook` output in real time via polling
- **Secure cleanup** — All temp files (inventory, keys, playbooks, requirements) deleted after runs; passwords zeroed in memory

### Authentication & Security

- **JWT authentication** — HMAC-SHA256 signed tokens with configurable expiry
- **Password management** — bcrypt-hashed passwords, changeable from The Capsule
- **API protection** — All management endpoints require valid bearer tokens
- **Credential encryption** — AES-GCM-256 for SSH keys and sudo passwords at rest
- **Secure memory** — `std.crypto.secureZero` on all decrypted secrets after use

### Node Groups & Tags

- **Tag any node** — Add free-form labels like `prod`, `staging`, `frontend`, `eu-west` from the node detail panel
- **Dashboard filtering** — Click tag pills to filter the node grid (OR logic — shows nodes matching any selected tag)
- **Tag-based targeting** — Fleet Command and Ansible modals let you select/deselect nodes by tag in one click
- **Autocomplete** — Tag input suggests existing tags from across your fleet
- **Clean lifecycle** — Tags are automatically removed when a node is deleted

### Drift Detection

- **Configuration snapshots** — Capture installed packages, running services, listening ports, and system users via SSH
- **Package manager auto-detection** — Uses the node's detected package manager (`apt`/`dpkg`, `dnf`/`yum`/`rpm`, `pacman`, `apk`) for accurate package listing
- **Baseline management** — Set any snapshot as the baseline for a node; future snapshots can be diffed against it
- **Cross-snapshot diff** — Compare any two snapshots with color-coded results: added (green), removed (red), drifted (amber)
- **Cross-node comparison** — Compare snapshots between different nodes to find configuration differences across your fleet
- **Filter toggles** — Focus on specific drift types: items only in source, only in target, or drifted between both
- **Text search** — Filter diff entries by name across all categories
- **Remediation actions** — Install missing packages on either node directly from the diff view
- **Version-aware updates** — For drifted packages with differing versions, proposes updating the node running the older version
- **Snapshot history** — Browse and manage historical snapshots per node with timestamps
- **Tabbed results** — View snapshot data organized by category (Packages, Services, Ports, Users) in sortable tables

### Prometheus Metrics

- **`GET /metrics`** — Unauthenticated endpoint exposing all node telemetry in [Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/)
- **Per-node labels** — Every metric carries `agent_id` and `hostname` labels; filesystem, network, disk I/O, and temperature metrics add `mountpoint`/`fstype`, `interface`, `device`, or `zone`
- **30+ metric families** — CPU, memory, swap, load, filesystems, network I/O, connections, temperatures, disk I/O, uptime, and node availability (`stardust_up`)
- **Zero config** — Scrape directly with Prometheus, pipe into Grafana dashboards, and set alerts on any metric
- **Ready-made Grafana dashboard** — Import `grafana/stardust-fleet.json` for a full fleet overview with per-node filtering

```yaml
# prometheus.yml
scrape_configs:
  - job_name: stardust
    scrape_interval: 15s
    static_configs:
      - targets: ['your-stardust-host:8933']
```

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

# 2. Build server + agent (x86_64)
zig build -Dcpu=baseline -Doptimize=ReleaseSafe

# 3. (Optional) Cross-compile Spider for ARM64
zig build spider-aarch64 -Doptimize=ReleaseSafe
```

> **Note:** `-Dcpu=baseline` ensures compatibility with older x86\_64 CPUs. Omit it if all your machines have modern instruction sets.

Binaries land in `zig-out/bin/`:

| Binary | Size | Description |
|:-------|:-----|:------------|
| `stardust-server` | ~12 MB | Ground Control (server + embedded UI) |
| `stardust-spider` | ~6.5 MB | Spider agent (zero dependencies, static, x86\_64) |
| `stardust-spider-aarch64` | ~6.5 MB | Spider agent for ARM64 (cross-compiled, optional) |

Place the ARM64 Spider alongside the default binary on the Ground Control host. When deploying to an ARM64 node, Major Tom automatically detects the target architecture and uploads the correct binary.

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

All endpoints (except health, metrics, and login) require `Authorization: Bearer <token>`.

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
| `PATCH` | `/api/nodes/:id` | Update node (credentials, tags) |
| `DELETE` | `/api/nodes/:id` | Delete node from database |
| `GET` | `/api/nodes/:id/stats` | Latest telemetry snapshot |
| `GET` | `/api/nodes/:id/stats/history?count=N` | Historical snapshots |
| `POST` | `/api/nodes/check` | Pre-deployment SSH connectivity test |
| `GET` | `/api/tags` | List all unique tags across all nodes |

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

Package actions: `check-updates`, `upgrade`, `full-upgrade`, `list-installed`, `search:<query>`, `install:<package>`, `remove:<package>`

### Fleet Command (Starman)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/fleet/run` | Start command `{command, node_ids, sudo?}`, returns `{job_id}` |
| `POST` | `/api/fleet/poll?job=ID` | Poll output `{offsets: [{node_id, offset}, ...]}`, returns per-node results |

### Services (Life on Mars)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/services/:id/list?scope=system\|user` | List all services on a node |
| `GET` | `/api/services/:id/status?name=svc&scope=system\|user` | Detailed service status |
| `POST` | `/api/services/:id/action` | Execute action `{name, action, scope}` (start/stop/restart/enable/disable) |

### Processes (Ashes to Ashes)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/processes/:id/list` | List all processes on a node (`ps aux`) |
| `POST` | `/api/processes/:id/kill` | Send signal `{pid, signal}` (1=HUP, 9=KILL, 15=TERM) |

### Log Streaming (Sound and Vision)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/logs/:id/start` | Start log stream `{source, service?, path?, lines?}`, returns `{job_id}` |
| `GET` | `/api/logs/:id/poll?job=ID&offset=N` | Poll log output, returns `{output, offset, done, ok}` |
| `POST` | `/api/logs/:id/stop` | Stop log stream `{job_id}` |

### Security Posture (Heroes)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/security/:id/scan` | Run security scan, returns `{ok, score, upgradable, ssh_config, ports, firewall, autoupdate}` |

### Drift Detection

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/drift/snapshot` | Take snapshot `{node_ids: [...]}`, returns snapshot summaries |
| `GET` | `/api/drift/snapshots?node_id=ID` | List snapshots for a node |
| `GET` | `/api/drift/snapshot/:id` | Get full snapshot data |
| `POST` | `/api/drift/baseline` | Set baseline `{snapshot_id}` |
| `POST` | `/api/drift/diff` | Compare snapshots `{snapshot_a, snapshot_b?}` or `{snapshot_a, baseline: true}` |
| `DELETE` | `/api/drift/snapshot/:id` | Delete a snapshot |

### Event Timeline (Changes)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/events?node_id=X&type=Y&limit=50&before=123` | List events (paginated, filterable by node and type) |

Event types: `node.connected`, `node.disconnected`, `node.added`, `node.removed`, `deploy.started`, `fleet.command`, `ansible.run`, `service.action`, `process.signal`, `drift.snapshot`, `security.scan`, `container.action`, `schedule.executed`, `schedule.failed`

### Container Management (Suffragette City)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/containers/:id/list` | List all containers (Docker or Podman, tab-delimited) |
| `GET` | `/api/containers/:id/inspect?id=CONTAINER` | Inspect container JSON |
| `POST` | `/api/containers/:id/action` | Execute action `{id, action}` (start/stop/restart/pause/unpause/rm) |
| `GET` | `/api/containers/:id/logs?id=CONTAINER&tail=100` | Fetch container logs (tail, max 500) |

### Scheduled Automation (Station to Station)

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/schedules` | List all schedules |
| `POST` | `/api/schedules` | Create schedule `{name, job_type, config, target_type, target_value?, cron_*}` |
| `GET` | `/api/schedules/:id` | Get single schedule |
| `PUT` | `/api/schedules/:id` | Update schedule |
| `DELETE` | `/api/schedules/:id` | Delete schedule (cascades to runs) |
| `POST` | `/api/schedules/:id/toggle` | Enable/disable schedule |
| `POST` | `/api/schedules/:id/run` | Trigger immediate execution |
| `GET` | `/api/schedules/:id/runs?limit=20` | Execution history |

Job types: `command` (config: `{command, sudo?}`), `ansible` (config: `{playbook, requirements?}`), `package_update` (config: `{pkg_action}`)

### Ansible

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/capabilities` | Server feature flags (ansible, deployer, auth, fleet, services, processes, drift, logs, security, schedules) |
| `GET` | `/api/ansible/status` | Ansible version and availability |
| `POST` | `/api/ansible/run` | Run playbook `{playbook, nodes?, requirements?}` |
| `POST` | `/api/ansible/poll?job=ID&offset=N` | Poll playbook output |

### System

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/health` | Health check (no auth) |
| `GET` | `/metrics` | Prometheus metrics (no auth) |

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
│   │   ├── fleet.zig          # Starman (fleet command execution)
│   │   ├── services.zig      # Life on Mars (service manager)
│   │   ├── processes.zig     # Ashes to Ashes (process explorer)
│   │   ├── logs.zig          # Sound and Vision (log streaming)
│   │   ├── security.zig     # Heroes (security posture scanner)
│   │   ├── drift.zig         # Drift detection (SSH snapshots & parsing)
│   │   ├── scheduler.zig    # Station to Station (cron scheduler)
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
│       │   ├── terminal-modal.tsx  # Package manager (search, install, upgrade, remove)
│       │   ├── drift-modal.tsx    # Drift detection & cross-node comparison
│       │   ├── web-terminal.tsx   # SSH terminal (Space Oddity)
│       │   ├── fleet-command-modal.tsx # Fleet command runner (Starman)
│       │   ├── service-manager.tsx  # Service viewer/controller (Life on Mars)
│       │   ├── process-explorer.tsx # Process viewer/killer (Ashes to Ashes)
│       │   ├── log-viewer.tsx     # Log streamer (Sound and Vision)
│       │   ├── security-posture.tsx # Security scanner (Heroes)
│       │   ├── event-timeline.tsx  # Event timeline (Changes)
│       │   ├── schedule-manager.tsx # Scheduled automation (Station to Station)
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

# 1b. (Optional) Cross-compile Spider for ARM64 nodes
zig build spider-aarch64 -Doptimize=ReleaseSafe

# 2. Deploy binaries to your server
scp zig-out/bin/stardust-server you@server:/opt/stardust/
scp zig-out/bin/stardust-spider-aarch64 you@server:/opt/stardust/  # if you have ARM64 nodes

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
