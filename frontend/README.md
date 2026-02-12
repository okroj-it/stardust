# The Capsule — Stardust Frontend

React dashboard for the Stardust server monitoring platform.

## Stack

- **React 19** + **TypeScript 5.9**
- **Tailwind CSS 4** — dark theme
- **xterm.js 6** — browser-based SSH terminal
- **Lucide** — icons
- **Motion** — animations
- **Vite 7** — build tooling

## Development

```bash
npm install
npm run dev
```

Opens at `http://localhost:5173` with HMR. API requests proxy to the Zig server (configure in `vite.config.ts`).

## Production Build

```bash
npm run build
```

Output goes to `../ui/` — the Zig server embeds these assets into the binary at compile time.

## Components

| Component | File | Description |
|:----------|:-----|:------------|
| Dashboard | `App.tsx` | Main layout, node grid, header toolbar |
| Node Card | `node-card.tsx` | Fleet overview card with live stats |
| Node Detail | `node-detail.tsx` | Per-node metrics, charts, system info |
| Add Node | `add-node-modal.tsx` | Onboarding wizard (SSH credentials) |
| Remove Node | `remove-node-modal.tsx` | Clean teardown with confirmation |
| Package Manager | `terminal-modal.tsx` | Package updates, upgrades, cache refresh |
| Web Terminal | `web-terminal.tsx` | Interactive SSH shell (Space Oddity) |
| Fleet Command | `fleet-command-modal.tsx` | Parallel command execution (Starman) |
| Service Manager | `service-manager.tsx` | Systemd service viewer/controller (Life on Mars) |
| Ansible | `ansible-modal.tsx` | Playbook editor and runner (Ziggy) |
| Login | `login-page.tsx` | JWT authentication |
| Profile | `profile-modal.tsx` | Password change, logout |

## API Client

All server communication goes through `lib/api.ts` — typed fetch wrappers with JWT auth, automatic 401 handling, and token refresh.

## Key Patterns

- **Polling**: Long-running operations (fleet commands, Ansible, package jobs) use offset-based polling at 300ms intervals
- **Capabilities**: Features are conditionally rendered based on server capabilities (`/api/capabilities`)
- **Embedded build**: The frontend is compiled into the server binary — no separate web server in production
