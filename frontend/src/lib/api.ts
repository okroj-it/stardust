import { getToken, clearToken } from './auth'

export interface SystemStats {
  agent_id: string
  hostname: string
  timestamp: number
  uptime_secs: number
  cpu: {
    usage_percent: number
    iowait_percent: number
    cores: Array<{
      core_id: number
      usage_percent: number
      iowait_percent: number
    }>
  }
  memory: {
    total_bytes: number
    free_bytes: number
    available_bytes: number
    buffers_bytes: number
    cached_bytes: number
    active_bytes: number
    inactive_bytes: number
    used_percent: number
  }
  swap: {
    total_bytes: number
    used_bytes: number
    free_bytes: number
    used_percent: number
  }
  load: {
    one: number
    five: number
    fifteen: number
    running_processes: number
    total_processes: number
  }
  disks: Array<{
    name: string
    reads_completed: number
    writes_completed: number
    sectors_read: number
    sectors_written: number
    io_in_progress: number
    ms_reading: number
    ms_writing: number
    ms_doing_io: number
  }>
  filesystems: Array<{
    mount_point: string
    fs_type: string
    total_bytes: number
    free_bytes: number
    available_bytes: number
    used_percent: number
  }>
  network: Array<{
    name: string
    rx_bytes: number
    rx_packets: number
    rx_errors: number
    rx_dropped: number
    tx_bytes: number
    tx_packets: number
    tx_errors: number
    tx_dropped: number
  }>
  temperatures: Array<{
    zone: string
    label: string
    temp_celsius: number
  }>
  connections: {
    established: number
    listen: number
    time_wait: number
    close_wait: number
    total: number
  }
}

export interface NodeStatus {
  agent_id: string
  name: string
  host: string
  connected: boolean
  last_seen: number
  snapshot_count: number
  // System info (from agent sysinfo)
  os_id?: string | null
  os_version?: string | null
  os_name?: string | null
  arch?: string | null
  kernel?: string | null
  cpu_model?: string | null
  cpu_cores?: number | null
  total_ram?: number | null
  pkg_manager?: string | null
}

const BASE = ''

async function apiFetch(url: string, options?: RequestInit): Promise<Response> {
  const headers = new Headers(options?.headers)
  const token = getToken()
  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  const res = await fetch(url, { ...options, headers })

  if (res.status === 401) {
    clearToken()
    window.dispatchEvent(new CustomEvent('auth:logout'))
  }

  return res
}

export async function login(username: string, password: string): Promise<string> {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Login failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  const data = await res.json()
  return data.token
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  const res = await apiFetch(`${BASE}/api/auth/password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
}

export async function fetchNodes(): Promise<NodeStatus[]> {
  const res = await apiFetch(`${BASE}/api/nodes`)
  return res.json()
}

export async function fetchNodeStats(nodeId: string): Promise<SystemStats | null> {
  const res = await apiFetch(`${BASE}/api/nodes/${nodeId}/stats`)
  if (!res.ok) return null
  return res.json()
}

export async function fetchNodeHistory(nodeId: string, count = 30): Promise<SystemStats[]> {
  const res = await apiFetch(`${BASE}/api/nodes/${nodeId}/stats/history?count=${count}`)
  if (!res.ok) return []
  return res.json()
}

export async function fetchHealth(): Promise<{ status: string }> {
  const res = await fetch(`${BASE}/api/health`)
  return res.json()
}

export interface AddNodePayload {
  name: string
  host: string
  port?: number
  ssh_user: string
  ssh_key: string
  sudo_password?: string
}

export interface AddNodeResponse {
  id: string
  name: string
  host: string
  token: string
  status: string
}

export async function addNode(payload: AddNodePayload): Promise<AddNodeResponse> {
  const res = await apiFetch(`${BASE}/api/nodes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function deleteNode(nodeId: string): Promise<void> {
  await apiFetch(`${BASE}/api/nodes/${nodeId}`, { method: 'DELETE' })
}

export interface CheckNodePayload {
  host: string
  port?: number
  ssh_user: string
  ssh_key: string
  sudo_password?: string
}

export interface CheckNodeResult {
  connected: boolean
  arch: string | null
  agent_available: boolean
  message: string
}

export async function checkNode(payload: CheckNodePayload): Promise<CheckNodeResult> {
  const res = await apiFetch(`${BASE}/api/nodes/check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export interface DeployStepResult {
  ok: boolean
  message: string
}

export async function deployStep(nodeId: string, step: 'upload' | 'install' | 'start' | 'connect' | 'stop' | 'check-stopped' | 'uninstall' | 'check-uninstalled' | 'remove-binary' | 'check-removed' | 'wipe-creds' | 'detect-pkg-manager'): Promise<DeployStepResult> {
  const res = await apiFetch(`${BASE}/api/nodes/${nodeId}/deploy?step=${step}`, {
    method: 'POST',
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export interface PkgRefreshResult {
  ok: boolean
  output: string
}

export async function pkgRefresh(nodeId: string, pkgManager: string): Promise<PkgRefreshResult> {
  const res = await apiFetch(`${BASE}/api/nodes/${nodeId}/deploy?step=pkg-refresh&pkg=${pkgManager}`, {
    method: 'POST',
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function pkgRefreshStart(nodeId: string, pkgManager: string): Promise<string> {
  const res = await apiFetch(`${BASE}/api/nodes/${nodeId}/deploy?step=pkg-refresh-start&pkg=${pkgManager}`, {
    method: 'POST',
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  const data = await res.json()
  return data.job_id
}

export interface PkgPollResult {
  output: string
  offset: number
  done: boolean
  ok: boolean
}

export async function pkgRefreshPoll(nodeId: string, jobId: string, offset: number): Promise<PkgPollResult> {
  const res = await apiFetch(`${BASE}/api/nodes/${nodeId}/deploy?step=pkg-refresh-poll&job=${jobId}&offset=${offset}`, {
    method: 'POST',
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export type PkgAction = 'check-updates' | 'upgrade' | 'full-upgrade'

export async function pkgJobStart(nodeId: string, pkgManager: string, action: PkgAction): Promise<string> {
  const res = await apiFetch(`${BASE}/api/nodes/${nodeId}/deploy?step=pkg-job-start&pkg=${pkgManager}&action=${action}`, {
    method: 'POST',
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  const data = await res.json()
  return data.job_id
}

// Reuse the same poll endpoint for all jobs
export async function pkgJobPoll(nodeId: string, jobId: string, offset: number): Promise<PkgPollResult> {
  return pkgRefreshPoll(nodeId, jobId, offset)
}

export interface UpgradablePackage {
  name: string
  oldVersion: string
  newVersion: string
}

export function parseUpgradablePackages(output: string, pkgManager: string): UpgradablePackage[] {
  const packages: UpgradablePackage[] = []

  if (pkgManager === 'apt') {
    // apt-get upgrade -s output: "Inst pkg [old] (new repo) ..."
    for (const line of output.split('\n')) {
      const match = line.match(/^Inst\s+(\S+)\s+\[([^\]]+)\]\s+\((\S+)/)
      if (match) {
        packages.push({ name: match[1], oldVersion: match[2], newVersion: match[3] })
      }
    }
  } else if (pkgManager === 'dnf' || pkgManager === 'yum') {
    // dnf/yum check-update output: "name.arch  version  repo"
    for (const line of output.split('\n')) {
      const match = line.match(/^(\S+?)\.(\S+)\s+(\S+)\s+(\S+)/)
      if (match && !line.startsWith('Last metadata') && !line.startsWith('Obsoleting')) {
        packages.push({ name: match[1], oldVersion: '', newVersion: match[3] })
      }
    }
  } else if (pkgManager === 'pacman') {
    // pacman -Qu output: "name old -> new"
    for (const line of output.split('\n')) {
      const match = line.match(/^(\S+)\s+(\S+)\s+->\s+(\S+)/)
      if (match) {
        packages.push({ name: match[1], oldVersion: match[2], newVersion: match[3] })
      }
    }
  } else if (pkgManager === 'apk') {
    // apk upgrade -s: "(1/N) Upgrading pkg (old -> new)" or "Upgrading pkg (old -> new)"
    for (const line of output.split('\n')) {
      const match = line.match(/(?:Upgrading|Installing)\s+(\S+)\s+\((\S+)\s+->\s+(\S+)\)/)
      if (match) {
        packages.push({ name: match[1], oldVersion: match[2], newVersion: match[3] })
      }
    }
  }

  return packages
}
