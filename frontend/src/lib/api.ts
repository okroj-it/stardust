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
  tags?: string[]
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

export async function updateNodeTags(nodeId: string, tags: string[]): Promise<void> {
  const res = await apiFetch(`${BASE}/api/nodes/${nodeId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tags }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
}

export async function fetchAllTags(): Promise<string[]> {
  const res = await apiFetch(`${BASE}/api/tags`)
  if (!res.ok) return []
  return res.json()
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

export async function deployStep(nodeId: string, step: 'upload' | 'install' | 'start' | 'connect' | 'stop' | 'check-stopped' | 'uninstall' | 'check-uninstalled' | 'remove-binary' | 'check-removed' | 'wipe-creds' | 'detect-pkg-manager', arch?: string): Promise<DeployStepResult> {
  let url = `${BASE}/api/nodes/${nodeId}/deploy?step=${step}`
  if (arch) url += `&arch=${arch}`
  const res = await apiFetch(url, {
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
  | 'list-installed' | `search:${string}` | `install:${string}` | `remove:${string}`

export async function pkgJobStart(nodeId: string, pkgManager: string, action: PkgAction): Promise<string> {
  // Replace spaces with + for URL safety (zap doesn't URL-decode query params)
  const encodedAction = action.replace(/ /g, '+')
  const res = await apiFetch(`${BASE}/api/nodes/${nodeId}/deploy?step=pkg-job-start&pkg=${pkgManager}&action=${encodedAction}`, {
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

// --- Capabilities ---

export interface Capabilities {
  deployer: boolean
  auth: boolean
  ansible: boolean
  ansible_version?: string | null
  fleet: boolean
  services: boolean
  processes: boolean
  logs: boolean
  drift: boolean
  security: boolean
  containers: boolean
}

export async function fetchCapabilities(): Promise<Capabilities> {
  const res = await apiFetch(`${BASE}/api/capabilities`)
  if (!res.ok) return { deployer: false, auth: false, ansible: false, fleet: false, services: false, processes: false, logs: false, drift: false, security: false, containers: false }
  return res.json()
}

// --- Ansible ---

export async function ansibleRun(playbook: string, nodes?: string[], requirements?: string): Promise<string> {
  const res = await apiFetch(`${BASE}/api/ansible/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      playbook,
      nodes: nodes && nodes.length > 0 ? nodes : null,
      requirements: requirements && requirements.trim() ? requirements.trim() : null,
    }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  const data = await res.json()
  return data.job_id
}

export async function ansiblePoll(jobId: string, offset: number): Promise<PkgPollResult> {
  const res = await apiFetch(`${BASE}/api/ansible/poll?job=${jobId}&offset=${offset}`, {
    method: 'POST',
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
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

// --- Fleet Command Execution ---

export interface FleetNodeResult {
  name: string
  output: string
  offset: number
  done: boolean
  ok: boolean
}

export interface FleetPollResult {
  nodes: Record<string, FleetNodeResult>
  all_done: boolean
}

export async function fleetRun(command: string, nodeIds: string[], sudo: boolean = false): Promise<string> {
  const res = await apiFetch(`${BASE}/api/fleet/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command, node_ids: nodeIds, sudo }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  const data = await res.json()
  return data.job_id
}

export async function fleetPoll(jobId: string, offsets: Record<string, number>): Promise<FleetPollResult> {
  const offsetArray = Object.entries(offsets).map(([node_id, offset]) => ({ node_id, offset }))
  const res = await apiFetch(`${BASE}/api/fleet/poll?job=${jobId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ offsets: offsetArray }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

// --- Service Manager ---

export type ServiceScope = 'system' | 'user'
export type ServiceAction = 'start' | 'stop' | 'restart' | 'enable' | 'disable'

export interface ServiceInfo {
  name: string
  load: string
  active: string
  sub: string
  description: string
}

export interface ServiceResult {
  ok: boolean
  output: string
}

export async function fetchServiceList(nodeId: string, scope: ServiceScope): Promise<ServiceResult> {
  const res = await apiFetch(`${BASE}/api/services/${nodeId}/list?scope=${scope}`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function fetchServiceStatus(nodeId: string, name: string, scope: ServiceScope): Promise<ServiceResult> {
  const res = await apiFetch(`${BASE}/api/services/${nodeId}/status?name=${encodeURIComponent(name)}&scope=${scope}`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function runServiceAction(nodeId: string, name: string, action: ServiceAction, scope: ServiceScope): Promise<ServiceResult> {
  const res = await apiFetch(`${BASE}/api/services/${nodeId}/action`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, action, scope }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export function parseServiceList(output: string): ServiceInfo[] {
  const services: ServiceInfo[] = []
  for (const line of output.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed) continue
    // systemctl --plain --no-legend: "name.service  loaded  active  sub  description..."
    const parts = trimmed.split(/\s+/)
    if (parts.length >= 4) {
      services.push({
        name: parts[0],
        load: parts[1],
        active: parts[2],
        sub: parts[3],
        description: parts.slice(4).join(' '),
      })
    }
  }
  return services
}

// --- Drift Detection ---

export interface DriftPackageEntry { name: string; version: string }
export interface DriftServiceEntry { name: string; state: string; sub_state: string }
export interface DriftPortEntry { proto: string; address: string; port: string }
export interface DriftUserEntry { name: string; uid: string; gid: string; home: string; shell: string }

export interface DriftSnapshotSummary {
  id: number
  node_id: string
  node_name?: string
  is_baseline: boolean
  created_at: number
  error?: string
}

export interface DriftSnapshot extends DriftSnapshotSummary {
  packages: DriftPackageEntry[]
  services: DriftServiceEntry[]
  ports: DriftPortEntry[]
  users: DriftUserEntry[]
}

export interface DriftDiffEntry { key: string; value: string }
export interface DriftChangedEntry { key: string; old_value: string; new_value: string }

export interface DriftCategoryDiff {
  added: DriftDiffEntry[]
  removed: DriftDiffEntry[]
  changed: DriftChangedEntry[]
}

export interface DriftDiffResult {
  snapshot_a: number
  snapshot_b: number
  node_a_id: string
  node_b_id: string
  packages: DriftCategoryDiff
  services: DriftCategoryDiff
  ports: DriftCategoryDiff
  users: DriftCategoryDiff
}

export async function driftSnapshot(nodeIds: string[]): Promise<{ snapshots: DriftSnapshotSummary[] }> {
  const res = await apiFetch(`${BASE}/api/drift/snapshot`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ node_ids: nodeIds }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function driftListSnapshots(nodeId: string): Promise<{ snapshots: DriftSnapshotSummary[] }> {
  const res = await apiFetch(`${BASE}/api/drift/snapshots?node_id=${nodeId}`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function driftGetSnapshot(id: number): Promise<DriftSnapshot> {
  const res = await apiFetch(`${BASE}/api/drift/snapshot/${id}`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function driftSetBaseline(snapshotId: number): Promise<void> {
  const res = await apiFetch(`${BASE}/api/drift/baseline`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ snapshot_id: snapshotId }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
}

export async function driftDiff(snapshotA: number, snapshotB?: number, baseline?: boolean): Promise<DriftDiffResult> {
  const res = await apiFetch(`${BASE}/api/drift/diff`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      snapshot_a: snapshotA,
      ...(snapshotB != null ? { snapshot_b: snapshotB } : {}),
      ...(baseline ? { baseline: true } : {}),
    }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function driftDeleteSnapshot(id: number): Promise<void> {
  const res = await apiFetch(`${BASE}/api/drift/snapshot/${id}`, { method: 'DELETE' })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
}

// --- Process Explorer ---

export interface ProcessInfo {
  user: string
  pid: number
  cpu: number
  mem: number
  vsz: number
  rss: number
  tty: string
  stat: string
  start: string
  time: string
  command: string
}

export async function fetchProcessList(nodeId: string): Promise<ServiceResult> {
  const res = await apiFetch(`${BASE}/api/processes/${nodeId}/list`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function killProcess(nodeId: string, pid: number, signal: number): Promise<ServiceResult> {
  const res = await apiFetch(`${BASE}/api/processes/${nodeId}/kill`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pid, signal }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export function parseProcessList(output: string): ProcessInfo[] {
  const processes: ProcessInfo[] = []
  for (const line of output.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed) continue
    // ps aux --no-headers: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND...
    const parts = trimmed.split(/\s+/)
    if (parts.length >= 11) {
      processes.push({
        user: parts[0],
        pid: parseInt(parts[1], 10),
        cpu: parseFloat(parts[2]),
        mem: parseFloat(parts[3]),
        vsz: parseInt(parts[4], 10),
        rss: parseInt(parts[5], 10),
        tty: parts[6],
        stat: parts[7],
        start: parts[8],
        time: parts[9],
        command: parts.slice(10).join(' '),
      })
    }
  }
  return processes
}

// --- Log Streaming ---

export type LogSource = 'journal' | 'file'

export interface LogPollResult {
  output: string
  offset: number
  done: boolean
  ok: boolean
}

export async function startLogStream(
  nodeId: string,
  source: LogSource,
  service?: string,
  path?: string,
  lines?: number,
): Promise<string> {
  const res = await apiFetch(`${BASE}/api/logs/${nodeId}/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      source,
      ...(service ? { service } : {}),
      ...(path ? { path } : {}),
      ...(lines ? { lines } : {}),
    }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  const data = await res.json()
  return data.job_id
}

export async function pollLogStream(nodeId: string, jobId: string, offset: number): Promise<LogPollResult> {
  const res = await apiFetch(`${BASE}/api/logs/${nodeId}/poll?job=${jobId}&offset=${offset}`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function stopLogStream(nodeId: string, jobId: string): Promise<void> {
  await apiFetch(`${BASE}/api/logs/${nodeId}/stop`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ job_id: jobId }),
  })
}

// --- Event Timeline ---

export interface TimelineEvent {
  id: number
  created_at: number
  event_type: string
  node_id: string | null
  message: string
  detail: string | null
}

export async function fetchEvents(params?: {
  node_id?: string
  type?: string
  limit?: number
  before?: number
}): Promise<TimelineEvent[]> {
  const qs = new URLSearchParams()
  if (params?.node_id) qs.set('node_id', params.node_id)
  if (params?.type) qs.set('type', params.type)
  if (params?.limit) qs.set('limit', String(params.limit))
  if (params?.before) qs.set('before', String(params.before))
  const res = await apiFetch(`${BASE}/api/events?${qs}`)
  if (!res.ok) return []
  return res.json()
}

// --- Security Posture ---

export interface SecurityScanResult {
  ok: boolean
  score: number
  upgradable: Array<{ name: string; current: string; available: string }>
  ssh_config: Array<{ key: string; value: string; status: 'pass' | 'warn' | 'fail'; detail: string }>
  ports: Array<{ proto: string; address: string; port: string; process: string }>
  firewall: { active: boolean; type: string; rules: string }
  autoupdate: { enabled: boolean; package: string; detail: string }
  error?: string
}

export async function securityScan(nodeId: string): Promise<SecurityScanResult> {
  const res = await apiFetch(`${BASE}/api/security/${nodeId}/scan`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

// --- Container Management (Suffragette City) ---

export interface ContainerInfo {
  id: string
  name: string
  image: string
  status: string
  state: string
  ports: string
  size: string
}

export interface ContainerResult {
  ok: boolean
  output: string
}

export async function fetchContainers(nodeId: string): Promise<ContainerResult> {
  const res = await apiFetch(`${BASE}/api/containers/${nodeId}/list`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function inspectContainer(nodeId: string, containerId: string): Promise<ContainerResult> {
  const res = await apiFetch(`${BASE}/api/containers/${nodeId}/inspect?id=${encodeURIComponent(containerId)}`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function containerAction(nodeId: string, containerId: string, action: string): Promise<ContainerResult> {
  const res = await apiFetch(`${BASE}/api/containers/${nodeId}/action`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: containerId, action }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function fetchContainerLogs(nodeId: string, containerId: string, tail?: number): Promise<ContainerResult> {
  const res = await apiFetch(`${BASE}/api/containers/${nodeId}/logs?id=${encodeURIComponent(containerId)}&tail=${tail ?? 100}`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export function parseContainerList(output: string): ContainerInfo[] {
  return output.split('\n').filter(l => l.trim()).map(line => {
    const parts = line.split('\t')
    return {
      id: parts[0] ?? '',
      name: parts[1] ?? '',
      image: parts[2] ?? '',
      status: parts[3] ?? '',
      state: parts[4] ?? '',
      ports: parts[5] ?? '',
      size: parts[6] ?? '',
    }
  })
}
