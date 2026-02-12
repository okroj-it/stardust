import { useState, useEffect, useRef } from "react"
import { cn, formatBytes, formatUptime } from "@/lib/utils"
import { useNodeStats } from "@/hooks/use-stats"
import { StatRing } from "./stat-ring"
import { CpuCores } from "./cpu-cores"
import { MiniChart } from "./mini-chart"
import { TerminalModal } from "./terminal-modal"
import { WebTerminal } from "./web-terminal"
import { ServiceManager } from "./service-manager"
import { ProcessExplorer } from "./process-explorer"
import type { NodeStatus, Capabilities } from "@/lib/api"
import { deployStep, updateNodeTags, fetchAllTags } from "@/lib/api"
import {
  X,
  Cpu,
  MemoryStick,
  HardDrive,
  Network,
  Thermometer,
  Cable,
  ArrowDownToLine,
  ArrowUpFromLine,
  Clock,
  Gauge,
  Activity,
  Trash2,
  Package,
  Server,
  RotateCw,
  SquareTerminal,
  Cog,
  Tag,
} from "lucide-react"

interface NodeDetailProps {
  node: NodeStatus
  onClose: () => void
  onRemove: () => void
  onTagsChanged?: () => void
  capabilities?: Capabilities | null
}

export function NodeDetail({ node, onClose, onRemove, onTagsChanged, capabilities }: NodeDetailProps) {
  const nodeId = node.agent_id
  const { stats, history } = useNodeStats(nodeId, 5000)
  const [showTerminal, setShowTerminal] = useState(false)
  const [showShell, setShowShell] = useState(false)
  const [showReinstall, setShowReinstall] = useState(false)
  const [showServices, setShowServices] = useState(false)
  const [showProcesses, setShowProcesses] = useState(false)

  const cpuHistory = history.map((h) => h.cpu.usage_percent)
  const memHistory = history.map((h) => h.memory.used_percent)
  const loadHistory = history.map((h) => h.load.one)

  // Compute network throughput rates (bytes/sec) from cumulative counters
  const netRxRates: number[] = []
  const netTxRates: number[] = []
  for (let i = 1; i < history.length; i++) {
    const dt = (history[i].timestamp - history[i - 1].timestamp) / 1000
    if (dt <= 0) { netRxRates.push(0); netTxRates.push(0); continue }
    // Sum across all interfaces (exclude lo)
    const sumBytes = (snap: typeof history[0], field: 'rx_bytes' | 'tx_bytes') =>
      snap.network?.filter((n) => n.name !== 'lo').reduce((s, n) => s + n[field], 0) ?? 0
    const rxDelta = sumBytes(history[i], 'rx_bytes') - sumBytes(history[i - 1], 'rx_bytes')
    const txDelta = sumBytes(history[i], 'tx_bytes') - sumBytes(history[i - 1], 'tx_bytes')
    netRxRates.push(Math.max(0, rxDelta / dt))
    netTxRates.push(Math.max(0, txDelta / dt))
  }

  if (!stats) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">{stats.hostname}</h2>
          <p className="text-sm text-muted-foreground font-mono">{nodeId}</p>
        </div>
        <div className="flex items-center gap-1">
          {capabilities?.processes && node.connected && (
            <button
              onClick={() => setShowProcesses(true)}
              className="p-2 rounded-lg hover:bg-cyan-500/10 text-muted-foreground hover:text-cyan-400 transition-colors"
              title="Processes"
            >
              <Activity className="w-4 h-4" />
            </button>
          )}
          {capabilities?.services && node.connected && (
            <button
              onClick={() => setShowServices(true)}
              className="p-2 rounded-lg hover:bg-violet-500/10 text-muted-foreground hover:text-violet-400 transition-colors"
              title="Services"
            >
              <Cog className="w-4 h-4" />
            </button>
          )}
          {node.connected && (
            <button
              onClick={() => setShowShell(true)}
              className="p-2 rounded-lg hover:bg-[#58a6ff]/10 text-muted-foreground hover:text-[#58a6ff] transition-colors"
              title="SSH Terminal"
            >
              <SquareTerminal className="w-4 h-4" />
            </button>
          )}
          <button
            onClick={() => setShowTerminal(true)}
            className="p-2 rounded-lg hover:bg-primary/10 text-muted-foreground hover:text-primary transition-colors"
            title="Package upgrades"
          >
            <Package className="w-4 h-4" />
          </button>
          <button
            onClick={() => setShowReinstall(true)}
            className="p-2 rounded-lg hover:bg-amber-500/10 text-muted-foreground hover:text-amber-400 transition-colors"
            title="Reinstall Spider"
          >
            <RotateCw className="w-4 h-4" />
          </button>
          <button
            onClick={onRemove}
            className="p-2 rounded-lg hover:bg-red-500/10 text-muted-foreground hover:text-red-400 transition-colors"
            title="Remove node"
          >
            <Trash2 className="w-4 h-4" />
          </button>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-muted transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* System Info */}
      {(node.os_name || node.cpu_model || node.arch) && (
        <div className="p-4 rounded-xl border border-border/50 bg-card/30 backdrop-blur-sm">
          <div className="flex items-center gap-2 mb-3 text-muted-foreground">
            <Server className="w-4 h-4" />
            <span className="text-sm font-semibold text-foreground">System Info</span>
          </div>
          <div className="grid grid-cols-2 gap-x-8 gap-y-0.5">
            {node.os_name && <InfoRow label="OS" value={node.os_name} />}
            {node.arch && <InfoRow label="Architecture" value={node.arch} />}
            {node.kernel && <InfoRow label="Kernel" value={node.kernel} />}
            {node.cpu_model && <InfoRow label="CPU" value={`${node.cpu_model}${node.cpu_cores ? ` (${node.cpu_cores} cores)` : ''}`} />}
            {node.total_ram != null && <InfoRow label="Total RAM" value={formatBytes(node.total_ram)} />}
            {node.pkg_manager && <InfoRow label="Package Manager" value={node.pkg_manager} />}
          </div>
        </div>
      )}

      {/* Tags */}
      <TagEditor
        nodeId={nodeId}
        tags={node.tags ?? []}
        onChanged={onTagsChanged}
      />

      {/* Overview Rings */}
      <div className="grid grid-cols-3 gap-6 p-6 rounded-xl border border-border/50 bg-card/30 backdrop-blur-sm">
        <StatRing
          value={stats.cpu.usage_percent}
          label="CPU"
          sublabel={`${stats.cpu.cores.length} cores`}
          color="rgb(99, 102, 241)"
        />
        <StatRing
          value={stats.memory.used_percent}
          label="Memory"
          sublabel={formatBytes(stats.memory.total_bytes)}
          color="rgb(16, 185, 129)"
        />
        <StatRing
          value={stats.swap.used_percent}
          label="Swap"
          sublabel={formatBytes(stats.swap.total_bytes)}
          color="rgb(245, 158, 11)"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-2 gap-4">
        <ChartCard title="CPU Usage" data={cpuHistory} color="rgb(99, 102, 241)" icon={<Cpu className="w-4 h-4" />} suffix="%" />
        <ChartCard title="Memory" data={memHistory} color="rgb(16, 185, 129)" icon={<MemoryStick className="w-4 h-4" />} suffix="%" />
        <ChartCard title="Load Avg" data={loadHistory} color="rgb(245, 158, 11)" icon={<Activity className="w-4 h-4" />} />
        <NetworkChartCard rxRates={netRxRates} txRates={netTxRates} />
      </div>

      {/* CPU Cores */}
      <div className="p-5 rounded-xl border border-border/50 bg-card/30 backdrop-blur-sm">
        <CpuCores cores={stats.cpu.cores} />
      </div>

      {/* System Info Grid */}
      <div className="grid grid-cols-2 gap-4">
        {/* Memory Breakdown */}
        <InfoCard title="Memory" icon={<MemoryStick className="w-4 h-4" />}>
          <InfoRow label="Total" value={formatBytes(stats.memory.total_bytes)} />
          <InfoRow label="Available" value={formatBytes(stats.memory.available_bytes)} />
          <InfoRow label="Buffers" value={formatBytes(stats.memory.buffers_bytes)} />
          <InfoRow label="Cached" value={formatBytes(stats.memory.cached_bytes)} />
          <InfoRow label="Active" value={formatBytes(stats.memory.active_bytes)} />
          <InfoRow label="Inactive" value={formatBytes(stats.memory.inactive_bytes)} />
        </InfoCard>

        {/* Load & System */}
        <InfoCard title="System" icon={<Gauge className="w-4 h-4" />}>
          <InfoRow label="Load 1m" value={stats.load.one.toFixed(2)} />
          <InfoRow label="Load 5m" value={stats.load.five.toFixed(2)} />
          <InfoRow label="Load 15m" value={stats.load.fifteen.toFixed(2)} />
          <InfoRow label="Processes" value={`${stats.load.running_processes} / ${stats.load.total_processes}`} />
          <InfoRow label="Uptime" value={formatUptime(stats.uptime_secs)} icon={<Clock className="w-3 h-3" />} />
        </InfoCard>

        {/* Filesystem Usage */}
        <div className="col-span-2">
          <InfoCard title="Disk Usage" icon={<HardDrive className="w-4 h-4" />}>
            {(stats.filesystems ?? []).length > 0 ? (
              <div className="space-y-3">
                {stats.filesystems.map((fs) => (
                  <div key={fs.mount_point}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono text-muted-foreground">{fs.mount_point}</span>
                      <span className="text-xs text-muted-foreground">
                        {formatBytes(fs.total_bytes - fs.free_bytes)} / {formatBytes(fs.total_bytes)}
                        <span className="ml-1.5 text-foreground font-mono">{fs.used_percent.toFixed(1)}%</span>
                      </span>
                    </div>
                    <div className="h-2 rounded-full bg-muted/50 overflow-hidden">
                      <div
                        className={cn(
                          "h-full rounded-full transition-all duration-500",
                          fs.used_percent > 90
                            ? "bg-red-500"
                            : fs.used_percent > 75
                              ? "bg-amber-500"
                              : "bg-emerald-500"
                        )}
                        style={{ width: `${Math.min(fs.used_percent, 100)}%` }}
                      />
                    </div>
                    <div className="text-[10px] text-muted-foreground/60 mt-0.5">{fs.fs_type}</div>
                  </div>
                ))}
              </div>
            ) : stats.disks.length > 0 ? (
              stats.disks.map((d) => (
                <div key={d.name} className="flex items-center justify-between py-1.5 border-b border-border/30 last:border-0">
                  <span className="text-xs font-mono text-muted-foreground">{d.name}</span>
                  <div className="flex gap-3">
                    <span className="text-xs text-emerald-400 flex items-center gap-1">
                      <ArrowDownToLine className="w-3 h-3" />
                      {d.reads_completed.toLocaleString()} reads
                    </span>
                    <span className="text-xs text-amber-400 flex items-center gap-1">
                      <ArrowUpFromLine className="w-3 h-3" />
                      {d.writes_completed.toLocaleString()} writes
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-xs text-muted-foreground">No disk data</p>
            )}
          </InfoCard>
        </div>

        {/* Network */}
        <InfoCard title="Network" icon={<Network className="w-4 h-4" />}>
          {stats.network.filter((n) => n.name !== 'lo').map((n) => (
            <div key={n.name} className="flex items-center justify-between py-1.5 border-b border-border/30 last:border-0">
              <span className="text-xs font-mono text-muted-foreground">{n.name}</span>
              <div className="flex gap-3">
                <span className="text-xs text-blue-400 flex items-center gap-1">
                  <ArrowDownToLine className="w-3 h-3" />
                  {formatBytes(n.rx_bytes)}
                </span>
                <span className="text-xs text-purple-400 flex items-center gap-1">
                  <ArrowUpFromLine className="w-3 h-3" />
                  {formatBytes(n.tx_bytes)}
                </span>
              </div>
            </div>
          ))}
        </InfoCard>

        {/* Connections */}
        <InfoCard title="Connections" icon={<Cable className="w-4 h-4" />}>
          <InfoRow label="Established" value={String(stats.connections.established)} dot="bg-emerald-400" />
          <InfoRow label="Listen" value={String(stats.connections.listen)} dot="bg-blue-400" />
          <InfoRow label="Time Wait" value={String(stats.connections.time_wait)} dot="bg-amber-400" />
          <InfoRow label="Close Wait" value={String(stats.connections.close_wait)} dot="bg-red-400" />
          <InfoRow label="Total" value={String(stats.connections.total)} />
        </InfoCard>

        {/* Temperatures */}
        {stats.temperatures.length > 0 && (
          <InfoCard title="Temperatures" icon={<Thermometer className="w-4 h-4" />}>
            {stats.temperatures.map((t) => (
              <InfoRow key={t.zone} label={t.label} value={`${t.temp_celsius.toFixed(1)}C`} />
            ))}
          </InfoCard>
        )}
      </div>

      {showProcesses && (
        <ProcessExplorer
          nodeId={nodeId}
          nodeName={node.name}
          onClose={() => setShowProcesses(false)}
        />
      )}

      {showServices && (
        <ServiceManager
          nodeId={nodeId}
          nodeName={node.name}
          onClose={() => setShowServices(false)}
        />
      )}

      {showShell && (
        <WebTerminal
          nodeId={nodeId}
          nodeName={node.name}
          onClose={() => setShowShell(false)}
        />
      )}

      {showTerminal && (
        <TerminalModal
          nodeId={nodeId}
          nodePkgManager={node.pkg_manager}
          onClose={() => setShowTerminal(false)}
        />
      )}

      {showReinstall && (
        <ReinstallDialog
          nodeId={nodeId}
          onClose={() => setShowReinstall(false)}
        />
      )}
    </div>
  )
}

function ChartCard({
  title,
  data,
  color,
  icon,
  suffix,
}: {
  title: string
  data: number[]
  color: string
  icon: React.ReactNode
  suffix?: string
}) {
  return (
    <div className="p-4 rounded-xl border border-border/50 bg-card/30 backdrop-blur-sm">
      <div className="flex items-center gap-2 mb-3 text-muted-foreground">
        {icon}
        <span className="text-xs font-medium">{title}</span>
        {data.length > 0 && (
          <span className="ml-auto text-xs font-mono text-foreground">
            {data[data.length - 1]?.toFixed(1)}{suffix ?? ''}
          </span>
        )}
      </div>
      <MiniChart data={data} height={48} color={color} />
    </div>
  )
}

function NetworkChartCard({
  rxRates,
  txRates,
}: {
  rxRates: number[]
  txRates: number[]
}) {
  const lastRx = rxRates.length > 0 ? rxRates[rxRates.length - 1] : 0
  const lastTx = txRates.length > 0 ? txRates[txRates.length - 1] : 0

  return (
    <div className="p-4 rounded-xl border border-border/50 bg-card/30 backdrop-blur-sm">
      <div className="flex items-center gap-2 mb-3 text-muted-foreground">
        <Network className="w-4 h-4" />
        <span className="text-xs font-medium">Network</span>
        <span className="ml-auto text-xs font-mono flex gap-2">
          <span className="text-blue-400">{formatBytes(lastRx)}/s</span>
          <span className="text-purple-400">{formatBytes(lastTx)}/s</span>
        </span>
      </div>
      <DualChart rxData={rxRates} txData={txRates} height={48} />
    </div>
  )
}

function DualChart({
  rxData,
  txData,
  height,
}: {
  rxData: number[]
  txData: number[]
  height: number
}) {
  const width = 200
  const allData = [...rxData, ...txData]
  const max = allData.length > 0 ? Math.max(...allData, 1) : 1

  const makePath = (data: number[]) => {
    if (data.length < 2) return ''
    const stepX = width / (data.length - 1)
    return data.map((v, i) => {
      const x = i * stepX
      const y = height - (v / max) * height
      return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`
    }).join(' ')
  }

  const makeArea = (data: number[]) => {
    const path = makePath(data)
    if (!path) return ''
    const stepX = width / (data.length - 1)
    return `${path} L${((data.length - 1) * stepX).toFixed(1)},${height} L0,${height} Z`
  }

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full" style={{ height }}>
      <defs>
        <linearGradient id="rxGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="rgb(96, 165, 250)" stopOpacity="0.3" />
          <stop offset="100%" stopColor="rgb(96, 165, 250)" stopOpacity="0" />
        </linearGradient>
        <linearGradient id="txGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="rgb(192, 132, 252)" stopOpacity="0.3" />
          <stop offset="100%" stopColor="rgb(192, 132, 252)" stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={makeArea(rxData)} fill="url(#rxGrad)" />
      <path d={makePath(rxData)} fill="none" stroke="rgb(96, 165, 250)" strokeWidth="1.5" />
      <path d={makeArea(txData)} fill="url(#txGrad)" />
      <path d={makePath(txData)} fill="none" stroke="rgb(192, 132, 252)" strokeWidth="1.5" />
    </svg>
  )
}

function InfoCard({
  title,
  icon,
  children,
}: {
  title: string
  icon: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div className="p-4 rounded-xl border border-border/50 bg-card/30 backdrop-blur-sm">
      <div className="flex items-center gap-2 mb-3 text-muted-foreground">
        {icon}
        <span className="text-sm font-semibold text-foreground">{title}</span>
      </div>
      <div className="space-y-0.5">{children}</div>
    </div>
  )
}

function InfoRow({
  label,
  value,
  icon,
  dot,
}: {
  label: string
  value: string
  icon?: React.ReactNode
  dot?: string
}) {
  return (
    <div className="flex items-center justify-between py-1">
      <span className="text-xs text-muted-foreground flex items-center gap-1.5">
        {dot && <div className={cn("w-1.5 h-1.5 rounded-full", dot)} />}
        {icon}
        {label}
      </span>
      <span className="text-xs font-mono text-foreground">{value}</span>
    </div>
  )
}

function TagEditor({ nodeId, tags, onChanged }: { nodeId: string; tags: string[]; onChanged?: () => void }) {
  const [localTags, setLocalTags] = useState<string[]>(tags)
  const [input, setInput] = useState("")
  const [suggestions, setSuggestions] = useState<string[]>([])
  const [allTags, setAllTags] = useState<string[]>([])
  const [showSuggestions, setShowSuggestions] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => { setLocalTags(tags) }, [tags.join(',')])

  useEffect(() => {
    fetchAllTags().then(setAllTags).catch(() => {})
  }, [])

  useEffect(() => {
    if (input.trim()) {
      const lower = input.toLowerCase()
      setSuggestions(allTags.filter(t => t.toLowerCase().includes(lower) && !localTags.includes(t)).slice(0, 5))
    } else {
      setSuggestions([])
    }
  }, [input, allTags, localTags])

  const save = async (newTags: string[]) => {
    setLocalTags(newTags)
    try {
      await updateNodeTags(nodeId, newTags)
      onChanged?.()
    } catch {}
  }

  const addTag = (tag: string) => {
    const t = tag.trim().toLowerCase()
    if (t && !localTags.includes(t)) {
      save([...localTags, t])
    }
    setInput("")
    setShowSuggestions(false)
  }

  const removeTag = (tag: string) => {
    save(localTags.filter(t => t !== tag))
  }

  return (
    <div className="p-4 rounded-xl border border-border/50 bg-card/30 backdrop-blur-sm">
      <div className="flex items-center gap-2 mb-3 text-muted-foreground">
        <Tag className="w-4 h-4" />
        <span className="text-sm font-semibold text-foreground">Tags</span>
      </div>
      <div className="flex items-center gap-1.5 flex-wrap">
        {localTags.map(tag => (
          <span key={tag} className="flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium bg-primary/10 text-primary border border-primary/20 group">
            {tag}
            <button onClick={() => removeTag(tag)} className="text-primary/40 hover:text-red-400 transition-colors">
              <X className="w-3 h-3" />
            </button>
          </span>
        ))}
        <div className="relative">
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && input.trim()) { addTag(input); e.preventDefault() }
              if (e.key === 'Backspace' && !input && localTags.length > 0) removeTag(localTags[localTags.length - 1])
            }}
            onFocus={() => setShowSuggestions(true)}
            onBlur={() => setTimeout(() => setShowSuggestions(false), 150)}
            placeholder={localTags.length === 0 ? "Add tags..." : "+"}
            className="w-24 px-2 py-0.5 rounded-md text-xs bg-transparent border border-border/30 text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40"
          />
          {showSuggestions && suggestions.length > 0 && (
            <div className="absolute top-full left-0 mt-1 w-40 rounded-lg bg-card border border-border/50 shadow-lg z-10 overflow-hidden">
              {suggestions.map(s => (
                <button
                  key={s}
                  onMouseDown={() => addTag(s)}
                  className="w-full px-3 py-1.5 text-left text-xs text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                >
                  {s}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

type ReinstallStep = 'confirm' | 'stopping' | 'uploading' | 'installing' | 'starting' | 'done' | 'error'

function ReinstallDialog({ nodeId, onClose }: { nodeId: string; onClose: () => void }) {
  const [step, setStep] = useState<ReinstallStep>('confirm')
  const [error, setError] = useState<string | null>(null)

  const runReinstall = async () => {
    const steps: { step: Parameters<typeof deployStep>[1]; label: ReinstallStep }[] = [
      { step: 'stop', label: 'stopping' },
      { step: 'upload', label: 'uploading' },
      { step: 'install', label: 'installing' },
      { step: 'start', label: 'starting' },
    ]

    for (const s of steps) {
      setStep(s.label)
      try {
        const res = await deployStep(nodeId, s.step)
        if (!res.ok) {
          setError(res.message)
          setStep('error')
          return
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed')
        setStep('error')
        return
      }
    }
    setStep('done')
  }

  const isRunning = step !== 'confirm' && step !== 'done' && step !== 'error'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={!isRunning ? onClose : undefined} />
      <div className="relative w-full max-w-md mx-4 rounded-2xl border border-border/50 bg-card shadow-2xl animate-in fade-in zoom-in-95 duration-200 p-6">
        <h3 className="text-lg font-semibold mb-2">Reinstall Spider</h3>

        {step === 'confirm' && (
          <>
            <p className="text-sm text-muted-foreground mb-4">
              This will stop the Spider, upload the latest binary, reinstall the service, and restart it.
            </p>
            <div className="flex justify-end gap-2">
              <button onClick={onClose} className="px-3 py-1.5 rounded-lg text-sm text-muted-foreground hover:bg-muted transition-colors">Cancel</button>
              <button onClick={runReinstall} className="px-3 py-1.5 rounded-lg text-sm bg-amber-600 text-white hover:bg-amber-700 transition-colors font-medium">Reinstall</button>
            </div>
          </>
        )}

        {isRunning && (
          <div className="flex items-center gap-3 py-2">
            <div className="w-5 h-5 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
            <span className="text-sm text-muted-foreground">
              {step === 'stopping' && 'Standing down Spider...'}
              {step === 'uploading' && 'Major Tom stepping through the door...'}
              {step === 'installing' && 'Wiring up the circuits...'}
              {step === 'starting' && 'Launching Spider...'}
            </span>
          </div>
        )}

        {step === 'done' && (
          <>
            <p className="text-sm text-emerald-400 mb-4">Major Tom has landed — Spider reinstalled.</p>
            <div className="flex justify-end">
              <button onClick={onClose} className="px-3 py-1.5 rounded-lg text-sm bg-primary text-primary-foreground hover:bg-primary/90 transition-colors font-medium">Done</button>
            </div>
          </>
        )}

        {step === 'error' && (
          <>
            <p className="text-sm text-red-400 mb-4">{error || 'Reinstall failed'}</p>
            <div className="flex justify-end gap-2">
              <button onClick={onClose} className="px-3 py-1.5 rounded-lg text-sm text-muted-foreground hover:bg-muted transition-colors">Close</button>
              <button onClick={runReinstall} className="px-3 py-1.5 rounded-lg text-sm bg-amber-600 text-white hover:bg-amber-700 transition-colors font-medium">Retry</button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
