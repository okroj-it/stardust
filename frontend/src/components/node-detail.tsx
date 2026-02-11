import { useState } from "react"
import { cn, formatBytes, formatUptime } from "@/lib/utils"
import { useNodeStats } from "@/hooks/use-stats"
import { StatRing } from "./stat-ring"
import { CpuCores } from "./cpu-cores"
import { MiniChart } from "./mini-chart"
import { TerminalModal } from "./terminal-modal"
import type { NodeStatus } from "@/lib/api"
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
  RefreshCw,
} from "lucide-react"

interface NodeDetailProps {
  node: NodeStatus
  onClose: () => void
  onRemove: () => void
}

export function NodeDetail({ node, onClose, onRemove }: NodeDetailProps) {
  const nodeId = node.agent_id
  const { stats, history } = useNodeStats(nodeId, 5000)
  const [showTerminal, setShowTerminal] = useState(false)

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
          <button
            onClick={() => setShowTerminal(true)}
            className="p-2 rounded-lg hover:bg-primary/10 text-muted-foreground hover:text-primary transition-colors"
            title="Refresh packages"
          >
            <RefreshCw className="w-4 h-4" />
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

      {showTerminal && (
        <TerminalModal
          nodeId={nodeId}
          onClose={() => setShowTerminal(false)}
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
