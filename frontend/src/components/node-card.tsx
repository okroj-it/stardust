import { useEffect, useState } from "react"
import { cn, formatUptime, formatBytes } from "@/lib/utils"
import type { SystemStats, NodeStatus } from "@/lib/api"
import { fetchNodeStats } from "@/lib/api"
import { MiniChart } from "./mini-chart"
import {
  Server,
  Cpu,
  MemoryStick,
  HardDrive,
  Wifi,
  Clock,
  Activity,
  Tag,
} from "lucide-react"

interface NodeCardProps {
  node: NodeStatus
  onClick: () => void
  selected?: boolean
}

export function NodeCard({ node, onClick, selected }: NodeCardProps) {
  const [stats, setStats] = useState<SystemStats | null>(null)
  const [cpuHistory, setCpuHistory] = useState<number[]>([])

  useEffect(() => {
    const load = async () => {
      const s = await fetchNodeStats(node.agent_id)
      if (s) {
        setStats(s)
        setCpuHistory((prev) => [...prev.slice(-29), s.cpu.usage_percent])
      }
    }
    load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [node.agent_id])

  const online = node.connected

  return (
    <button
      onClick={onClick}
      className={cn(
        "relative group w-full text-left rounded-xl border p-5 transition-all duration-300",
        "bg-card/50 backdrop-blur-sm hover:bg-card/80",
        "hover:border-primary/30 hover:shadow-lg hover:shadow-primary/5",
        selected && "border-primary/50 bg-card/80 shadow-lg shadow-primary/10",
        !selected && "border-border/50"
      )}
    >
      {/* Glow effect on hover */}
      <div className="absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none bg-gradient-to-br from-primary/5 via-transparent to-transparent" />

      <div className="relative space-y-4">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className={cn(
              "p-2 rounded-lg",
              online ? "bg-emerald-500/10 text-emerald-400" : "bg-red-500/10 text-red-400"
            )}>
              <Server className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <h3 className="font-semibold text-sm truncate">{node.name || stats?.hostname || node.host}</h3>
              <p className="text-xs text-muted-foreground truncate">{node.host || stats?.hostname}</p>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            <div className={cn(
              "w-2 h-2 rounded-full",
              online ? "bg-emerald-400 animate-pulse-slow" : "bg-red-400"
            )} />
            <span className={cn(
              "text-xs font-medium",
              online ? "text-emerald-400" : "text-red-400"
            )}>
              {online ? "Online" : "Offline"}
            </span>
          </div>
        </div>

        {/* Tags */}
        {node.tags && node.tags.length > 0 && (
          <div className="flex items-center gap-1 flex-wrap">
            <Tag className="w-3 h-3 text-muted-foreground shrink-0" />
            {node.tags.slice(0, 3).map(tag => (
              <span key={tag} className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-primary/10 text-primary/80 border border-primary/20">
                {tag}
              </span>
            ))}
            {node.tags.length > 3 && (
              <span className="text-[10px] text-muted-foreground">+{node.tags.length - 3}</span>
            )}
          </div>
        )}

        {stats && (
          <>
            {/* Quick Stats */}
            <div className="grid grid-cols-3 gap-3">
              <QuickStat
                icon={<Cpu className="w-3.5 h-3.5" />}
                label="CPU"
                value={`${stats.cpu.usage_percent.toFixed(1)}%`}
                color={stats.cpu.usage_percent > 80 ? "text-red-400" : stats.cpu.usage_percent > 50 ? "text-amber-400" : "text-emerald-400"}
              />
              <QuickStat
                icon={<MemoryStick className="w-3.5 h-3.5" />}
                label="RAM"
                value={`${stats.memory.used_percent.toFixed(1)}%`}
                color={stats.memory.used_percent > 80 ? "text-red-400" : stats.memory.used_percent > 50 ? "text-amber-400" : "text-emerald-400"}
              />
              <QuickStat
                icon={<HardDrive className="w-3.5 h-3.5" />}
                label="Disks"
                value={`${stats.disks.length}`}
                color="text-blue-400"
              />
            </div>

            {/* CPU Sparkline */}
            {cpuHistory.length > 1 && (
              <MiniChart data={cpuHistory} height={32} color="rgb(99, 102, 241)" />
            )}

            {/* Footer */}
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <div className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                <span>{formatUptime(stats.uptime_secs)}</span>
              </div>
              <div className="flex items-center gap-1">
                <Activity className="w-3 h-3" />
                <span>Load {stats.load.one.toFixed(2)}</span>
              </div>
              <div className="flex items-center gap-1">
                <Wifi className="w-3 h-3" />
                <span>{formatBytes(stats.network.reduce((a, n) => a + n.rx_bytes, 0))} rx</span>
              </div>
            </div>
          </>
        )}

        {!stats && online && (
          <div className="flex items-center justify-center py-4">
            <div className="w-5 h-5 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
          </div>
        )}
      </div>
    </button>
  )
}

function QuickStat({
  icon,
  label,
  value,
  color,
}: {
  icon: React.ReactNode
  label: string
  value: string
  color: string
}) {
  return (
    <div className="flex flex-col gap-1 p-2 rounded-lg bg-muted/30">
      <div className="flex items-center gap-1.5 text-muted-foreground">
        {icon}
        <span className="text-[10px] uppercase tracking-wider">{label}</span>
      </div>
      <span className={cn("text-sm font-bold font-mono", color)}>{value}</span>
    </div>
  )
}
