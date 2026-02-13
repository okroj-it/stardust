import { useState, useEffect, useCallback, useRef } from "react"
import { fetchContainers, inspectContainer, containerAction, fetchContainerLogs, parseContainerList } from "@/lib/api"
import type { ContainerInfo } from "@/lib/api"
import {
  X,
  Loader2,
  Play,
  Square,
  RotateCw,
  Search,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  AlertCircle,
  Box,
  Pause,
  Trash2,
  ScrollText,
  FileJson,
} from "lucide-react"

interface ContainerManagerProps {
  nodeId: string
  nodeName: string
  onClose: () => void
}

type DetailTab = 'inspect' | 'logs'

const STATE_COLORS: Record<string, string> = {
  running: 'text-emerald-400',
  exited: 'text-red-400',
  paused: 'text-amber-400',
  created: 'text-blue-400',
  restarting: 'text-cyan-400',
  dead: 'text-red-500',
  removing: 'text-orange-400',
}

const STATE_DOTS: Record<string, string> = {
  running: 'bg-emerald-400',
  exited: 'bg-red-400',
  paused: 'bg-amber-400',
  created: 'bg-blue-400',
  restarting: 'bg-cyan-400',
  dead: 'bg-red-500',
  removing: 'bg-orange-400',
}

function getActionsForState(state: string): Array<{ action: string; label: string; icon: typeof Play; color: string }> {
  switch (state.toLowerCase()) {
    case 'running':
      return [
        { action: 'stop', label: 'Stop', icon: Square, color: 'text-red-400 hover:bg-red-500/10' },
        { action: 'restart', label: 'Restart', icon: RotateCw, color: 'text-amber-400 hover:bg-amber-500/10' },
        { action: 'pause', label: 'Pause', icon: Pause, color: 'text-blue-400 hover:bg-blue-500/10' },
      ]
    case 'exited':
    case 'created':
    case 'dead':
      return [
        { action: 'start', label: 'Start', icon: Play, color: 'text-emerald-400 hover:bg-emerald-500/10' },
        { action: 'rm', label: 'Remove', icon: Trash2, color: 'text-red-400 hover:bg-red-500/10' },
      ]
    case 'paused':
      return [
        { action: 'unpause', label: 'Unpause', icon: Play, color: 'text-emerald-400 hover:bg-emerald-500/10' },
        { action: 'stop', label: 'Stop', icon: Square, color: 'text-red-400 hover:bg-red-500/10' },
      ]
    default:
      return [
        { action: 'stop', label: 'Stop', icon: Square, color: 'text-red-400 hover:bg-red-500/10' },
        { action: 'start', label: 'Start', icon: Play, color: 'text-emerald-400 hover:bg-emerald-500/10' },
      ]
  }
}

export function ContainerManager({ nodeId, nodeName, onClose }: ContainerManagerProps) {
  const [containers, setContainers] = useState<ContainerInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [noRuntime, setNoRuntime] = useState(false)
  const [filter, setFilter] = useState("")
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [detailTab, setDetailTab] = useState<DetailTab>('inspect')
  const [detailContent, setDetailContent] = useState<string | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const detailRef = useRef<HTMLPreElement | null>(null)

  const loadContainers = useCallback(async () => {
    if (!loading) setLoading(true)
    setError(null)
    setNoRuntime(false)

    try {
      const result = await fetchContainers(nodeId)
      if (result.ok) {
        setContainers(parseContainerList(result.output))
        setNoRuntime(false)
      } else {
        const out = result.output.toLowerCase()
        if (out.includes('not found') || out.includes('command not found') || out.includes('no such file')) {
          setNoRuntime(true)
          setContainers([])
        } else {
          setError(result.output || "Failed to list containers")
          setContainers([])
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch containers")
      setContainers([])
    } finally {
      setLoading(false)
    }
  }, [nodeId])

  useEffect(() => {
    loadContainers()
  }, [loadContainers])

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(loadContainers, 5000)
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [autoRefresh, loadContainers])

  const handleExpand = async (id: string) => {
    if (expandedId === id) {
      setExpandedId(null)
      setDetailContent(null)
      return
    }

    setExpandedId(id)
    setDetailTab('inspect')
    setDetailLoading(true)
    setDetailContent(null)

    try {
      const result = await inspectContainer(nodeId, id)
      try {
        const parsed = JSON.parse(result.output)
        setDetailContent(JSON.stringify(parsed, null, 2))
      } catch {
        setDetailContent(result.output || "(no output)")
      }
    } catch {
      setDetailContent("Failed to fetch inspect data")
    } finally {
      setDetailLoading(false)
    }
  }

  const handleTabChange = async (tab: DetailTab) => {
    if (!expandedId) return
    setDetailTab(tab)
    setDetailLoading(true)
    setDetailContent(null)

    try {
      if (tab === 'inspect') {
        const result = await inspectContainer(nodeId, expandedId)
        try {
          const parsed = JSON.parse(result.output)
          setDetailContent(JSON.stringify(parsed, null, 2))
        } catch {
          setDetailContent(result.output || "(no output)")
        }
      } else {
        const result = await fetchContainerLogs(nodeId, expandedId, 100)
        setDetailContent(result.output || "(no logs)")
      }
    } catch {
      setDetailContent(`Failed to fetch ${tab} data`)
    } finally {
      setDetailLoading(false)
    }
  }

  const handleAction = async (containerId: string, action: string) => {
    setActionLoading(`${containerId}:${action}`)
    try {
      await containerAction(nodeId, containerId, action)
      await loadContainers()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed")
    } finally {
      setActionLoading(null)
    }
  }

  const filtered = containers.filter(c =>
    c.name.toLowerCase().includes(filter.toLowerCase()) ||
    c.image.toLowerCase().includes(filter.toLowerCase()) ||
    c.id.toLowerCase().includes(filter.toLowerCase())
  )

  const runningCount = containers.filter(c => c.state.toLowerCase() === 'running').length
  const stoppedCount = containers.filter(c => c.state.toLowerCase() === 'exited').length

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-5xl mx-4 rounded-2xl border border-border/50 bg-[#0d1117] shadow-2xl animate-in fade-in zoom-in-95 duration-200 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border/30 bg-[#161b22] rounded-t-2xl">
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-[#ff5f57]" />
              <div className="w-3 h-3 rounded-full bg-[#febc2e]" />
              <div className="w-3 h-3 rounded-full bg-[#28c840]" />
            </div>
            <div className="flex items-center gap-2">
              <Box className="w-3.5 h-3.5 text-blue-400" />
              <span className="text-xs text-[#8b949e] font-mono">Containers</span>
              <span className="text-[10px] text-blue-400 bg-blue-400/10 px-1.5 py-0.5 rounded font-mono">
                {nodeName}
              </span>
              <span className="text-[10px] text-[#484f58] font-mono ml-1">Suffragette City</span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-[#30363d] transition-colors"
          >
            <X className="w-4 h-4 text-[#8b949e]" />
          </button>
        </div>

        {/* Toolbar */}
        <div className="flex items-center gap-3 px-4 py-2.5 border-b border-border/20">
          {/* Search */}
          <div className="flex-1 relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-[#484f58]" />
            <input
              type="text"
              value={filter}
              onChange={e => setFilter(e.target.value)}
              placeholder="Filter containers..."
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-[#161b22] border border-border/30 text-xs font-mono text-[#c9d1d9] placeholder:text-[#484f58] focus:outline-none focus:border-blue-500/40"
            />
          </div>

          {/* Stats */}
          {!loading && !noRuntime && (
            <div className="flex items-center gap-3 text-[10px] font-mono">
              <span className="text-[#8b949e]">{containers.length} total</span>
              <span className="text-emerald-400">{runningCount} running</span>
              {stoppedCount > 0 && <span className="text-red-400">{stoppedCount} stopped</span>}
            </div>
          )}

          {/* Auto-refresh */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-2 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
              autoRefresh
                ? 'border-blue-500/30 bg-blue-500/10 text-blue-400'
                : 'border-border/30 bg-[#161b22] text-[#484f58] hover:text-[#8b949e]'
            }`}
          >
            <RefreshCw className={`w-3 h-3 ${autoRefresh ? 'animate-spin' : ''}`} />
            Auto
          </button>

          {/* Refresh */}
          <button
            onClick={loadContainers}
            disabled={loading}
            className="p-1.5 rounded-lg hover:bg-[#161b22] text-[#484f58] hover:text-[#8b949e] transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto min-h-0">
          {loading && containers.length === 0 ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="w-5 h-5 animate-spin text-[#484f58]" />
            </div>
          ) : noRuntime ? (
            <div className="flex flex-col items-center justify-center py-16 text-center px-8">
              <Box className="w-8 h-8 text-[#30363d] mb-3" />
              <p className="text-sm text-[#8b949e] mb-1">No container runtime detected</p>
              <p className="text-xs text-[#484f58]">
                Install Docker or Podman on this node to manage containers.
              </p>
            </div>
          ) : error ? (
            <div className="flex items-center gap-2 mx-4 my-4 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <p className="text-xs text-red-400 font-mono">{error}</p>
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <Box className="w-8 h-8 text-[#30363d] mb-3" />
              <p className="text-sm text-[#8b949e]">
                {filter ? 'No containers match filter' : 'No containers found'}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-border/10">
              {filtered.map(container => (
                <div key={container.id}>
                  {/* Container row */}
                  <div
                    className="flex items-center gap-3 px-4 py-2.5 hover:bg-[#161b22]/50 cursor-pointer transition-colors"
                    onClick={() => handleExpand(container.id)}
                  >
                    {/* Expand icon */}
                    <div className="shrink-0 text-[#484f58]">
                      {expandedId === container.id
                        ? <ChevronDown className="w-3.5 h-3.5" />
                        : <ChevronRight className="w-3.5 h-3.5" />
                      }
                    </div>

                    {/* State dot */}
                    <div className={`w-2 h-2 rounded-full shrink-0 ${STATE_DOTS[container.state.toLowerCase()] ?? 'bg-[#484f58]'}`} />

                    {/* ID */}
                    <span className="text-[10px] font-mono text-[#484f58] w-16 shrink-0 truncate">
                      {container.id.slice(0, 12)}
                    </span>

                    {/* Name */}
                    <span className="text-xs font-mono text-[#c9d1d9] w-40 shrink-0 truncate" title={container.name}>
                      {container.name}
                    </span>

                    {/* Image */}
                    <span className="text-xs font-mono text-[#8b949e] flex-1 truncate" title={container.image}>
                      {container.image}
                    </span>

                    {/* State */}
                    <span className={`text-[10px] font-mono uppercase tracking-wide w-16 text-right shrink-0 ${STATE_COLORS[container.state.toLowerCase()] ?? 'text-[#484f58]'}`}>
                      {container.state}
                    </span>

                    {/* Status */}
                    <span className="text-[10px] font-mono text-[#484f58] w-32 text-right shrink-0 truncate" title={container.status}>
                      {container.status}
                    </span>

                    {/* Actions */}
                    <div className="flex items-center gap-0.5 shrink-0" onClick={e => e.stopPropagation()}>
                      {getActionsForState(container.state).map(({ action, label, icon: Icon, color }) => (
                        <button
                          key={action}
                          onClick={() => handleAction(container.id, action)}
                          disabled={actionLoading === `${container.id}:${action}`}
                          className={`p-1.5 rounded transition-colors ${color} disabled:opacity-50`}
                          title={label}
                        >
                          {actionLoading === `${container.id}:${action}`
                            ? <Loader2 className="w-3 h-3 animate-spin" />
                            : <Icon className="w-3 h-3" />
                          }
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Expanded detail */}
                  {expandedId === container.id && (
                    <div className="px-4 pb-3">
                      <div className="ml-8 rounded-lg border border-border/20 bg-[#0d1117] overflow-hidden">
                        {/* Ports row if present */}
                        {container.ports && (
                          <div className="px-3 py-1.5 border-b border-border/10 text-[10px] font-mono text-[#8b949e]">
                            <span className="text-[#484f58]">Ports:</span> {container.ports}
                          </div>
                        )}

                        {/* Tabs */}
                        <div className="flex border-b border-border/20">
                          <button
                            onClick={() => handleTabChange('inspect')}
                            className={`flex items-center gap-1.5 px-3 py-2 text-[10px] font-mono transition-colors ${
                              detailTab === 'inspect'
                                ? 'text-blue-400 border-b-2 border-blue-400 -mb-px'
                                : 'text-[#484f58] hover:text-[#8b949e]'
                            }`}
                          >
                            <FileJson className="w-3 h-3" />
                            Inspect
                          </button>
                          <button
                            onClick={() => handleTabChange('logs')}
                            className={`flex items-center gap-1.5 px-3 py-2 text-[10px] font-mono transition-colors ${
                              detailTab === 'logs'
                                ? 'text-blue-400 border-b-2 border-blue-400 -mb-px'
                                : 'text-[#484f58] hover:text-[#8b949e]'
                            }`}
                          >
                            <ScrollText className="w-3 h-3" />
                            Logs
                          </button>
                        </div>

                        {/* Detail content */}
                        <div className="max-h-64 overflow-auto">
                          {detailLoading ? (
                            <div className="flex items-center justify-center py-8">
                              <Loader2 className="w-4 h-4 animate-spin text-[#484f58]" />
                            </div>
                          ) : (
                            <pre
                              ref={detailRef}
                              className="p-3 text-[11px] font-mono text-[#8b949e] leading-relaxed whitespace-pre-wrap break-all"
                            >
                              {detailContent || "(no data)"}
                            </pre>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
