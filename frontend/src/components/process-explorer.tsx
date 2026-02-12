import { useState, useEffect, useCallback, useRef } from "react"
import { fetchProcessList, killProcess, parseProcessList } from "@/lib/api"
import type { ProcessInfo } from "@/lib/api"
import {
  X,
  Loader2,
  Search,
  RefreshCw,
  Activity,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  Skull,
  Zap,
  RotateCw,
} from "lucide-react"

interface ProcessExplorerProps {
  nodeId: string
  nodeName: string
  onClose: () => void
}

type SortField = 'cpu' | 'mem' | 'pid' | 'user' | 'command' | 'rss'
type SortDir = 'asc' | 'desc'

export function ProcessExplorer({ nodeId, nodeName, onClose }: ProcessExplorerProps) {
  const [processes, setProcesses] = useState<ProcessInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState("")
  const [sortField, setSortField] = useState<SortField>('cpu')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [killing, setKilling] = useState<number | null>(null)
  const [killConfirm, setKillConfirm] = useState<{ pid: number; command: string; user: string } | null>(null)
  const [killSignal, setKillSignal] = useState<number>(15)
  const [killResult, setKillResult] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<number | null>(null)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const loadProcesses = useCallback(async () => {
    if (!loading) setError(null)
    try {
      const result = await fetchProcessList(nodeId)
      if (result.ok) {
        setProcesses(parseProcessList(result.output))
        setError(null)
      } else {
        setError(result.output || "Failed to list processes")
        setProcesses([])
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch processes")
      setProcesses([])
    } finally {
      setLoading(false)
    }
  }, [nodeId])

  useEffect(() => {
    loadProcesses()
  }, [loadProcesses])

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(loadProcesses, 3000)
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [autoRefresh, loadProcesses])

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDir(field === 'user' || field === 'command' ? 'asc' : 'desc')
    }
  }

  const handleKill = async () => {
    if (!killConfirm) return
    setKilling(killConfirm.pid)
    setKillResult(null)
    try {
      const result = await killProcess(nodeId, killConfirm.pid, killSignal)
      if (result.ok) {
        setKillResult("Signal sent")
        setTimeout(() => {
          setKillConfirm(null)
          setKillResult(null)
          loadProcesses()
        }, 800)
      } else {
        setKillResult(result.output || "Kill failed")
      }
    } catch (err) {
      setKillResult(err instanceof Error ? err.message : "Kill failed")
    } finally {
      setKilling(null)
    }
  }

  const sorted = [...processes]
    .filter(p => {
      if (!filter) return true
      const lower = filter.toLowerCase()
      return p.user.toLowerCase().includes(lower) ||
        p.command.toLowerCase().includes(lower) ||
        String(p.pid).includes(lower)
    })
    .sort((a, b) => {
      const dir = sortDir === 'asc' ? 1 : -1
      switch (sortField) {
        case 'cpu': return (a.cpu - b.cpu) * dir
        case 'mem': return (a.mem - b.mem) * dir
        case 'rss': return (a.rss - b.rss) * dir
        case 'pid': return (a.pid - b.pid) * dir
        case 'user': return a.user.localeCompare(b.user) * dir
        case 'command': return a.command.localeCompare(b.command) * dir
        default: return 0
      }
    })

  const formatRss = (kb: number) => {
    if (kb >= 1048576) return `${(kb / 1048576).toFixed(1)}G`
    if (kb >= 1024) return `${(kb / 1024).toFixed(1)}M`
    return `${kb}K`
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-6xl mx-4 rounded-2xl border border-border/50 bg-[#0d1117] shadow-2xl animate-in fade-in zoom-in-95 duration-200 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border/30 bg-[#161b22] rounded-t-2xl">
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-[#ff5f57]" />
              <div className="w-3 h-3 rounded-full bg-[#febc2e]" />
              <div className="w-3 h-3 rounded-full bg-[#28c840]" />
            </div>
            <div className="flex items-center gap-2">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-xs text-[#8b949e] font-mono">Processes</span>
              <span className="text-[10px] text-cyan-400 bg-cyan-400/10 px-1.5 py-0.5 rounded font-mono">
                {nodeName}
              </span>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded hover:bg-[#30363d] transition-colors">
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
              placeholder="Filter by user, PID, or command..."
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-[#161b22] border border-border/30 text-xs font-mono text-[#c9d1d9] placeholder:text-[#484f58] focus:outline-none focus:border-cyan-500/40"
            />
          </div>

          {/* Stats */}
          {!loading && (
            <span className="text-[10px] text-[#8b949e] font-mono">
              {sorted.length}{filter ? ` / ${processes.length}` : ''} processes
            </span>
          )}

          {/* Auto-refresh toggle */}
          <button
            onClick={() => setAutoRefresh(a => !a)}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[10px] font-mono transition-colors border ${
              autoRefresh
                ? 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30'
                : 'bg-[#161b22] text-[#484f58] border-border/30 hover:text-[#8b949e]'
            }`}
          >
            <div className={`w-1.5 h-1.5 rounded-full ${autoRefresh ? 'bg-cyan-400 animate-pulse' : 'bg-[#484f58]'}`} />
            Live
          </button>

          {/* Refresh */}
          <button
            onClick={loadProcesses}
            disabled={loading}
            className="p-1.5 rounded-lg hover:bg-[#30363d] transition-colors disabled:opacity-50"
            title="Refresh"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-[#8b949e] ${loading && processes.length === 0 ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {/* Table */}
        <div className="flex-1 overflow-y-auto min-h-0">
          {loading && processes.length === 0 && (
            <div className="flex items-center justify-center gap-2 py-12">
              <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
              <span className="text-xs text-[#484f58]">Loading processes...</span>
            </div>
          )}

          {error && !loading && (
            <div className="flex items-center gap-2 px-4 py-3 m-4 rounded-lg bg-red-500/10 border border-red-500/20">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span className="text-xs text-red-400">{error}</span>
            </div>
          )}

          {(processes.length > 0 || (!loading && !error)) && (
            <table className="w-full text-xs font-mono">
              <thead className="sticky top-0 bg-[#161b22] z-10">
                <tr className="text-[#484f58]">
                  <SortHeader field="pid" label="PID" current={sortField} dir={sortDir} onClick={handleSort} className="w-16 text-right" />
                  <SortHeader field="user" label="USER" current={sortField} dir={sortDir} onClick={handleSort} className="w-20" />
                  <SortHeader field="cpu" label="%CPU" current={sortField} dir={sortDir} onClick={handleSort} className="w-16 text-right" />
                  <SortHeader field="mem" label="%MEM" current={sortField} dir={sortDir} onClick={handleSort} className="w-16 text-right" />
                  <SortHeader field="rss" label="RSS" current={sortField} dir={sortDir} onClick={handleSort} className="w-16 text-right" />
                  <th className="px-3 py-2 text-left text-[10px] font-medium w-12">STAT</th>
                  <SortHeader field="command" label="COMMAND" current={sortField} dir={sortDir} onClick={handleSort} className="text-left" />
                  <th className="w-10" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border/5">
                {sorted.map(proc => {
                  const isExpanded = expanded === proc.pid
                  return (
                    <tr
                      key={`${proc.pid}-${proc.start}`}
                      className={`hover:bg-[#161b22]/50 transition-colors cursor-pointer group ${
                        isExpanded ? 'bg-[#161b22]/70' : ''
                      }`}
                      onClick={() => setExpanded(isExpanded ? null : proc.pid)}
                    >
                      <td className="px-3 py-1.5 text-right text-[#8b949e]">{proc.pid}</td>
                      <td className="px-3 py-1.5 text-[#8b949e] truncate max-w-[80px]">{proc.user}</td>
                      <td className={`px-3 py-1.5 text-right ${
                        proc.cpu >= 50 ? 'text-red-400' :
                        proc.cpu >= 10 ? 'text-amber-400' :
                        proc.cpu > 0 ? 'text-[#c9d1d9]' : 'text-[#484f58]'
                      }`}>
                        {proc.cpu.toFixed(1)}
                      </td>
                      <td className={`px-3 py-1.5 text-right ${
                        proc.mem >= 20 ? 'text-red-400' :
                        proc.mem >= 5 ? 'text-amber-400' :
                        proc.mem > 0 ? 'text-[#c9d1d9]' : 'text-[#484f58]'
                      }`}>
                        {proc.mem.toFixed(1)}
                      </td>
                      <td className="px-3 py-1.5 text-right text-[#8b949e]">{formatRss(proc.rss)}</td>
                      <td className="px-3 py-1.5">
                        <span className={`text-[10px] ${
                          proc.stat.includes('R') ? 'text-emerald-400' :
                          proc.stat.includes('S') ? 'text-[#8b949e]' :
                          proc.stat.includes('Z') ? 'text-red-400' :
                          proc.stat.includes('T') ? 'text-amber-400' :
                          'text-[#484f58]'
                        }`}>
                          {proc.stat}
                        </span>
                      </td>
                      <td className="px-3 py-1.5 text-[#c9d1d9]">
                        <div className={`truncate ${isExpanded ? '' : 'max-w-[500px]'}`}>
                          {isExpanded ? proc.command : proc.command.split(' ')[0].split('/').pop()}
                        </div>
                        {isExpanded && proc.command.includes(' ') && (
                          <div className="text-[10px] text-[#484f58] mt-0.5 break-all whitespace-pre-wrap">
                            {proc.command}
                          </div>
                        )}
                      </td>
                      <td className="px-2 py-1.5" onClick={e => e.stopPropagation()}>
                        <button
                          onClick={() => {
                            setKillConfirm({ pid: proc.pid, command: proc.command.split(' ')[0].split('/').pop() || '', user: proc.user })
                            setKillSignal(15)
                            setKillResult(null)
                          }}
                          className="p-1 rounded opacity-0 group-hover:opacity-100 hover:bg-red-500/10 text-[#484f58] hover:text-red-400 transition-all"
                          title="Send signal"
                        >
                          <Skull className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}

          {!loading && !error && processes.length === 0 && (
            <div className="flex flex-col items-center justify-center py-12 text-[#484f58]">
              <Activity className="w-8 h-8 mb-2 opacity-50" />
              <span className="text-xs">No processes found</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-2.5 border-t border-border/30 bg-[#161b22] rounded-b-2xl">
          <span className="text-[10px] text-[#484f58] font-mono">
            ps aux &middot; {nodeName}
          </span>
          {autoRefresh && (
            <span className="text-[10px] text-cyan-400/60 font-mono">refreshing every 3s</span>
          )}
        </div>
      </div>

      {/* Kill confirmation dialog */}
      {killConfirm && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center">
          <div className="absolute inset-0" onClick={() => { setKillConfirm(null); setKillResult(null) }} />
          <div className="relative w-full max-w-sm mx-4 rounded-xl border border-border/50 bg-[#161b22] shadow-2xl p-5 animate-in fade-in zoom-in-95 duration-150">
            <h4 className="text-sm font-semibold text-[#c9d1d9] mb-1">Send Signal</h4>
            <p className="text-xs text-[#8b949e] mb-4">
              PID <span className="text-[#c9d1d9] font-mono">{killConfirm.pid}</span>
              {' '}&middot;{' '}
              <span className="font-mono">{killConfirm.user}</span>
              {' '}&middot;{' '}
              <span className="font-mono">{killConfirm.command}</span>
            </p>

            <div className="flex gap-2 mb-4">
              {[
                { sig: 15, label: 'SIGTERM', desc: 'Graceful', icon: <Zap className="w-3 h-3" />, color: 'amber' },
                { sig: 9, label: 'SIGKILL', desc: 'Force', icon: <Skull className="w-3 h-3" />, color: 'red' },
                { sig: 1, label: 'SIGHUP', desc: 'Reload', icon: <RotateCw className="w-3 h-3" />, color: 'blue' },
              ].map(s => (
                <button
                  key={s.sig}
                  onClick={() => setKillSignal(s.sig)}
                  className={`flex-1 flex flex-col items-center gap-1 px-3 py-2 rounded-lg border text-xs transition-colors ${
                    killSignal === s.sig
                      ? `bg-${s.color}-500/15 border-${s.color}-500/30 text-${s.color}-400`
                      : 'border-border/30 text-[#484f58] hover:text-[#8b949e]'
                  }`}
                  style={killSignal === s.sig ? {
                    backgroundColor: s.color === 'amber' ? 'rgba(245,158,11,0.15)' : s.color === 'red' ? 'rgba(239,68,68,0.15)' : 'rgba(59,130,246,0.15)',
                    borderColor: s.color === 'amber' ? 'rgba(245,158,11,0.3)' : s.color === 'red' ? 'rgba(239,68,68,0.3)' : 'rgba(59,130,246,0.3)',
                    color: s.color === 'amber' ? 'rgb(251,191,36)' : s.color === 'red' ? 'rgb(248,113,113)' : 'rgb(96,165,250)',
                  } : {}}
                >
                  {s.icon}
                  <span className="font-mono font-medium">{s.label}</span>
                  <span className="text-[10px] opacity-70">{s.desc}</span>
                </button>
              ))}
            </div>

            {killResult && (
              <div className={`text-xs mb-3 px-3 py-2 rounded-lg font-mono ${
                killResult === 'Signal sent' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'
              }`}>
                {killResult}
              </div>
            )}

            <div className="flex justify-end gap-2">
              <button
                onClick={() => { setKillConfirm(null); setKillResult(null) }}
                className="px-3 py-1.5 rounded-lg text-xs text-[#8b949e] hover:bg-[#30363d] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleKill}
                disabled={killing !== null}
                className="px-3 py-1.5 rounded-lg text-xs bg-red-600 text-white hover:bg-red-700 transition-colors font-medium disabled:opacity-50 flex items-center gap-1.5"
              >
                {killing !== null ? <Loader2 className="w-3 h-3 animate-spin" /> : <Skull className="w-3 h-3" />}
                Send
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function SortHeader({
  field,
  label,
  current,
  dir,
  onClick,
  className = '',
}: {
  field: SortField
  label: string
  current: SortField
  dir: SortDir
  onClick: (field: SortField) => void
  className?: string
}) {
  const isActive = current === field
  return (
    <th
      className={`px-3 py-2 text-[10px] font-medium cursor-pointer select-none hover:text-[#8b949e] transition-colors ${
        isActive ? 'text-cyan-400' : ''
      } ${className}`}
      onClick={() => onClick(field)}
    >
      <span className="inline-flex items-center gap-0.5">
        {label}
        {isActive && (dir === 'desc' ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />)}
      </span>
    </th>
  )
}
