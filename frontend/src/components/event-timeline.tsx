import { useState, useEffect, useRef, useCallback } from "react"
import { fetchEvents } from "@/lib/api"
import type { TimelineEvent, NodeStatus } from "@/lib/api"
import {
  X,
  Activity,
  Wifi,
  WifiOff,
  Rocket,
  Zap,
  Terminal,
  Cog,
  GitBranch,
  Shield,
  Plus,
  Minus,
  Crosshair,
  Loader2,
  ChevronDown,
} from "lucide-react"

interface EventTimelineProps {
  onClose: () => void
  nodeId?: string
  nodes?: NodeStatus[]
}

const EVENT_TYPES = [
  { value: 'all', label: 'All Events' },
  { value: 'node.connected', label: 'Connected' },
  { value: 'node.disconnected', label: 'Disconnected' },
  { value: 'node.added', label: 'Node Added' },
  { value: 'node.removed', label: 'Node Removed' },
  { value: 'deploy.started', label: 'Deploy' },
  { value: 'fleet.command', label: 'Fleet Command' },
  { value: 'ansible.run', label: 'Ansible' },
  { value: 'service.action', label: 'Service' },
  { value: 'process.signal', label: 'Process' },
  { value: 'drift.snapshot', label: 'Drift' },
  { value: 'security.scan', label: 'Security' },
]

function getEventIcon(type: string) {
  switch (type) {
    case 'node.connected': return <Wifi className="w-3.5 h-3.5" />
    case 'node.disconnected': return <WifiOff className="w-3.5 h-3.5" />
    case 'node.added': return <Plus className="w-3.5 h-3.5" />
    case 'node.removed': return <Minus className="w-3.5 h-3.5" />
    case 'deploy.started': return <Rocket className="w-3.5 h-3.5" />
    case 'fleet.command': return <Zap className="w-3.5 h-3.5" />
    case 'ansible.run': return <Terminal className="w-3.5 h-3.5" />
    case 'service.action': return <Cog className="w-3.5 h-3.5" />
    case 'process.signal': return <Crosshair className="w-3.5 h-3.5" />
    case 'drift.snapshot': return <GitBranch className="w-3.5 h-3.5" />
    case 'security.scan': return <Shield className="w-3.5 h-3.5" />
    default: return <Activity className="w-3.5 h-3.5" />
  }
}

function getEventColor(type: string) {
  switch (type) {
    case 'node.connected': return 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20'
    case 'node.disconnected': return 'text-red-400 bg-red-400/10 border-red-400/20'
    case 'node.added': return 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20'
    case 'node.removed': return 'text-red-400 bg-red-400/10 border-red-400/20'
    case 'deploy.started': return 'text-orange-400 bg-orange-400/10 border-orange-400/20'
    case 'fleet.command': return 'text-blue-400 bg-blue-400/10 border-blue-400/20'
    case 'ansible.run': return 'text-blue-400 bg-blue-400/10 border-blue-400/20'
    case 'service.action': return 'text-violet-400 bg-violet-400/10 border-violet-400/20'
    case 'process.signal': return 'text-cyan-400 bg-cyan-400/10 border-cyan-400/20'
    case 'drift.snapshot': return 'text-amber-400 bg-amber-400/10 border-amber-400/20'
    case 'security.scan': return 'text-red-400 bg-red-400/10 border-red-400/20'
    default: return 'text-muted-foreground bg-muted/10 border-border/20'
  }
}

function getTypeBadgeColor(type: string) {
  switch (type) {
    case 'node.connected':
    case 'node.added':
      return 'bg-emerald-400/10 text-emerald-400 border-emerald-400/30'
    case 'node.disconnected':
    case 'node.removed':
      return 'bg-red-400/10 text-red-400 border-red-400/30'
    case 'deploy.started':
      return 'bg-orange-400/10 text-orange-400 border-orange-400/30'
    case 'fleet.command':
    case 'ansible.run':
      return 'bg-blue-400/10 text-blue-400 border-blue-400/30'
    case 'service.action':
      return 'bg-violet-400/10 text-violet-400 border-violet-400/30'
    case 'process.signal':
      return 'bg-cyan-400/10 text-cyan-400 border-cyan-400/30'
    case 'drift.snapshot':
      return 'bg-amber-400/10 text-amber-400 border-amber-400/30'
    case 'security.scan':
      return 'bg-red-400/10 text-red-400 border-red-400/30'
    default:
      return 'bg-muted/10 text-muted-foreground border-border/30'
  }
}

function typeLabel(type: string): string {
  return EVENT_TYPES.find(t => t.value === type)?.label ?? type
}

function timeAgo(ts: number): string {
  const now = Math.floor(Date.now() / 1000)
  const diff = now - ts
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export function EventTimeline({ onClose, nodeId, nodes }: EventTimelineProps) {
  const [events, setEvents] = useState<TimelineEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [typeFilter, setTypeFilter] = useState('all')
  const [hasMore, setHasMore] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const nodeNameMap = useRef<Record<string, string>>({})
  if (nodes) {
    for (const n of nodes) {
      nodeNameMap.current[n.agent_id] = n.name
    }
  }

  const loadEvents = useCallback(async (before?: number) => {
    const params: Parameters<typeof fetchEvents>[0] = { limit: 50 }
    if (nodeId) params.node_id = nodeId
    if (typeFilter !== 'all') params.type = typeFilter
    if (before) params.before = before
    return fetchEvents(params)
  }, [nodeId, typeFilter])

  // Initial load & filter changes
  useEffect(() => {
    setLoading(true)
    setEvents([])
    setHasMore(true)
    loadEvents().then(data => {
      setEvents(data)
      setHasMore(data.length >= 50)
      setLoading(false)
    })
  }, [loadEvents])

  // Auto-refresh: poll for new events every 10s
  useEffect(() => {
    pollRef.current = setInterval(async () => {
      if (events.length === 0) return
      const params: Parameters<typeof fetchEvents>[0] = { limit: 50 }
      if (nodeId) params.node_id = nodeId
      if (typeFilter !== 'all') params.type = typeFilter
      const fresh = await fetchEvents(params)
      if (fresh.length > 0 && fresh[0].id > events[0].id) {
        // Prepend new events
        const newIds = new Set(events.map(e => e.id))
        const newEvents = fresh.filter(e => !newIds.has(e.id))
        setEvents(prev => [...newEvents, ...prev])
      }
    }, 10_000)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [events, nodeId, typeFilter])

  const handleLoadMore = async () => {
    if (!hasMore || loadingMore) return
    setLoadingMore(true)
    const lastId = events[events.length - 1]?.id
    const more = await loadEvents(lastId)
    setEvents(prev => [...prev, ...more])
    setHasMore(more.length >= 50)
    setLoadingMore(false)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-2xl max-h-[85vh] mx-4 flex flex-col rounded-2xl border border-border/50 bg-[#0d1117] shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border/30">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500/80" />
              <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
              <div className="w-3 h-3 rounded-full bg-green-500/80" />
            </div>
            <div className="flex items-center gap-2 text-sm font-medium">
              <Activity className="w-4 h-4 text-amber-400" />
              {nodeId ? 'Node Timeline' : 'Event Timeline'}
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-muted transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3 px-6 py-3 border-b border-border/20">
          <div className="relative">
            <select
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value)}
              className="appearance-none bg-card/50 border border-border/50 rounded-lg px-3 py-1.5 pr-8 text-xs font-medium focus:outline-none focus:border-primary/50 cursor-pointer"
            >
              {EVENT_TYPES.map(t => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground pointer-events-none" />
          </div>
          <span className="text-[10px] text-muted-foreground">
            {events.length} event{events.length !== 1 ? 's' : ''}
          </span>
        </div>

        {/* Events List */}
        <div className="flex-1 overflow-y-auto px-6 py-3 space-y-1">
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
            </div>
          ) : events.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <Activity className="w-8 h-8 text-muted-foreground/30 mb-3" />
              <p className="text-sm text-muted-foreground">No events recorded yet</p>
              <p className="text-xs text-muted-foreground/60 mt-1">Events will appear here as actions occur</p>
            </div>
          ) : (
            <>
              {events.map(event => (
                <div
                  key={event.id}
                  className="flex items-start gap-3 py-2.5 px-3 rounded-lg hover:bg-card/30 transition-colors group"
                >
                  {/* Icon */}
                  <div className={`mt-0.5 p-1.5 rounded-lg border ${getEventColor(event.event_type)}`}>
                    {getEventIcon(event.event_type)}
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm leading-snug">{event.message}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border ${getTypeBadgeColor(event.event_type)}`}>
                        {typeLabel(event.event_type)}
                      </span>
                      {event.node_id && !nodeId && (
                        <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-card/50 border border-border/30 text-[10px] font-mono text-muted-foreground">
                          {nodeNameMap.current[event.node_id] || event.node_id}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Time */}
                  <span className="text-[10px] text-muted-foreground whitespace-nowrap mt-1 opacity-60 group-hover:opacity-100 transition-opacity">
                    {timeAgo(event.created_at)}
                  </span>
                </div>
              ))}

              {/* Load More */}
              {hasMore && (
                <div className="flex justify-center py-4">
                  <button
                    onClick={handleLoadMore}
                    disabled={loadingMore}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg border border-border/50 bg-card/30 text-xs font-medium hover:bg-card/50 transition-colors disabled:opacity-50"
                  >
                    {loadingMore ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : null}
                    {loadingMore ? 'Loading...' : 'Load more'}
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
