import { useState, useEffect, useCallback, useRef } from "react"
import { fetchServiceList, fetchServiceStatus, runServiceAction, parseServiceList } from "@/lib/api"
import type { ServiceScope, ServiceAction, ServiceInfo } from "@/lib/api"
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
  Cog,
  CheckCircle2,
  XCircle,
  MinusCircle,
} from "lucide-react"

interface ServiceManagerProps {
  nodeId: string
  nodeName: string
  onClose: () => void
}

export function ServiceManager({ nodeId, nodeName, onClose }: ServiceManagerProps) {
  const [scope, setScope] = useState<ServiceScope>('system')
  const [services, setServices] = useState<ServiceInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState("")
  const [expandedService, setExpandedService] = useState<string | null>(null)
  const [statusOutput, setStatusOutput] = useState<string | null>(null)
  const [statusLoading, setStatusLoading] = useState(false)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const statusRef = useRef<HTMLPreElement | null>(null)

  const loadServices = useCallback(async () => {
    setLoading(true)
    setError(null)
    setExpandedService(null)
    setStatusOutput(null)

    try {
      const result = await fetchServiceList(nodeId, scope)
      if (result.ok) {
        setServices(parseServiceList(result.output))
      } else {
        setError(result.output || "Failed to list services")
        setServices([])
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch services")
      setServices([])
    } finally {
      setLoading(false)
    }
  }, [nodeId, scope])

  useEffect(() => {
    loadServices()
  }, [loadServices])

  const handleExpand = async (serviceName: string) => {
    if (expandedService === serviceName) {
      setExpandedService(null)
      setStatusOutput(null)
      return
    }

    setExpandedService(serviceName)
    setStatusLoading(true)
    setStatusOutput(null)

    try {
      const result = await fetchServiceStatus(nodeId, serviceName, scope)
      setStatusOutput(result.output || "(no output)")
    } catch {
      setStatusOutput("Failed to fetch status")
    } finally {
      setStatusLoading(false)
    }
  }

  useEffect(() => {
    if (statusRef.current) {
      statusRef.current.scrollTop = 0
    }
  }, [statusOutput])

  const handleAction = async (serviceName: string, action: ServiceAction) => {
    setActionLoading(`${serviceName}:${action}`)
    try {
      await runServiceAction(nodeId, serviceName, action, scope)
      // Refresh the status if this service is expanded
      if (expandedService === serviceName) {
        setStatusLoading(true)
        try {
          const result = await fetchServiceStatus(nodeId, serviceName, scope)
          setStatusOutput(result.output || "(no output)")
        } catch {
          setStatusOutput("Failed to refresh status")
        } finally {
          setStatusLoading(false)
        }
      }
      // Refresh the list to show updated states
      await loadServices()
      // Re-expand the service we just acted on
      if (expandedService === serviceName) {
        setExpandedService(serviceName)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed")
    } finally {
      setActionLoading(null)
    }
  }

  const filtered = services.filter(s =>
    s.name.toLowerCase().includes(filter.toLowerCase()) ||
    s.description.toLowerCase().includes(filter.toLowerCase())
  )

  const activeCount = services.filter(s => s.active === 'active').length
  const failedCount = services.filter(s => s.active === 'failed').length

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
              <Cog className="w-3.5 h-3.5 text-violet-400" />
              <span className="text-xs text-[#8b949e] font-mono">Services</span>
              <span className="text-[10px] text-violet-400 bg-violet-400/10 px-1.5 py-0.5 rounded font-mono">
                {nodeName}
              </span>
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
          {/* Scope toggle */}
          <div className="flex rounded-lg border border-border/30 overflow-hidden">
            <button
              onClick={() => setScope('system')}
              className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                scope === 'system'
                  ? 'bg-violet-500/20 text-violet-300 border-r border-border/30'
                  : 'bg-[#161b22] text-[#484f58] hover:text-[#8b949e] border-r border-border/30'
              }`}
            >
              System
            </button>
            <button
              onClick={() => setScope('user')}
              className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                scope === 'user'
                  ? 'bg-violet-500/20 text-violet-300'
                  : 'bg-[#161b22] text-[#484f58] hover:text-[#8b949e]'
              }`}
            >
              User
            </button>
          </div>

          {/* Search */}
          <div className="flex-1 relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-[#484f58]" />
            <input
              type="text"
              value={filter}
              onChange={e => setFilter(e.target.value)}
              placeholder="Filter services..."
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-[#161b22] border border-border/30 text-xs font-mono text-[#c9d1d9] placeholder:text-[#484f58] focus:outline-none focus:border-violet-500/40"
            />
          </div>

          {/* Stats */}
          {!loading && (
            <div className="flex items-center gap-3 text-[10px] font-mono">
              <span className="text-[#8b949e]">{services.length} total</span>
              <span className="text-emerald-400">{activeCount} active</span>
              {failedCount > 0 && <span className="text-red-400">{failedCount} failed</span>}
            </div>
          )}

          {/* Refresh */}
          <button
            onClick={loadServices}
            disabled={loading}
            className="p-1.5 rounded-lg hover:bg-[#30363d] transition-colors disabled:opacity-50"
            title="Refresh"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-[#8b949e] ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto min-h-0">
          {loading && (
            <div className="flex items-center justify-center gap-2 py-12">
              <Loader2 className="w-4 h-4 text-violet-400 animate-spin" />
              <span className="text-xs text-[#484f58]">Loading {scope} services...</span>
            </div>
          )}

          {error && !loading && (
            <div className="flex items-center gap-2 px-4 py-3 m-4 rounded-lg bg-red-500/10 border border-red-500/20">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span className="text-xs text-red-400">{error}</span>
            </div>
          )}

          {!loading && !error && filtered.length === 0 && (
            <div className="flex flex-col items-center justify-center py-12 text-[#484f58]">
              <Cog className="w-8 h-8 mb-2 opacity-50" />
              <span className="text-xs">
                {filter ? 'No services match your filter' : 'No services found'}
              </span>
            </div>
          )}

          {!loading && !error && filtered.length > 0 && (
            <div className="divide-y divide-border/10">
              {filtered.map(svc => {
                const isExpanded = expandedService === svc.name
                return (
                  <div key={svc.name}>
                    <div
                      className={`flex items-center gap-2 px-4 py-2 hover:bg-[#161b22]/50 transition-colors cursor-pointer ${
                        isExpanded ? 'bg-[#161b22]/70' : ''
                      }`}
                      onClick={() => handleExpand(svc.name)}
                    >
                      {isExpanded
                        ? <ChevronDown className="w-3 h-3 text-[#484f58] shrink-0" />
                        : <ChevronRight className="w-3 h-3 text-[#484f58] shrink-0" />
                      }

                      {/* State icon */}
                      <ServiceStateIcon active={svc.active} sub={svc.sub} />

                      {/* Name */}
                      <span className="text-xs font-mono text-[#c9d1d9] min-w-0 truncate flex-1">
                        {svc.name}
                      </span>

                      {/* Sub state */}
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        svc.sub === 'running' ? 'bg-emerald-500/10 text-emerald-400' :
                        svc.sub === 'exited' ? 'bg-[#30363d] text-[#8b949e]' :
                        svc.sub === 'failed' ? 'bg-red-500/10 text-red-400' :
                        svc.sub === 'dead' ? 'bg-[#30363d] text-[#484f58]' :
                        'bg-[#30363d] text-[#8b949e]'
                      }`}>
                        {svc.sub}
                      </span>

                      {/* Description */}
                      <span className="text-[10px] text-[#484f58] max-w-[200px] truncate hidden sm:inline">
                        {svc.description}
                      </span>

                      {/* Action buttons */}
                      <div className="flex items-center gap-0.5 ml-2 shrink-0" onClick={e => e.stopPropagation()}>
                        {svc.sub !== 'running' && (
                          <ActionButton
                            icon={<Play className="w-3 h-3" />}
                            title="Start"
                            color="text-emerald-400 hover:bg-emerald-400/10"
                            loading={actionLoading === `${svc.name}:start`}
                            onClick={() => handleAction(svc.name, 'start')}
                          />
                        )}
                        {svc.sub === 'running' && (
                          <ActionButton
                            icon={<Square className="w-3 h-3" />}
                            title="Stop"
                            color="text-red-400 hover:bg-red-400/10"
                            loading={actionLoading === `${svc.name}:stop`}
                            onClick={() => handleAction(svc.name, 'stop')}
                          />
                        )}
                        <ActionButton
                          icon={<RotateCw className="w-3 h-3" />}
                          title="Restart"
                          color="text-amber-400 hover:bg-amber-400/10"
                          loading={actionLoading === `${svc.name}:restart`}
                          onClick={() => handleAction(svc.name, 'restart')}
                        />
                      </div>
                    </div>

                    {/* Expanded status */}
                    {isExpanded && (
                      <div className="px-4 pb-3 bg-[#0d1117]">
                        <div className="rounded-lg border border-border/20 overflow-hidden">
                          {/* Status actions bar */}
                          <div className="flex items-center gap-1 px-3 py-1.5 bg-[#161b22] border-b border-border/20">
                            <span className="text-[10px] text-[#484f58] font-mono flex-1">systemctl status</span>
                            <ActionButton
                              icon={<Play className="w-3 h-3" />}
                              title="Enable"
                              color="text-blue-400 hover:bg-blue-400/10"
                              loading={actionLoading === `${svc.name}:enable`}
                              onClick={() => handleAction(svc.name, 'enable')}
                              label="Enable"
                            />
                            <ActionButton
                              icon={<MinusCircle className="w-3 h-3" />}
                              title="Disable"
                              color="text-[#8b949e] hover:bg-[#30363d]"
                              loading={actionLoading === `${svc.name}:disable`}
                              onClick={() => handleAction(svc.name, 'disable')}
                              label="Disable"
                            />
                          </div>
                          {statusLoading ? (
                            <div className="flex items-center gap-2 px-3 py-4">
                              <Loader2 className="w-3 h-3 text-violet-400 animate-spin" />
                              <span className="text-[10px] text-[#484f58]">Loading status...</span>
                            </div>
                          ) : (
                            <pre
                              ref={statusRef}
                              className="px-3 py-2 text-[11px] font-mono text-[#8b949e] whitespace-pre-wrap break-all overflow-y-auto max-h-64"
                            >
                              {statusOutput || ''}
                            </pre>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-2.5 border-t border-border/30 bg-[#161b22] rounded-b-2xl">
          <span className="text-[10px] text-[#484f58] font-mono">
            {scope === 'system' ? 'systemctl' : 'systemctl --user'} &middot; {nodeName}
          </span>
          {filter && (
            <span className="text-[10px] text-[#484f58]">
              {filtered.length} / {services.length} shown
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

function ServiceStateIcon({ active, sub }: { active: string; sub: string }) {
  if (active === 'active' && sub === 'running') {
    return <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
  }
  if (active === 'failed') {
    return <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
  }
  if (active === 'active') {
    return <CheckCircle2 className="w-3.5 h-3.5 text-[#8b949e] shrink-0" />
  }
  return <MinusCircle className="w-3.5 h-3.5 text-[#484f58] shrink-0" />
}

function ActionButton({
  icon,
  title,
  color,
  loading,
  onClick,
  label,
}: {
  icon: React.ReactNode
  title: string
  color: string
  loading: boolean
  onClick: () => void
  label?: string
}) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      className={`flex items-center gap-1 p-1 rounded transition-colors ${color} disabled:opacity-50`}
      title={title}
    >
      {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : icon}
      {label && <span className="text-[10px]">{label}</span>}
    </button>
  )
}
