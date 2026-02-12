import { useState, useEffect, useRef, useCallback } from "react"
import { fleetRun, fleetPoll } from "@/lib/api"
import type { NodeStatus, FleetNodeResult } from "@/lib/api"
import { X, Loader2, Check, AlertCircle, Play, Zap, RotateCw, Shield, ChevronDown, ChevronRight } from "lucide-react"

interface FleetCommandModalProps {
  nodes: NodeStatus[]
  onClose: () => void
}

type Phase = 'ready' | 'running' | 'done' | 'error'

const HISTORY_KEY = 'stardust-fleet-history'
const MAX_HISTORY = 10

function getHistory(): string[] {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]')
  } catch {
    return []
  }
}

function saveHistory(cmd: string) {
  const history = getHistory().filter(h => h !== cmd)
  history.unshift(cmd)
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, MAX_HISTORY)))
}

export function FleetCommandModal({ nodes, onClose }: FleetCommandModalProps) {
  const [phase, setPhase] = useState<Phase>('ready')
  const [command, setCommand] = useState("")
  const [sudo, setSudo] = useState(false)
  const [selectedNodes, setSelectedNodes] = useState<Set<string>>(
    new Set(nodes.filter(n => n.connected).map(n => n.agent_id))
  )
  const [activeTags, setActiveTags] = useState<Set<string>>(new Set())
  const [nodeOutputs, setNodeOutputs] = useState<Record<string, FleetNodeResult>>({})
  const [error, setError] = useState<string | null>(null)
  const [showHistory, setShowHistory] = useState(false)
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set())
  const jobRef = useRef<{ id: string; offsets: Record<string, number> } | null>(null)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const outputRefs = useRef<Record<string, HTMLPreElement | null>>({})
  const history = getHistory()

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [])

  // Auto-scroll all output panes
  useEffect(() => {
    for (const ref of Object.values(outputRefs.current)) {
      if (ref) ref.scrollTop = ref.scrollHeight
    }
  }, [nodeOutputs])

  const poll = useCallback(async () => {
    const job = jobRef.current
    if (!job) return

    try {
      const res = await fleetPoll(job.id, job.offsets)

      setNodeOutputs(prev => {
        const next = { ...prev }
        for (const [nodeId, result] of Object.entries(res.nodes)) {
          const existing = next[nodeId]
          next[nodeId] = {
            ...result,
            output: (existing?.output || '') + result.output,
          }
          job.offsets[nodeId] = result.offset
        }
        return next
      })

      if (res.all_done) {
        if (pollingRef.current) {
          clearInterval(pollingRef.current)
          pollingRef.current = null
        }
        jobRef.current = null

        // Check if any node failed
        const anyFailed = Object.values(res.nodes).some(n => n.done && !n.ok)
        setPhase(anyFailed ? 'error' : 'done')
        if (anyFailed) setError("Some nodes reported errors")
      }
    } catch {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
      jobRef.current = null
      setError("Polling failed")
      setPhase('error')
    }
  }, [])

  const handleRun = async () => {
    if (!command.trim() || selectedNodes.size === 0) return

    setPhase('running')
    setNodeOutputs({})
    setError(null)
    setExpandedNodes(new Set(selectedNodes))
    saveHistory(command.trim())

    try {
      const jobId = await fleetRun(command.trim(), Array.from(selectedNodes), sudo)
      const offsets: Record<string, number> = {}
      for (const nodeId of selectedNodes) offsets[nodeId] = 0
      jobRef.current = { id: jobId, offsets }
      pollingRef.current = setInterval(poll, 300)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start fleet command')
      setPhase('error')
    }
  }

  const handleReset = () => {
    setPhase('ready')
    setNodeOutputs({})
    setError(null)
  }

  const toggleNode = (id: string) => {
    setSelectedNodes(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const connectedNodes = nodes.filter(n => n.connected)
  const toggleAll = () => {
    if (selectedNodes.size === connectedNodes.length) {
      setSelectedNodes(new Set())
      setActiveTags(new Set())
    } else {
      setSelectedNodes(new Set(connectedNodes.map(n => n.agent_id)))
      setActiveTags(new Set())
    }
  }

  const toggleExpanded = (id: string) => {
    setExpandedNodes(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const isRunning = phase === 'running'
  const showEditor = phase === 'ready'
  const showOutput = phase !== 'ready'

  const nodeNameMap: Record<string, string> = {}
  for (const n of nodes) nodeNameMap[n.agent_id] = n.name

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={!isRunning ? onClose : undefined} />
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
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <span className="text-xs text-[#8b949e] font-mono">Fleet Command</span>
              <span className="text-[10px] text-amber-400 bg-amber-400/10 px-1.5 py-0.5 rounded font-mono">
                {selectedNodes.size} node{selectedNodes.size !== 1 ? 's' : ''}
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={isRunning}
            className="p-1 rounded hover:bg-[#30363d] transition-colors disabled:opacity-50"
          >
            <X className="w-4 h-4 text-[#8b949e]" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto min-h-0">
          {showEditor && (
            <div className="p-4 space-y-4">
              {/* Command input */}
              <div className="relative">
                <input
                  type="text"
                  value={command}
                  onChange={e => { setCommand(e.target.value); setShowHistory(false) }}
                  onKeyDown={e => {
                    if (e.key === 'Enter' && command.trim() && selectedNodes.size > 0) handleRun()
                  }}
                  onFocus={() => { if (history.length > 0 && !command) setShowHistory(true) }}
                  onBlur={() => setTimeout(() => setShowHistory(false), 150)}
                  placeholder="Enter command (e.g. uptime, df -h, free -m)"
                  className="w-full px-3 py-2.5 rounded-lg bg-[#161b22] border border-border/30 text-sm font-mono text-[#c9d1d9] placeholder:text-[#484f58] focus:outline-none focus:border-[#58a6ff]/50"
                  autoFocus
                />
                {showHistory && history.length > 0 && (
                  <div className="absolute top-full left-0 right-0 mt-1 rounded-lg bg-[#161b22] border border-border/30 shadow-lg z-10 overflow-hidden">
                    {history.map((cmd, i) => (
                      <button
                        key={i}
                        onMouseDown={() => { setCommand(cmd); setShowHistory(false) }}
                        className="w-full px-3 py-2 text-left text-xs font-mono text-[#8b949e] hover:bg-[#30363d] hover:text-[#c9d1d9] transition-colors"
                      >
                        {cmd}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Sudo toggle */}
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={sudo}
                  onChange={e => setSudo(e.target.checked)}
                  className="rounded border-border/50"
                />
                <Shield className="w-3.5 h-3.5 text-amber-400" />
                <span className="text-xs text-[#8b949e]">Run with sudo</span>
              </label>

              {/* Node selection */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-[#8b949e] font-medium">Target Nodes</span>
                  <button
                    onClick={toggleAll}
                    className="text-[10px] text-[#58a6ff] hover:text-[#79c0ff] transition-colors"
                  >
                    {selectedNodes.size === connectedNodes.length ? 'Deselect all' : 'Select all'}
                  </button>
                </div>
                {/* Tag quick-select */}
                {(() => {
                  const tagSet = new Set<string>()
                  for (const n of connectedNodes) for (const t of n.tags ?? []) tagSet.add(t)
                  const tags = [...tagSet].sort()
                  if (tags.length === 0) return null
                  return (
                    <div className="flex flex-wrap gap-1.5 mb-2">
                      {tags.map(tag => {
                        const tagNodes = connectedNodes.filter(n => n.tags?.includes(tag))
                        const active = activeTags.has(tag)
                        return (
                          <button
                            key={tag}
                            onClick={() => {
                              const nextTags = new Set(activeTags)
                              if (active) {
                                nextTags.delete(tag)
                                setActiveTags(nextTags)
                                // Deselect nodes with this tag
                                setSelectedNodes(prev => {
                                  const next = new Set(prev)
                                  for (const n of tagNodes) next.delete(n.agent_id)
                                  return next
                                })
                              } else {
                                nextTags.add(tag)
                                setActiveTags(nextTags)
                                // Select nodes matching any active tag, deselect those that don't
                                const next = new Set<string>()
                                for (const n of connectedNodes) {
                                  if (n.tags?.some(t => nextTags.has(t))) next.add(n.agent_id)
                                }
                                setSelectedNodes(next)
                              }
                            }}
                            className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors border ${
                              active
                                ? 'bg-amber-400/15 border-amber-400/30 text-amber-300'
                                : 'bg-[#161b22] border-border/20 text-[#484f58] hover:text-[#8b949e]'
                            }`}
                          >
                            {tag} ({tagNodes.length})
                          </button>
                        )
                      })}
                    </div>
                  )
                })()}
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
                  {connectedNodes.map(node => (
                    <button
                      key={node.agent_id}
                      onClick={() => toggleNode(node.agent_id)}
                      className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-xs font-mono transition-colors border ${
                        selectedNodes.has(node.agent_id)
                          ? 'border-amber-400/30 bg-amber-400/10 text-amber-300'
                          : 'border-border/20 bg-[#161b22] text-[#484f58] hover:text-[#8b949e]'
                      }`}
                    >
                      <div className={`w-1.5 h-1.5 rounded-full ${
                        selectedNodes.has(node.agent_id) ? 'bg-amber-400' : 'bg-[#30363d]'
                      }`} />
                      <span className="truncate">{node.name}</span>
                    </button>
                  ))}
                </div>
                {connectedNodes.length === 0 && (
                  <p className="text-xs text-[#484f58] italic">No connected nodes</p>
                )}
              </div>
            </div>
          )}

          {showOutput && (
            <div className="p-4 space-y-2">
              {/* Command display */}
              <div className="flex items-center gap-2 mb-3">
                <span className="text-[10px] text-[#484f58] font-mono">$</span>
                <span className="text-xs font-mono text-[#c9d1d9]">
                  {sudo && <span className="text-amber-400">sudo </span>}
                  {command}
                </span>
              </div>

              {/* Per-node output panels */}
              {Object.entries(nodeOutputs).map(([nodeId, result]) => {
                const isExpanded = expandedNodes.has(nodeId)
                const name = result.name || nodeNameMap[nodeId] || nodeId.slice(0, 12)
                return (
                  <div key={nodeId} className="rounded-lg border border-border/20 overflow-hidden">
                    <button
                      onClick={() => toggleExpanded(nodeId)}
                      className="w-full flex items-center gap-2 px-3 py-2 bg-[#161b22] hover:bg-[#1c2128] transition-colors"
                    >
                      {isExpanded
                        ? <ChevronDown className="w-3 h-3 text-[#484f58]" />
                        : <ChevronRight className="w-3 h-3 text-[#484f58]" />
                      }
                      <span className="text-xs font-mono text-[#c9d1d9] flex-1 text-left truncate">{name}</span>
                      {!result.done && (
                        <Loader2 className="w-3 h-3 text-amber-400 animate-spin" />
                      )}
                      {result.done && result.ok && (
                        <Check className="w-3 h-3 text-emerald-400" />
                      )}
                      {result.done && !result.ok && (
                        <AlertCircle className="w-3 h-3 text-red-400" />
                      )}
                    </button>
                    {isExpanded && (
                      <pre
                        ref={el => { outputRefs.current[nodeId] = el }}
                        className="px-3 py-2 text-[11px] font-mono text-[#8b949e] bg-[#0d1117] whitespace-pre-wrap break-all overflow-y-auto max-h-48"
                      >
                        {result.output || (result.done ? '(no output)' : 'Waiting...')}
                      </pre>
                    )}
                  </div>
                )
              })}

              {/* Empty state during running before first poll */}
              {isRunning && Object.keys(nodeOutputs).length === 0 && (
                <div className="flex items-center justify-center gap-2 py-8">
                  <Loader2 className="w-4 h-4 text-amber-400 animate-spin" />
                  <span className="text-xs text-[#484f58]">Executing across fleet...</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-border/30 bg-[#161b22] rounded-b-2xl">
          <div className="flex items-center gap-2">
            {error && (
              <span className="text-[10px] text-red-400 flex items-center gap-1">
                <AlertCircle className="w-3 h-3" /> {error}
              </span>
            )}
            {phase === 'done' && !error && (
              <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                <Check className="w-3 h-3" /> All nodes completed
              </span>
            )}
            {isRunning && (
              <span className="text-[10px] text-amber-400 flex items-center gap-1">
                <Loader2 className="w-3 h-3 animate-spin" /> Running...
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {(phase === 'done' || phase === 'error') && (
              <button
                onClick={handleReset}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-[#30363d] text-[#c9d1d9] hover:bg-[#484f58] transition-colors"
              >
                <RotateCw className="w-3 h-3" />
                New Command
              </button>
            )}
            {showEditor && (
              <button
                onClick={handleRun}
                disabled={!command.trim() || selectedNodes.size === 0}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-medium bg-amber-500 text-black hover:bg-amber-400 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <Play className="w-3 h-3" />
                Run
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
