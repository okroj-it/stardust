import { useState, useEffect, useCallback } from "react"
import {
  driftSnapshot,
  driftListSnapshots,
  driftGetSnapshot,
  driftSetBaseline,
  driftDiff,
  driftDeleteSnapshot,
  fleetRun,
  fleetPoll,
} from "@/lib/api"
import type {
  NodeStatus,
  DriftSnapshotSummary,
  DriftSnapshot,
  DriftDiffResult,
  DriftCategoryDiff,
} from "@/lib/api"
import {
  X,
  Loader2,
  Camera,
  Shield,
  GitCompare,
  Package,
  Server,
  Wifi,
  Users,
  Trash2,
  Star,
  ChevronDown,
  ChevronRight,
  Plus,
  Minus,
  ArrowRight,
  Search,
  Download,
  Check,
} from "lucide-react"

interface DriftModalProps {
  nodes: NodeStatus[]
  onClose: () => void
}

type Phase = 'ready' | 'snapshotting' | 'viewing' | 'diffing'
type Tab = 'packages' | 'services' | 'ports' | 'users'

const TAB_CONFIG = {
  packages: { label: 'Packages', icon: Package },
  services: { label: 'Services', icon: Server },
  ports: { label: 'Ports', icon: Wifi },
  users: { label: 'Users', icon: Users },
} as const

export function DriftModal({ nodes, onClose }: DriftModalProps) {
  const [phase, setPhase] = useState<Phase>('ready')
  const [selectedNodes, setSelectedNodes] = useState<Set<string>>(
    new Set(nodes.filter(n => n.connected).map(n => n.agent_id))
  )
  const [error, setError] = useState<string | null>(null)

  // Snapshot state
  const [snapshots, setSnapshots] = useState<DriftSnapshotSummary[]>([])
  const [viewingSnapshot, setViewingSnapshot] = useState<DriftSnapshot | null>(null)
  const [activeTab, setActiveTab] = useState<Tab>('packages')

  // History state
  const [historyNode, setHistoryNode] = useState<string | null>(null)
  const [history, setHistory] = useState<DriftSnapshotSummary[]>([])
  const [showHistory, setShowHistory] = useState(false)

  // Diff state
  const [diffResult, setDiffResult] = useState<DriftDiffResult | null>(null)
  const [diffMode, setDiffMode] = useState<'compare' | 'baseline' | null>(null)

  // Browse mode: load existing snapshots without taking a new one
  const [browseNode, setBrowseNode] = useState<string | null>(null)

  const connectedNodes = nodes.filter(n => n.connected)
  const nodeNameMap = Object.fromEntries(nodes.map(n => [n.agent_id, n.name]))

  const toggleNode = (id: string) => {
    setSelectedNodes(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const selectAll = () => setSelectedNodes(new Set(connectedNodes.map(n => n.agent_id)))
  const selectNone = () => setSelectedNodes(new Set())

  // Browse existing snapshots for a node
  const handleBrowse = useCallback(async (nodeId: string) => {
    setError(null)
    setBrowseNode(nodeId)
    try {
      const r = await driftListSnapshots(nodeId)
      if (r.snapshots.length === 0) {
        setError(`No snapshots found for ${nodeNameMap[nodeId] || nodeId.slice(0, 8)}`)
        return
      }
      setHistory(r.snapshots)
      setHistoryNode(nodeId)
      setSnapshots([]) // clear "current batch" since we're browsing
      // Load the latest snapshot
      const latest = r.snapshots[0]
      const full = await driftGetSnapshot(latest.id)
      setViewingSnapshot(full)
      setPhase('viewing')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load snapshots')
    }
  }, [nodeNameMap])

  // Take snapshot
  const handleSnapshot = useCallback(async () => {
    if (selectedNodes.size === 0) return
    setPhase('snapshotting')
    setError(null)
    try {
      const result = await driftSnapshot(Array.from(selectedNodes))
      setSnapshots(result.snapshots)
      // Auto-open first successful snapshot
      const first = result.snapshots.find(s => !s.error)
      if (first) {
        const full = await driftGetSnapshot(first.id)
        setViewingSnapshot(full)
        setHistoryNode(first.node_id)
      }
      setPhase('viewing')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to take snapshot')
      setPhase('ready')
    }
  }, [selectedNodes])

  // Load snapshot history when a node is selected
  useEffect(() => {
    if (historyNode) {
      driftListSnapshots(historyNode)
        .then(r => setHistory(r.snapshots))
        .catch(() => setHistory([]))
    }
  }, [historyNode])

  // View a specific snapshot
  const viewSnapshot = async (id: number) => {
    try {
      const full = await driftGetSnapshot(id)
      setViewingSnapshot(full)
      setDiffResult(null)
      setPhase('viewing')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load snapshot')
    }
  }

  // Set as baseline
  const handleSetBaseline = async (id: number) => {
    try {
      await driftSetBaseline(id)
      // Refresh history
      if (historyNode) {
        const r = await driftListSnapshots(historyNode)
        setHistory(r.snapshots)
      }
      // Refresh current snapshot view
      const full = await driftGetSnapshot(id)
      setViewingSnapshot(full)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to set baseline')
    }
  }

  // Compare against baseline
  const handleDiffBaseline = async (snapshotId: number) => {
    setPhase('diffing')
    setError(null)
    try {
      const result = await driftDiff(snapshotId, undefined, true)
      setDiffResult(result)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to compute diff')
      setPhase('viewing')
    }
  }

  // Compare two snapshots
  const handleDiffSnapshots = async (a: number, b: number) => {
    setPhase('diffing')
    setError(null)
    try {
      const result = await driftDiff(a, b)
      setDiffResult(result)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to compute diff')
      setPhase('viewing')
    }
  }

  // Delete snapshot
  const handleDelete = async (id: number) => {
    try {
      await driftDeleteSnapshot(id)
      if (historyNode) {
        const r = await driftListSnapshots(historyNode)
        setHistory(r.snapshots)
      }
      if (viewingSnapshot?.id === id) {
        setViewingSnapshot(null)
        setPhase('ready')
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete')
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-card border border-border/50 rounded-xl shadow-2xl w-full max-w-5xl max-h-[85vh] flex flex-col mx-4">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20">
              <Shield className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <h2 className="text-lg font-semibold">Drift Detection</h2>
              <p className="text-xs text-muted-foreground">Snapshot and compare node configurations</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg hover:bg-muted transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Error banner */}
        {error && (
          <div className="mx-6 mt-4 px-4 py-2 rounded-lg bg-destructive/10 border border-destructive/30 text-destructive text-sm">
            {error}
          </div>
        )}

        <div className="flex-1 overflow-hidden flex">
          {/* Sidebar */}
          <div className="w-56 border-r border-border/50 flex flex-col overflow-y-auto shrink-0">
            {/* Node selector (ready phase) or snapshot list */}
            {phase === 'ready' ? (
              <div className="p-4 flex flex-col gap-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Nodes</span>
                  <div className="flex gap-1">
                    <button onClick={selectAll} className="text-[10px] text-primary hover:underline">All</button>
                    <span className="text-[10px] text-muted-foreground">/</span>
                    <button onClick={selectNone} className="text-[10px] text-primary hover:underline">None</button>
                  </div>
                </div>
                {connectedNodes.map(n => (
                  <label key={n.agent_id} className="flex items-center gap-2 text-sm cursor-pointer group">
                    <input
                      type="checkbox"
                      checked={selectedNodes.has(n.agent_id)}
                      onChange={() => toggleNode(n.agent_id)}
                      className="rounded border-border/50 bg-muted/50 text-primary focus:ring-primary/30"
                    />
                    <span className="truncate group-hover:text-foreground text-muted-foreground transition-colors">{n.name}</span>
                  </label>
                ))}
                {connectedNodes.length === 0 && (
                  <p className="text-xs text-muted-foreground italic">No connected nodes</p>
                )}

                {/* Browse existing snapshots */}
                <div className="border-t border-border/50 pt-3 mt-1">
                  <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Browse History</span>
                  <div className="flex flex-col gap-1 mt-2">
                    {nodes.map(n => (
                      <button
                        key={n.agent_id}
                        onClick={() => handleBrowse(n.agent_id)}
                        className={`text-left text-xs px-2 py-1.5 rounded-md transition-colors hover:bg-muted text-muted-foreground hover:text-foreground ${
                          browseNode === n.agent_id ? 'bg-primary/10 text-primary' : ''
                        }`}
                      >
                        {n.name}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-4 flex flex-col gap-2">
                <button
                  onClick={() => { setPhase('ready'); setViewingSnapshot(null); setDiffResult(null) }}
                  className="text-xs text-primary hover:underline text-left mb-2"
                >
                  &larr; Back to snapshots
                </button>

                {/* Recent snapshots from current batch */}
                {snapshots.length > 0 && (
                  <>
                    <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Current</span>
                    {snapshots.map(s => (
                      <button
                        key={s.id}
                        onClick={() => {
                          viewSnapshot(s.id)
                          setHistoryNode(s.node_id)
                        }}
                        className={`text-left text-xs px-2 py-1.5 rounded-md transition-colors ${
                          viewingSnapshot?.id === s.id
                            ? 'bg-primary/10 text-primary border border-primary/20'
                            : 'hover:bg-muted text-muted-foreground'
                        }`}
                      >
                        <span className="font-medium">{nodeNameMap[s.node_id] || s.node_id.slice(0, 8)}</span>
                        {s.error && <span className="text-destructive ml-1">(error)</span>}
                        {s.is_baseline && <Star className="inline w-3 h-3 text-amber-400 ml-1" />}
                      </button>
                    ))}
                  </>
                )}

                {/* History for selected node */}
                {historyNode && (
                  <>
                    <button
                      onClick={() => setShowHistory(!showHistory)}
                      className="flex items-center gap-1 text-[10px] font-medium text-muted-foreground uppercase tracking-wider mt-3 hover:text-foreground"
                    >
                      {showHistory ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                      History
                    </button>
                    {showHistory && history.map(s => (
                      <div key={s.id} className="flex items-center gap-1">
                        <button
                          onClick={() => viewSnapshot(s.id)}
                          className={`flex-1 text-left text-xs px-2 py-1 rounded-md transition-colors ${
                            viewingSnapshot?.id === s.id
                              ? 'bg-primary/10 text-primary'
                              : 'hover:bg-muted text-muted-foreground'
                          }`}
                        >
                          {new Date(s.created_at * 1000).toLocaleString(undefined, {
                            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
                          })}
                          {s.is_baseline && <Star className="inline w-3 h-3 text-amber-400 ml-1" />}
                        </button>
                        <button
                          onClick={() => handleDelete(s.id)}
                          className="p-0.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors"
                          title="Delete snapshot"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </>
                )}
              </div>
            )}
          </div>

          {/* Main content */}
          <div className="flex-1 overflow-y-auto p-6">
            {phase === 'ready' && (
              <div className="flex flex-col items-center justify-center h-full gap-4">
                <div className="p-4 rounded-2xl bg-muted/30">
                  <Camera className="w-10 h-10 text-muted-foreground" />
                </div>
                <h3 className="text-lg font-semibold">Take a Configuration Snapshot</h3>
                <p className="text-sm text-muted-foreground text-center max-w-md">
                  Capture installed packages, running services, open ports, and user accounts.
                  Compare against baselines or other nodes to detect drift.
                </p>
                <button
                  onClick={handleSnapshot}
                  disabled={selectedNodes.size === 0}
                  className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-primary text-primary-foreground font-medium text-sm hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed mt-2"
                >
                  <Camera className="w-4 h-4" />
                  Snapshot {selectedNodes.size} node{selectedNodes.size !== 1 ? 's' : ''}
                </button>
              </div>
            )}

            {phase === 'snapshotting' && (
              <div className="flex flex-col items-center justify-center h-full gap-4">
                <Loader2 className="w-10 h-10 text-primary animate-spin" />
                <h3 className="text-lg font-semibold">Taking Snapshots...</h3>
                <p className="text-sm text-muted-foreground">Collecting configuration data via SSH</p>
              </div>
            )}

            {phase === 'viewing' && viewingSnapshot && (
              <SnapshotView
                snapshot={viewingSnapshot}
                nodeName={nodeNameMap[viewingSnapshot.node_id] || viewingSnapshot.node_id}
                activeTab={activeTab}
                onTabChange={setActiveTab}
                onSetBaseline={() => handleSetBaseline(viewingSnapshot.id)}
                onDiffBaseline={() => handleDiffBaseline(viewingSnapshot.id)}
                onDiffWith={(targetId) => handleDiffSnapshots(viewingSnapshot.id, targetId)}
                history={history}
                diffMode={diffMode}
                setDiffMode={setDiffMode}
                nodes={nodes}
                nodeNameMap={nodeNameMap}
              />
            )}

            {phase === 'diffing' && !diffResult && (
              <div className="flex flex-col items-center justify-center h-full gap-4">
                <Loader2 className="w-10 h-10 text-primary animate-spin" />
                <h3 className="text-lg font-semibold">Computing Diff...</h3>
              </div>
            )}

            {phase === 'diffing' && diffResult && (
              <DiffView
                diff={diffResult}
                activeTab={activeTab}
                onTabChange={setActiveTab}
                onBack={() => { setPhase('viewing'); setDiffResult(null) }}
                nodeNameMap={nodeNameMap}
              />
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// --- Snapshot View ---

function SnapshotView({
  snapshot,
  nodeName,
  activeTab,
  onTabChange,
  onSetBaseline,
  onDiffBaseline,
  onDiffWith,
  history,
  diffMode,
  setDiffMode,
  nodes,
  nodeNameMap,
}: {
  snapshot: DriftSnapshot
  nodeName: string
  activeTab: Tab
  onTabChange: (t: Tab) => void
  onSetBaseline: () => void
  onDiffBaseline: () => void
  onDiffWith: (targetId: number) => void
  history: DriftSnapshotSummary[]
  diffMode: 'compare' | 'baseline' | null
  setDiffMode: (m: 'compare' | 'baseline' | null) => void
  nodes: NodeStatus[]
  nodeNameMap: Record<string, string>
}) {
  const [crossNodeSnapshots, setCrossNodeSnapshots] = useState<Record<string, DriftSnapshotSummary[]>>({})
  const [loadingCross, setLoadingCross] = useState(false)
  const counts = {
    packages: snapshot.packages?.length ?? 0,
    services: snapshot.services?.length ?? 0,
    ports: snapshot.ports?.length ?? 0,
    users: snapshot.users?.length ?? 0,
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Snapshot header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-semibold flex items-center gap-2">
            {nodeName}
            {snapshot.is_baseline && (
              <span className="text-[10px] font-medium uppercase px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                Baseline
              </span>
            )}
          </h3>
          <p className="text-xs text-muted-foreground">
            {new Date(snapshot.created_at * 1000).toLocaleString()}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {!snapshot.is_baseline && (
            <button
              onClick={onSetBaseline}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-amber-500/30 bg-amber-500/5 text-amber-400 text-xs font-medium hover:bg-amber-500/10 transition-colors"
            >
              <Star className="w-3 h-3" />
              Set Baseline
            </button>
          )}
          <button
            onClick={onDiffBaseline}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border/50 bg-card/50 text-xs font-medium hover:bg-muted transition-colors"
          >
            <GitCompare className="w-3 h-3" />
            vs Baseline
          </button>
          <div className="relative">
            <button
              onClick={async () => {
                if (diffMode === 'compare') {
                  setDiffMode(null)
                } else {
                  setDiffMode('compare')
                  // Load baselines/latest from other nodes for cross-node comparison
                  if (Object.keys(crossNodeSnapshots).length === 0) {
                    setLoadingCross(true)
                    const otherNodes = nodes.filter(n => n.agent_id !== snapshot.node_id)
                    const results: Record<string, DriftSnapshotSummary[]> = {}
                    await Promise.all(otherNodes.map(async n => {
                      try {
                        const r = await driftListSnapshots(n.agent_id)
                        if (r.snapshots.length > 0) results[n.agent_id] = r.snapshots
                      } catch {}
                    }))
                    setCrossNodeSnapshots(results)
                    setLoadingCross(false)
                  }
                }
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border/50 bg-card/50 text-xs font-medium hover:bg-muted transition-colors"
            >
              <GitCompare className="w-3 h-3" />
              Compare...
            </button>
            {diffMode === 'compare' && (
              <div className="absolute top-full right-0 mt-1 w-64 bg-card border border-border/50 rounded-lg shadow-xl z-10 py-1 max-h-72 overflow-y-auto">
                {/* Same node history */}
                {history.filter(s => s.id !== snapshot.id).length > 0 && (
                  <>
                    <p className="px-3 py-1 text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Same Node</p>
                    {history
                      .filter(s => s.id !== snapshot.id)
                      .map(s => (
                        <button
                          key={s.id}
                          onClick={() => {
                            onDiffWith(s.id)
                            setDiffMode(null)
                          }}
                          className="w-full text-left px-3 py-1.5 text-xs hover:bg-muted transition-colors flex items-center justify-between"
                        >
                          <span>
                            {new Date(s.created_at * 1000).toLocaleString(undefined, {
                              month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
                            })}
                          </span>
                          {s.is_baseline && <Star className="w-3 h-3 text-amber-400" />}
                        </button>
                      ))}
                  </>
                )}

                {/* Cross-node snapshots */}
                {loadingCross ? (
                  <p className="px-3 py-2 text-xs text-muted-foreground italic flex items-center gap-1">
                    <Loader2 className="w-3 h-3 animate-spin" /> Loading other nodes...
                  </p>
                ) : Object.keys(crossNodeSnapshots).length > 0 ? (
                  <>
                    <div className="border-t border-border/30 my-1" />
                    <p className="px-3 py-1 text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Other Nodes</p>
                    {Object.entries(crossNodeSnapshots).map(([nodeId, snaps]) => {
                      // Show baseline first, or latest
                      const baseline = snaps.find(s => s.is_baseline)
                      const latest = snaps[0]
                      const pick = baseline || latest
                      return (
                        <button
                          key={nodeId}
                          onClick={() => {
                            onDiffWith(pick.id)
                            setDiffMode(null)
                          }}
                          className="w-full text-left px-3 py-1.5 text-xs hover:bg-muted transition-colors flex items-center justify-between"
                        >
                          <span className="font-medium">{nodeNameMap[nodeId] || nodeId.slice(0, 8)}</span>
                          <span className="text-muted-foreground flex items-center gap-1">
                            {baseline ? <Star className="w-3 h-3 text-amber-400" /> : 'latest'}
                          </span>
                        </button>
                      )
                    })}
                  </>
                ) : null}

                {history.filter(s => s.id !== snapshot.id).length === 0 && Object.keys(crossNodeSnapshots).length === 0 && !loadingCross && (
                  <p className="px-3 py-2 text-xs text-muted-foreground italic">No other snapshots</p>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border/50">
        {(Object.keys(TAB_CONFIG) as Tab[]).map(tab => {
          const { label, icon: Icon } = TAB_CONFIG[tab]
          return (
            <button
              key={tab}
              onClick={() => onTabChange(tab)}
              className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
                activeTab === tab
                  ? 'border-primary text-primary'
                  : 'border-transparent text-muted-foreground hover:text-foreground'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {label}
              <span className="text-[10px] opacity-60">({counts[tab]})</span>
            </button>
          )
        })}
      </div>

      {/* Table content */}
      <div className="overflow-auto max-h-[400px]">
        {activeTab === 'packages' && (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-card">
              <tr className="border-b border-border/50 text-muted-foreground">
                <th className="text-left py-2 px-2 font-medium">Package</th>
                <th className="text-left py-2 px-2 font-medium">Version</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.packages?.map((p, i) => (
                <tr key={i} className="border-b border-border/30 hover:bg-muted/30">
                  <td className="py-1.5 px-2 font-mono">{p.name}</td>
                  <td className="py-1.5 px-2 font-mono text-muted-foreground">{p.version}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === 'services' && (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-card">
              <tr className="border-b border-border/50 text-muted-foreground">
                <th className="text-left py-2 px-2 font-medium">Service</th>
                <th className="text-left py-2 px-2 font-medium">State</th>
                <th className="text-left py-2 px-2 font-medium">Sub-state</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.services?.map((s, i) => (
                <tr key={i} className="border-b border-border/30 hover:bg-muted/30">
                  <td className="py-1.5 px-2 font-mono">{s.name}</td>
                  <td className="py-1.5 px-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                      s.state === 'active' ? 'bg-emerald-500/10 text-emerald-400' :
                      s.state === 'failed' ? 'bg-destructive/10 text-destructive' :
                      'bg-muted text-muted-foreground'
                    }`}>
                      {s.state}
                    </span>
                  </td>
                  <td className="py-1.5 px-2 text-muted-foreground">{s.sub_state}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === 'ports' && (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-card">
              <tr className="border-b border-border/50 text-muted-foreground">
                <th className="text-left py-2 px-2 font-medium">Proto</th>
                <th className="text-left py-2 px-2 font-medium">Address</th>
                <th className="text-left py-2 px-2 font-medium">Port</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.ports?.map((p, i) => (
                <tr key={i} className="border-b border-border/30 hover:bg-muted/30">
                  <td className="py-1.5 px-2 font-mono">{p.proto}</td>
                  <td className="py-1.5 px-2 font-mono">{p.address}</td>
                  <td className="py-1.5 px-2 font-mono font-semibold">{p.port}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === 'users' && (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-card">
              <tr className="border-b border-border/50 text-muted-foreground">
                <th className="text-left py-2 px-2 font-medium">User</th>
                <th className="text-left py-2 px-2 font-medium">UID</th>
                <th className="text-left py-2 px-2 font-medium">GID</th>
                <th className="text-left py-2 px-2 font-medium">Home</th>
                <th className="text-left py-2 px-2 font-medium">Shell</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.users?.map((u, i) => (
                <tr key={i} className="border-b border-border/30 hover:bg-muted/30">
                  <td className="py-1.5 px-2 font-mono font-semibold">{u.name}</td>
                  <td className="py-1.5 px-2 font-mono text-muted-foreground">{u.uid}</td>
                  <td className="py-1.5 px-2 font-mono text-muted-foreground">{u.gid}</td>
                  <td className="py-1.5 px-2 font-mono text-muted-foreground">{u.home}</td>
                  <td className="py-1.5 px-2 font-mono text-muted-foreground">{u.shell}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

// --- Diff View ---

function DiffView({
  diff,
  activeTab,
  onTabChange,
  onBack,
  nodeNameMap,
}: {
  diff: DriftDiffResult
  activeTab: Tab
  onTabChange: (t: Tab) => void
  onBack: () => void
  nodeNameMap: Record<string, string>
}) {
  const [showAdded, setShowAdded] = useState(true)
  const [showRemoved, setShowRemoved] = useState(true)
  const [showChanged, setShowChanged] = useState(true)
  const [searchFilter, setSearchFilter] = useState('')
  const [pkgActions, setPkgActions] = useState<Record<string, 'pending' | 'running' | 'done' | 'error'>>({})

  const categories = { packages: diff.packages, services: diff.services, ports: diff.ports, users: diff.users }
  const current = categories[activeTab]
  const totalChanges = (c: DriftCategoryDiff) => c.added.length + c.removed.length + c.changed.length

  const nameA = nodeNameMap[diff.node_a_id] || diff.node_a_id?.slice(0, 8) || `#${diff.snapshot_a}`
  const nameB = nodeNameMap[diff.node_b_id] || diff.node_b_id?.slice(0, 8) || `#${diff.snapshot_b}`

  // Filter entries by search text
  const filterFn = (key: string) =>
    !searchFilter || key.toLowerCase().includes(searchFilter.toLowerCase())

  const filteredAdded = showAdded ? current.added.filter(e => filterFn(e.key)) : []
  const filteredRemoved = showRemoved ? current.removed.filter(e => filterFn(e.key)) : []
  const filteredChanged = showChanged ? current.changed.filter(e => filterFn(e.key)) : []
  const visibleCount = filteredAdded.length + filteredRemoved.length + filteredChanged.length

  // Run package install/remove via fleet command
  const runPkgAction = async (action: 'install' | 'remove', packageName: string, nodeId: string) => {
    const actionKey = `${action}-${packageName}`
    setPkgActions(prev => ({ ...prev, [actionKey]: 'running' }))
    try {
      const cmd = action === 'install'
        ? `command -v apt >/dev/null 2>&1 && apt install -y ${packageName} || command -v dnf >/dev/null 2>&1 && dnf install -y ${packageName} || command -v pacman >/dev/null 2>&1 && pacman -S --noconfirm ${packageName}`
        : `command -v apt >/dev/null 2>&1 && apt remove -y ${packageName} || command -v dnf >/dev/null 2>&1 && dnf remove -y ${packageName} || command -v pacman >/dev/null 2>&1 && pacman -R --noconfirm ${packageName}`
      const jobId = await fleetRun(cmd, [nodeId], true)
      // Poll until done
      let done = false
      for (let i = 0; i < 30 && !done; i++) {
        await new Promise(r => setTimeout(r, 1000))
        const poll = await fleetPoll(jobId, { [nodeId]: 0 })
        const nodeResult = poll.nodes?.[nodeId]
        if (nodeResult?.done) done = true
      }
      setPkgActions(prev => ({ ...prev, [actionKey]: done ? 'done' : 'error' }))
    } catch {
      setPkgActions(prev => ({ ...prev, [actionKey]: 'error' }))
    }
  }

  const isPkgTab = activeTab === 'packages'

  // Simple version comparison: returns -1 if a < b, 0 if equal, 1 if a > b
  const compareVersions = (a: string, b: string): number => {
    const partsA = a.replace(/[~+]/g, '.').split(/[.\-:]/).map(s => {
      const n = parseInt(s, 10)
      return isNaN(n) ? s : n
    })
    const partsB = b.replace(/[~+]/g, '.').split(/[.\-:]/).map(s => {
      const n = parseInt(s, 10)
      return isNaN(n) ? s : n
    })
    const len = Math.max(partsA.length, partsB.length)
    for (let i = 0; i < len; i++) {
      const pa = partsA[i] ?? 0
      const pb = partsB[i] ?? 0
      if (typeof pa === 'number' && typeof pb === 'number') {
        if (pa < pb) return -1
        if (pa > pb) return 1
      } else {
        const sa = String(pa), sb = String(pb)
        if (sa < sb) return -1
        if (sa > sb) return 1
      }
    }
    return 0
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="text-xs text-primary hover:underline"
          >
            &larr; Back
          </button>
          <h3 className="text-base font-semibold flex items-center gap-2">
            <GitCompare className="w-4 h-4 text-primary" />
            {nameA} vs {nameB}
          </h3>
        </div>
      </div>

      {/* Tabs with change counts */}
      <div className="flex gap-1 border-b border-border/50">
        {(Object.keys(TAB_CONFIG) as Tab[]).map(tab => {
          const { label, icon: Icon } = TAB_CONFIG[tab]
          const count = totalChanges(categories[tab])
          return (
            <button
              key={tab}
              onClick={() => onTabChange(tab)}
              className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
                activeTab === tab
                  ? 'border-primary text-primary'
                  : 'border-transparent text-muted-foreground hover:text-foreground'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {label}
              {count > 0 && (
                <span className="bg-amber-500/10 text-amber-400 text-[10px] font-semibold px-1.5 py-0.5 rounded-full">
                  {count}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* Filter controls */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Type toggles */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setShowAdded(!showAdded)}
            className={`flex items-center gap-1 px-2 py-1 rounded-full text-[11px] font-medium transition-all border ${
              showAdded
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                : 'bg-card/50 border-border/50 text-muted-foreground opacity-50'
            }`}
          >
            <Plus className="w-2.5 h-2.5" />
            In {nameB} only
            {current.added.length > 0 && <span className="opacity-60">({current.added.length})</span>}
          </button>
          <button
            onClick={() => setShowRemoved(!showRemoved)}
            className={`flex items-center gap-1 px-2 py-1 rounded-full text-[11px] font-medium transition-all border ${
              showRemoved
                ? 'bg-red-500/10 border-red-500/30 text-red-400'
                : 'bg-card/50 border-border/50 text-muted-foreground opacity-50'
            }`}
          >
            <Minus className="w-2.5 h-2.5" />
            In {nameA} only
            {current.removed.length > 0 && <span className="opacity-60">({current.removed.length})</span>}
          </button>
          <button
            onClick={() => setShowChanged(!showChanged)}
            className={`flex items-center gap-1 px-2 py-1 rounded-full text-[11px] font-medium transition-all border ${
              showChanged
                ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                : 'bg-card/50 border-border/50 text-muted-foreground opacity-50'
            }`}
          >
            <ArrowRight className="w-2.5 h-2.5" />
            Drifted
            {current.changed.length > 0 && <span className="opacity-60">({current.changed.length})</span>}
          </button>
        </div>

        {/* Text search */}
        <div className="flex-1 min-w-[180px] relative">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={searchFilter}
            onChange={e => setSearchFilter(e.target.value)}
            placeholder="Filter by name..."
            className="w-full pl-8 pr-3 py-1.5 rounded-lg border border-border/50 bg-muted/30 text-xs placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40"
          />
          {searchFilter && (
            <button
              onClick={() => setSearchFilter('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
        <span className="text-[10px] text-muted-foreground">{visibleCount} shown</span>
      </div>

      {/* Diff content */}
      <div className="overflow-auto max-h-[400px]">
        {totalChanges(current) === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Shield className="w-8 h-8 mb-2 opacity-50" />
            <p className="text-sm">No differences in {TAB_CONFIG[activeTab].label.toLowerCase()}</p>
          </div>
        ) : visibleCount === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Search className="w-8 h-8 mb-2 opacity-50" />
            <p className="text-sm">No matching entries</p>
          </div>
        ) : (
          <div className="flex flex-col gap-1">
            {/* Added — in B but not in A → offer Install on A */}
            {filteredAdded.map((entry, i) => {
              const actionKey = `install-a-${entry.key}`
              const status = pkgActions[actionKey]
              return (
                <div key={`add-${i}`} className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-emerald-500/5 border border-emerald-500/20">
                  <Plus className="w-3 h-3 text-emerald-400 shrink-0" />
                  <span className="font-mono text-xs text-emerald-300">{entry.key}</span>
                  <span className="font-mono text-xs text-muted-foreground">{entry.value}</span>
                  <span className="flex-1" />
                  {isPkgTab && diff.node_a_id && (
                    status === 'running' ? <Loader2 className="w-3 h-3 text-muted-foreground animate-spin shrink-0" /> :
                    status === 'done' ? <Check className="w-3 h-3 text-emerald-400 shrink-0" /> :
                    <button
                      onClick={() => runPkgAction('install', entry.key, diff.node_a_id)}
                      className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20 transition-colors shrink-0"
                      title={`Install ${entry.key} on ${nameA}`}
                    >
                      <Download className="w-2.5 h-2.5" />
                      Install on {nameA}
                    </button>
                  )}
                </div>
              )
            })}

            {/* Removed — in A but not in B → offer Install on B */}
            {filteredRemoved.map((entry, i) => {
              const actionKey = `install-b-${entry.key}`
              const status = pkgActions[actionKey]
              return (
                <div key={`rm-${i}`} className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-destructive/5 border border-destructive/20">
                  <Minus className="w-3 h-3 text-destructive shrink-0" />
                  <span className="font-mono text-xs text-red-300">{entry.key}</span>
                  <span className="font-mono text-xs text-muted-foreground">{entry.value}</span>
                  <span className="flex-1" />
                  {isPkgTab && diff.node_b_id && (
                    status === 'running' ? <Loader2 className="w-3 h-3 text-muted-foreground animate-spin shrink-0" /> :
                    status === 'done' ? <Check className="w-3 h-3 text-emerald-400 shrink-0" /> :
                    <button
                      onClick={() => runPkgAction('install', entry.key, diff.node_b_id)}
                      className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20 transition-colors shrink-0"
                      title={`Install ${entry.key} on ${nameB}`}
                    >
                      <Download className="w-2.5 h-2.5" />
                      Install on {nameB}
                    </button>
                  )}
                </div>
              )
            })}

            {/* Changed */}
            {filteredChanged.map((entry, i) => {
              const cmp = isPkgTab ? compareVersions(entry.old_value, entry.new_value) : 0
              // old_value = A's version, new_value = B's version
              // if A < B → A is older → update on A
              // if A > B → B is older → update on B
              const olderNode = cmp < 0 ? diff.node_a_id : cmp > 0 ? diff.node_b_id : null
              const olderName = cmp < 0 ? nameA : cmp > 0 ? nameB : null
              const actionKey = `update-${entry.key}`
              const status = pkgActions[actionKey]
              return (
                <div key={`chg-${i}`} className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-amber-500/5 border border-amber-500/20">
                  <ArrowRight className="w-3 h-3 text-amber-400 shrink-0" />
                  <span className="font-mono text-xs text-amber-300">{entry.key}</span>
                  <span className="font-mono text-xs text-muted-foreground line-through">{entry.old_value}</span>
                  <ArrowRight className="w-2.5 h-2.5 text-muted-foreground shrink-0" />
                  <span className="font-mono text-xs">{entry.new_value}</span>
                  <span className="flex-1" />
                  {isPkgTab && olderNode && (
                    status === 'running' ? <Loader2 className="w-3 h-3 text-muted-foreground animate-spin shrink-0" /> :
                    status === 'done' ? <Check className="w-3 h-3 text-emerald-400 shrink-0" /> :
                    <button
                      onClick={() => runPkgAction('install', entry.key, olderNode)}
                      className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-500/10 border border-amber-500/20 text-amber-400 hover:bg-amber-500/20 transition-colors shrink-0"
                      title={`Update ${entry.key} on ${olderName}`}
                    >
                      <Download className="w-2.5 h-2.5" />
                      Update on {olderName}
                    </button>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
