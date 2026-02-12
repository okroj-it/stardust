import { useState, useEffect, useCallback } from "react"
import { useNodes } from "@/hooks/use-stats"
import { NodeCard } from "@/components/node-card"
import { NodeDetail } from "@/components/node-detail"
import { AddNodeModal } from "@/components/add-node-modal"
import { RemoveNodeModal } from "@/components/remove-node-modal"
import { ProfileModal } from "@/components/profile-modal"
import { LoginPage } from "@/components/login-page"
import { isTokenValid, clearToken } from "@/lib/auth"
import {
  Server,
  Activity,
  Plus,
  Zap,
  UserCircle,
} from "lucide-react"

function App() {
  const [authed, setAuthed] = useState(() => isTokenValid())

  const handleLogout = useCallback(() => {
    clearToken()
    setAuthed(false)
  }, [])

  useEffect(() => {
    const onAuthLogout = () => setAuthed(false)
    window.addEventListener('auth:logout', onAuthLogout)
    return () => window.removeEventListener('auth:logout', onAuthLogout)
  }, [])

  if (!authed) {
    return <LoginPage onLogin={() => setAuthed(true)} />
  }

  return <Dashboard onLogout={handleLogout} />
}

function Dashboard({ onLogout }: { onLogout: () => void }) {
  const { nodes, loading, refresh } = useNodes(5000)
  const [selectedNode, setSelectedNode] = useState<string | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)
  const [removeNode, setRemoveNode] = useState<string | null>(null)
  const [showProfile, setShowProfile] = useState(false)

  const onlineCount = nodes.filter((n) => n.connected).length

  return (
    <div className="min-h-screen relative overflow-hidden">
      {/* Subtle background grid */}
      <div className="fixed inset-0 pointer-events-none">
        <div
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: `
              linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px),
              linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)
            `,
            backgroundSize: "60px 60px",
          }}
        />
        {/* Gradient orbs */}
        <div className="absolute top-[-20%] right-[-10%] w-[500px] h-[500px] bg-primary/5 rounded-full blur-[120px]" />
        <div className="absolute bottom-[-10%] left-[-10%] w-[400px] h-[400px] bg-indigo-500/5 rounded-full blur-[100px]" />
      </div>

      <div className="relative z-10 max-w-[1400px] mx-auto px-6 py-8">
        {/* Header */}
        <header className="flex items-center justify-between mb-10">
          <div className="flex items-center gap-4">
            <div className="relative">
              <div className="p-3 rounded-xl bg-gradient-to-br from-primary/20 to-indigo-500/20 border border-primary/20">
                <Zap className="w-6 h-6 text-primary" />
              </div>
              <div className="absolute -top-0.5 -right-0.5 w-3 h-3 bg-emerald-400 rounded-full border-2 border-background" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text">
                Stardust
              </h1>
              <p className="text-xs text-muted-foreground">Orchestrating the Spiders from Mars</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Stats pills */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-border/50 bg-card/50 backdrop-blur-sm">
              <Server className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="text-xs font-medium">{nodes.length} nodes</span>
              <span className="w-px h-3 bg-border" />
              <div className="flex items-center gap-1">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                <span className="text-xs text-emerald-400 font-medium">{onlineCount} online</span>
              </div>
            </div>

            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
            >
              <Plus className="w-4 h-4" />
              Add Node
            </button>

            <button
              onClick={() => setShowProfile(true)}
              className="p-2 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
              title="Profile"
            >
              <UserCircle className="w-4 h-4" />
            </button>
          </div>
        </header>

        {/* Main Content */}
        <div className="flex gap-6">
          {/* Node Grid */}
          <div className={selectedNode ? "w-[380px] shrink-0" : "w-full"}>
            {loading ? (
              <div className="flex items-center justify-center py-20">
                <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
              </div>
            ) : nodes.length === 0 ? (
              <EmptyState />
            ) : (
              <div className={selectedNode
                ? "flex flex-col gap-3"
                : "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"
              }>
                {nodes.map((node) => (
                  <NodeCard
                    key={node.agent_id}
                    node={node}
                    onClick={() => setSelectedNode(
                      selectedNode === node.agent_id ? null : node.agent_id
                    )}
                    selected={selectedNode === node.agent_id}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Detail Panel */}
          {selectedNode && (
            <div className="flex-1 min-w-0">
              <NodeDetail
                node={nodes.find(n => n.agent_id === selectedNode)!}
                onClose={() => setSelectedNode(null)}
                onRemove={() => setRemoveNode(selectedNode)}
              />
            </div>
          )}
        </div>
      </div>

      {showAddModal && (
        <AddNodeModal
          onClose={() => setShowAddModal(false)}
          onSuccess={refresh}
        />
      )}

      {removeNode && (() => {
        const node = nodes.find(n => n.agent_id === removeNode)
        return node ? (
          <RemoveNodeModal
            node={node}
            onClose={() => setRemoveNode(null)}
            onDeleted={() => {
              setRemoveNode(null)
              setSelectedNode(null)
              refresh()
            }}
          />
        ) : null
      })()}

      {showProfile && (
        <ProfileModal
          onClose={() => setShowProfile(false)}
          onLogout={onLogout}
        />
      )}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <div className="p-4 rounded-2xl bg-muted/30 mb-6">
        <Activity className="w-10 h-10 text-muted-foreground" />
      </div>
      <h3 className="text-lg font-semibold mb-2">No Spiders Connected</h3>
      <p className="text-sm text-muted-foreground max-w-md mb-6">
        Deploy a Spider to any server to see live system metrics here.
        Spiders automatically connect via WebSocket and begin streaming telemetry.
      </p>
      <div className="p-4 rounded-lg bg-card/50 border border-border/50 font-mono text-xs text-muted-foreground max-w-lg text-left">
        <span className="text-emerald-400">$</span> ./stardust-spider --server wss://your-server/ws \<br />
        &nbsp;&nbsp;--token your-token --agent-id my-server
      </div>
    </div>
  )
}

export default App
