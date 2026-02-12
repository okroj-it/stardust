import { useState, useEffect, useRef, useCallback } from "react"
import { ansibleRun, ansiblePoll } from "@/lib/api"
import type { NodeStatus } from "@/lib/api"
import { X, Loader2, Check, AlertCircle, Play, Terminal, ChevronDown, ChevronRight } from "lucide-react"

interface AnsibleModalProps {
  nodes: NodeStatus[]
  ansibleVersion: string
  onClose: () => void
}

type Phase = 'ready' | 'running' | 'done' | 'error'

const EXAMPLE_PLAYBOOK = `---
- hosts: stardust
  gather_facts: true
  tasks:
    - name: Ping all nodes
      ansible.builtin.ping:

    - name: Show hostname
      ansible.builtin.command: hostname
      register: result

    - name: Print hostname
      ansible.builtin.debug:
        msg: "{{ result.stdout }}"
`

const EXAMPLE_REQUIREMENTS = `---
roles: []
  # - name: geerlingguy.docker
  #   version: "7.4.1"

collections: []
  # - name: community.general
  #   version: ">=9.0.0"
`

export function AnsibleModal({ nodes, ansibleVersion, onClose }: AnsibleModalProps) {
  const [phase, setPhase] = useState<Phase>('ready')
  const [playbook, setPlaybook] = useState(EXAMPLE_PLAYBOOK)
  const [requirements, setRequirements] = useState("")
  const [showRequirements, setShowRequirements] = useState(false)
  const [selectedNodes, setSelectedNodes] = useState<Set<string>>(
    new Set(nodes.filter(n => n.connected).map(n => n.agent_id))
  )
  const [output, setOutput] = useState("")
  const [error, setError] = useState<string | null>(null)
  const outputRef = useRef<HTMLPreElement>(null)
  const jobRef = useRef<{ id: string; offset: number } | null>(null)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Auto-scroll
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [output])

  // Cleanup
  useEffect(() => {
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [])

  const poll = useCallback(async () => {
    const job = jobRef.current
    if (!job) return

    try {
      const res = await ansiblePoll(job.id, job.offset)
      if (res.output) {
        setOutput(prev => prev + res.output)
      }
      job.offset = res.offset

      if (res.done) {
        if (pollingRef.current) {
          clearInterval(pollingRef.current)
          pollingRef.current = null
        }
        jobRef.current = null
        setPhase(res.ok ? 'done' : 'error')
        if (!res.ok) setError("Playbook failed (see output above)")
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
    if (!playbook.trim()) return

    setPhase('running')
    setOutput("")
    setError(null)

    try {
      const nodeIds = selectedNodes.size < nodes.length
        ? Array.from(selectedNodes)
        : undefined
      const jobId = await ansibleRun(playbook, nodeIds, requirements || undefined)
      jobRef.current = { id: jobId, offset: 0 }
      pollingRef.current = setInterval(poll, 300)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start playbook')
      setPhase('error')
    }
  }

  const handleReset = () => {
    setPhase('ready')
    setOutput("")
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

  const toggleAll = () => {
    if (selectedNodes.size === nodes.length) {
      setSelectedNodes(new Set())
    } else {
      setSelectedNodes(new Set(nodes.map(n => n.agent_id)))
    }
  }

  const isRunning = phase === 'running'
  const showEditor = phase === 'ready'
  const showOutput = phase === 'running' || phase === 'done' || (phase === 'error' && output)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={!isRunning ? onClose : undefined} />
      <div className="relative w-full max-w-4xl mx-4 rounded-2xl border border-border/50 bg-[#0d1117] shadow-2xl animate-in fade-in zoom-in-95 duration-200 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border/30 bg-[#161b22] rounded-t-2xl">
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-[#ff5f57]" />
              <div className="w-3 h-3 rounded-full bg-[#febc2e]" />
              <div className="w-3 h-3 rounded-full bg-[#28c840]" />
            </div>
            <div className="flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-[#8b949e]" />
              <span className="text-xs text-[#8b949e] font-mono">Ansible</span>
              <span className="text-[10px] text-[#58a6ff] bg-[#58a6ff]/10 px-1.5 py-0.5 rounded font-mono">
                v{ansibleVersion}
              </span>
            </div>
          </div>
          {!isRunning && (
            <button onClick={onClose} className="p-1 rounded hover:bg-[#30363d] transition-colors">
              <X className="w-4 h-4 text-[#8b949e]" />
            </button>
          )}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-auto flex flex-col min-h-0">
          {showEditor && (
            <div className="flex flex-col gap-3 p-4">
              {/* Node selection */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-[#8b949e] font-medium uppercase tracking-wider">Target Nodes</span>
                  <button
                    onClick={toggleAll}
                    className="text-[10px] text-[#58a6ff] hover:text-[#79c0ff] transition-colors"
                  >
                    {selectedNodes.size === nodes.length ? 'Deselect All' : 'Select All'}
                  </button>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {nodes.map(node => (
                    <button
                      key={node.agent_id}
                      onClick={() => toggleNode(node.agent_id)}
                      className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono transition-colors border ${
                        selectedNodes.has(node.agent_id)
                          ? 'bg-[#58a6ff]/10 border-[#58a6ff]/30 text-[#58a6ff]'
                          : 'bg-[#161b22] border-border/30 text-[#484f58] hover:text-[#8b949e]'
                      }`}
                    >
                      <div className={`w-1.5 h-1.5 rounded-full ${
                        node.connected ? 'bg-emerald-400' : 'bg-[#484f58]'
                      }`} />
                      {node.name}
                    </button>
                  ))}
                </div>
              </div>

              {/* Requirements (collapsible) */}
              <div>
                <button
                  onClick={() => {
                    setShowRequirements(!showRequirements)
                    if (!showRequirements && !requirements) setRequirements(EXAMPLE_REQUIREMENTS)
                  }}
                  className="flex items-center gap-1.5 text-xs text-[#8b949e] font-medium uppercase tracking-wider hover:text-[#c9d1d9] transition-colors mb-2"
                >
                  {showRequirements
                    ? <ChevronDown className="w-3 h-3" />
                    : <ChevronRight className="w-3 h-3" />
                  }
                  Requirements.yml
                  {requirements.trim() && (
                    <span className="text-[10px] text-[#58a6ff] bg-[#58a6ff]/10 px-1.5 py-0.5 rounded font-mono normal-case ml-1">active</span>
                  )}
                </button>
                {showRequirements && (
                  <textarea
                    value={requirements}
                    onChange={e => setRequirements(e.target.value)}
                    className="w-full h-[16vh] bg-[#0d1117] border border-border/30 rounded-lg p-3 font-mono text-[13px] text-[#c9d1d9] resize-none focus:outline-none focus:border-[#58a6ff]/50 scrollbar-thin"
                    spellCheck={false}
                    placeholder="---&#10;roles:&#10;  - name: geerlingguy.docker&#10;collections:&#10;  - name: community.general"
                  />
                )}
              </div>

              {/* Playbook editor */}
              <div>
                <span className="text-xs text-[#8b949e] font-medium uppercase tracking-wider block mb-2">Playbook</span>
                <textarea
                  value={playbook}
                  onChange={e => setPlaybook(e.target.value)}
                  className={`w-full bg-[#0d1117] border border-border/30 rounded-lg p-3 font-mono text-[13px] text-[#c9d1d9] resize-none focus:outline-none focus:border-[#58a6ff]/50 scrollbar-thin ${showRequirements ? 'h-[28vh]' : 'h-[40vh]'}`}
                  spellCheck={false}
                  placeholder="---&#10;- hosts: stardust&#10;  tasks:&#10;    - name: Ping&#10;      ansible.builtin.ping:"
                />
              </div>
            </div>
          )}

          {showOutput && (
            <pre
              ref={outputRef}
              className="flex-1 overflow-auto p-4 font-mono text-[13px] leading-relaxed text-[#c9d1d9] whitespace-pre-wrap break-all min-h-[200px] max-h-[65vh] scrollbar-thin"
            >
              <span className="text-[#58a6ff]">$ ansible-playbook</span>
              {'\n\n'}
              {output || (
                <span className="text-[#8b949e] flex items-center gap-2">
                  <Loader2 className="w-3.5 h-3.5 animate-spin inline" />
                  Starting playbook run...
                </span>
              )}
              {isRunning && output && <span className="animate-pulse">_</span>}
              {phase === 'done' && (
                <>
                  {'\n'}
                  <span className="text-[#7ee787]">Playbook completed successfully.</span>
                </>
              )}
            </pre>
          )}

          {phase === 'error' && !output && error && (
            <div className="p-4">
              <span className="text-[#f85149] text-sm">{error}</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-border/30 bg-[#161b22] rounded-b-2xl">
          <div className="flex items-center gap-2">
            {phase === 'done' && (
              <span className="flex items-center gap-1.5 text-xs text-[#7ee787]">
                <Check className="w-3.5 h-3.5" />
                Complete
              </span>
            )}
            {phase === 'running' && (
              <span className="flex items-center gap-1.5 text-xs text-[#8b949e]">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Running...
              </span>
            )}
            {phase === 'error' && error && (
              <span className="flex items-center gap-1.5 text-xs text-[#f85149]">
                <AlertCircle className="w-3.5 h-3.5" />
                {error}
              </span>
            )}
            {phase === 'ready' && (
              <span className="text-xs text-[#8b949e]">
                {selectedNodes.size} of {nodes.length} node{nodes.length !== 1 ? 's' : ''} selected
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {!isRunning && (
              <button
                onClick={onClose}
                className="px-3 py-1.5 rounded-lg text-xs text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#30363d] transition-colors"
              >
                Close
              </button>
            )}

            {(phase === 'done' || phase === 'error') && (
              <button
                onClick={handleReset}
                className="px-3 py-1.5 rounded-lg text-xs text-[#58a6ff] hover:bg-[#58a6ff]/10 transition-colors"
              >
                Edit Playbook
              </button>
            )}

            {phase === 'ready' && (
              <button
                onClick={handleRun}
                disabled={selectedNodes.size === 0 || !playbook.trim()}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#238636] text-white text-xs font-medium hover:bg-[#2ea043] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Play className="w-3.5 h-3.5" />
                Run Playbook
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
