import { useState, useCallback } from "react"
import { deployStep, deleteNode, type NodeStatus } from "@/lib/api"
import { X, Trash2, Loader2, Check, AlertCircle, Minus, Plug, Square, SearchCheck, Unplug, ShieldOff, DatabaseZap } from "lucide-react"

interface RemoveNodeModalProps {
  node: NodeStatus
  onClose: () => void
  onDeleted: () => void
}

type StepStatus = 'pending' | 'running' | 'success' | 'error' | 'skipped'

interface Step {
  id: string
  label: string
  status: StepStatus
  message?: string
}

const INITIAL_STEPS: Step[] = [
  { id: 'connect', label: 'Connect via SSH', status: 'pending' },
  { id: 'stop', label: 'Stop service', status: 'pending' },
  { id: 'check-stopped', label: 'Verify stopped', status: 'pending' },
  { id: 'uninstall', label: 'Uninstall service', status: 'pending' },
  { id: 'check-uninstalled', label: 'Verify uninstalled', status: 'pending' },
  { id: 'remove-binary', label: 'Remove binary', status: 'pending' },
  { id: 'check-removed', label: 'Verify removed', status: 'pending' },
  { id: 'disconnect', label: 'Disconnect', status: 'pending' },
  { id: 'wipe-creds', label: 'Wipe credentials', status: 'pending' },
  { id: 'delete', label: 'Delete node', status: 'pending' },
]

// Steps that require SSH (will be skipped on force delete)
const SSH_STEPS = new Set(['connect', 'stop', 'check-stopped', 'uninstall', 'check-uninstalled', 'remove-binary', 'check-removed', 'disconnect'])

export function RemoveNodeModal({ node, onClose, onDeleted }: RemoveNodeModalProps) {
  const [phase, setPhase] = useState<'confirm' | 'removing' | 'done'>('confirm')
  const [steps, setSteps] = useState<Step[]>(INITIAL_STEPS)
  const [error, setError] = useState<string | null>(null)

  const updateStep = useCallback((id: string, status: StepStatus, message?: string) => {
    setSteps(prev => prev.map(s => s.id === id ? { ...s, status, message } : s))
  }, [])

  const handleRemove = async (forceDelete = false) => {
    setPhase('removing')
    setError(null)

    if (forceDelete) {
      setSteps(prev => prev.map(s =>
        SSH_STEPS.has(s.id) ? { ...s, status: 'skipped', message: 'Skipped' } : { ...s, status: 'pending', message: undefined }
      ))
    } else {
      setSteps(INITIAL_STEPS)
    }

    try {
      if (!forceDelete) {
        // Steps 1-7: SSH operations
        const sshSteps: Array<{ id: string; step?: Parameters<typeof deployStep>[1] }> = [
          { id: 'connect', step: 'connect' },
          { id: 'stop', step: 'stop' },
          { id: 'check-stopped', step: 'check-stopped' },
          { id: 'uninstall', step: 'uninstall' },
          { id: 'check-uninstalled', step: 'check-uninstalled' },
          { id: 'remove-binary', step: 'remove-binary' },
          { id: 'check-removed', step: 'check-removed' },
        ]

        for (const { id, step } of sshSteps) {
          updateStep(id, 'running')
          try {
            const res = await deployStep(node.agent_id, step!)
            if (!res.ok) {
              updateStep(id, 'error', res.message)
              return
            }
            updateStep(id, 'success', res.message)
          } catch {
            updateStep(id, 'error', 'Failed — node may be unreachable')
            return
          }
        }

        // Step 8: Disconnect (visual only — SSH sessions are per-command)
        updateStep('disconnect', 'running')
        await new Promise(r => setTimeout(r, 300))
        updateStep('disconnect', 'success', 'Disconnected')
      }

      // Step 9: Wipe credentials
      updateStep('wipe-creds', 'running')
      try {
        const res = await deployStep(node.agent_id, 'wipe-creds')
        if (!res.ok) {
          updateStep('wipe-creds', 'error', res.message)
          return
        }
        updateStep('wipe-creds', 'success', res.message)
      } catch {
        updateStep('wipe-creds', 'error', 'Failed to wipe credentials')
        return
      }

      // Step 10: Delete node from DB
      updateStep('delete', 'running')
      try {
        await deleteNode(node.agent_id)
        updateStep('delete', 'success', 'Node deleted')
      } catch {
        updateStep('delete', 'error', 'Failed to delete from database')
        return
      }

      setPhase('done')
      onDeleted()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Remove failed')
    }
  }

  const hasFailedStep = steps.some(s => s.status === 'error')
  const sshFailed = steps.some(s => SSH_STEPS.has(s.id) && s.status === 'error')

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={phase === 'confirm' ? onClose : undefined} />
      <div className="relative w-full max-w-md mx-4 rounded-2xl border border-border/50 bg-card shadow-2xl animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-border/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-500/10">
              <Trash2 className="w-4 h-4 text-red-400" />
            </div>
            <h2 className="text-lg font-semibold">
              {phase === 'confirm' ? 'Remove Node' : phase === 'removing' ? 'Removing...' : 'Node Removed'}
            </h2>
          </div>
          {(phase === 'confirm' || phase === 'done' || hasFailedStep) && (
            <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-muted transition-colors">
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Confirm phase */}
        {phase === 'confirm' && (
          <div className="p-5 space-y-4">
            <div className="p-4 rounded-xl bg-red-500/5 border border-red-500/10">
              <p className="text-sm text-foreground">
                Remove <span className="font-semibold">{node.name || node.host || node.agent_id.slice(0, 12)}</span> from monitoring?
              </p>
              <p className="text-xs text-muted-foreground mt-1.5">
                This will stop the Spider, remove the binary, wipe stored SSH keys and sudo password, and delete the node from the database.
              </p>
            </div>

            <div className="flex gap-2">
              <button
                onClick={onClose}
                className="flex-1 py-2.5 rounded-lg bg-secondary text-secondary-foreground text-sm font-medium hover:bg-secondary/80 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleRemove(false)}
                className="flex-1 py-2.5 rounded-lg bg-red-500/90 text-white text-sm font-medium hover:bg-red-500 transition-colors"
              >
                Remove Node
              </button>
            </div>
          </div>
        )}

        {/* Removing / Done phase — stepper */}
        {(phase === 'removing' || phase === 'done') && (
          <div className="p-5">
            <div className="space-y-0 max-h-[420px] overflow-y-auto">
              {steps.map((step, i) => (
                <div key={step.id} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <StepIcon status={step.status} stepId={step.id} />
                    {i < steps.length - 1 && (
                      <div className={`w-px flex-1 min-h-[16px] ${
                        step.status === 'success' ? 'bg-emerald-500/30' :
                        step.status === 'error' ? 'bg-red-500/30' :
                        'bg-border/30'
                      }`} />
                    )}
                  </div>
                  <div className="pb-4 min-w-0">
                    <p className={`text-sm leading-5 ${
                      step.status === 'running' ? 'text-foreground font-medium' :
                      step.status === 'success' ? 'text-emerald-400' :
                      step.status === 'error' ? 'text-red-400 font-medium' :
                      step.status === 'skipped' ? 'text-muted-foreground/50' :
                      'text-muted-foreground'
                    }`}>
                      {step.label}
                    </p>
                    {step.message && (
                      <p className={`text-xs mt-0.5 ${
                        step.status === 'error' ? 'text-red-400/80' : 'text-muted-foreground'
                      }`}>
                        {step.message}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {error && (
              <div className="flex items-center gap-2 p-3 mt-3 rounded-lg bg-red-500/10 border border-red-500/20">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                <p className="text-xs text-red-400">{error}</p>
              </div>
            )}

            <div className="mt-4 flex gap-2">
              {sshFailed && (
                <button
                  onClick={() => handleRemove(true)}
                  className="flex-1 py-2.5 rounded-lg bg-red-500/90 text-white text-sm font-medium hover:bg-red-500 transition-colors"
                >
                  Force Delete
                </button>
              )}
              {(phase === 'done' || hasFailedStep) && (
                <button
                  onClick={onClose}
                  className="flex-1 py-2.5 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
                >
                  {phase === 'done' ? 'Done' : 'Close'}
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function StepIcon({ status, stepId }: { status: StepStatus; stepId: string }) {
  if (status === 'running') {
    return <Loader2 className="w-5 h-5 text-red-400 animate-spin shrink-0" />
  }
  if (status === 'success') {
    return (
      <div className="w-5 h-5 rounded-full bg-emerald-500/20 flex items-center justify-center shrink-0">
        <Check className="w-3 h-3 text-emerald-400" />
      </div>
    )
  }
  if (status === 'error') {
    return (
      <div className="w-5 h-5 rounded-full bg-red-500/20 flex items-center justify-center shrink-0">
        <X className="w-3 h-3 text-red-400" />
      </div>
    )
  }
  if (status === 'skipped') {
    return (
      <div className="w-5 h-5 rounded-full border-2 border-border/20 flex items-center justify-center shrink-0">
        <Minus className="w-3 h-3 text-muted-foreground/40" />
      </div>
    )
  }
  // Pending — show contextual icon
  const iconClass = "w-5 h-5 text-muted-foreground/30 shrink-0"
  switch (stepId) {
    case 'connect': return <Plug className={iconClass} />
    case 'stop': return <Square className={iconClass} />
    case 'check-stopped':
    case 'check-uninstalled':
    case 'check-removed': return <SearchCheck className={iconClass} />
    case 'disconnect': return <Unplug className={iconClass} />
    case 'wipe-creds': return <ShieldOff className={iconClass} />
    case 'delete': return <DatabaseZap className={iconClass} />
    default: return <div className="w-5 h-5 rounded-full border-2 border-border/40 shrink-0" />
  }
}
