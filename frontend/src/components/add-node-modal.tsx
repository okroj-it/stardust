import { useState, useCallback } from "react"
import { addNode, checkNode, deleteNode, deployStep, fetchNodeStats, type AddNodePayload, type CheckNodeResult, type AddNodeResponse } from "@/lib/api"
import { X, Server, Loader2, Check, AlertCircle, Minus } from "lucide-react"

interface AddNodeModalProps {
  onClose: () => void
  onSuccess: () => void
}

type StepStatus = 'pending' | 'running' | 'success' | 'error' | 'skipped'

interface Step {
  id: string
  label: string
  status: StepStatus
  message?: string
}

const INITIAL_STEPS: Step[] = [
  { id: 'connect', label: 'Connecting to server', status: 'pending' },
  { id: 'arch', label: 'Detecting architecture', status: 'pending' },
  { id: 'register', label: 'Registering node', status: 'pending' },
  { id: 'upload', label: 'Uploading agent binary', status: 'pending' },
  { id: 'install', label: 'Installing service', status: 'pending' },
  { id: 'start', label: 'Starting service', status: 'pending' },
  { id: 'verify', label: 'Verifying connection', status: 'pending' },
]

export function AddNodeModal({ onClose, onSuccess }: AddNodeModalProps) {
  const [form, setForm] = useState<AddNodePayload>({
    name: "",
    host: "",
    port: 22,
    ssh_user: "root",
    ssh_key: "",
    sudo_password: "",
  })
  const [phase, setPhase] = useState<'form' | 'deploying' | 'done'>('form')
  const [steps, setSteps] = useState<Step[]>(INITIAL_STEPS)
  const [error, setError] = useState<string | null>(null)
  const [nodeResult, setNodeResult] = useState<AddNodeResponse | null>(null)
  const [manualInstall, setManualInstall] = useState(false)
  const [checkInfo, setCheckInfo] = useState<CheckNodeResult | null>(null)

  const canDeploy = form.name && form.host && form.ssh_user && form.ssh_key

  const updateStep = useCallback((id: string, status: StepStatus, message?: string) => {
    setSteps(prev => prev.map(s => s.id === id ? { ...s, status, message } : s))
  }, [])

  const skipRemaining = useCallback((fromId: string, reason: string) => {
    setSteps(prev => {
      const idx = prev.findIndex(s => s.id === fromId)
      return prev.map((s, i) => i > idx ? { ...s, status: 'skipped', message: reason } : s)
    })
  }, [])

  const handleDeploy = async () => {
    setPhase('deploying')
    setSteps(INITIAL_STEPS)
    setError(null)

    try {
      // Step 1: Check SSH connection
      updateStep('connect', 'running')
      const check = await checkNode({
        host: form.host,
        ssh_user: form.ssh_user,
        ssh_key: form.ssh_key,
        ...(form.port && form.port !== 22 ? { port: form.port } : {}),
        ...(form.sudo_password ? { sudo_password: form.sudo_password } : {}),
      })
      setCheckInfo(check)

      if (!check.connected) {
        updateStep('connect', 'error', check.message)
        return
      }
      updateStep('connect', 'success', 'Connected')

      // Step 2: Architecture
      updateStep('arch', 'running')
      if (!check.arch) {
        updateStep('arch', 'error', 'Could not detect architecture')
        return
      }
      updateStep('arch', 'success', check.arch)

      // Step 3: Register node
      updateStep('register', 'running')
      const payload: AddNodePayload = {
        name: form.name,
        host: form.host,
        ssh_user: form.ssh_user,
        ssh_key: form.ssh_key,
      }
      if (form.port && form.port !== 22) payload.port = form.port
      if (form.sudo_password) payload.sudo_password = form.sudo_password
      const node = await addNode(payload)
      setNodeResult(node)
      updateStep('register', 'success')

      // If no agent binary available, skip deploy steps
      if (!check.agent_available) {
        setManualInstall(true)
        skipRemaining('register', `No agent binary for ${check.arch}`)
        setPhase('done')
        onSuccess()
        return
      }

      // Step 4: Upload binary
      updateStep('upload', 'running')
      const uploadRes = await deployStep(node.id, 'upload', check.arch ?? undefined)
      if (!uploadRes.ok) {
        updateStep('upload', 'error', uploadRes.message)
        await deleteNode(node.id).catch(() => {})
        return
      }
      updateStep('upload', 'success')

      // Step 5: Install service
      updateStep('install', 'running')
      const installRes = await deployStep(node.id, 'install')
      if (!installRes.ok) {
        updateStep('install', 'error', installRes.message)
        await deleteNode(node.id).catch(() => {})
        return
      }
      updateStep('install', 'success')

      // Step 6: Start service
      updateStep('start', 'running')
      const startRes = await deployStep(node.id, 'start')
      if (!startRes.ok) {
        updateStep('start', 'error', startRes.message)
        await deleteNode(node.id).catch(() => {})
        return
      }
      updateStep('start', 'success')

      // Step 7: Verify — poll for stats
      updateStep('verify', 'running', 'Waiting for agent data...')
      let verified = false
      for (let i = 0; i < 8; i++) {
        await new Promise(r => setTimeout(r, 2000))
        const stats = await fetchNodeStats(node.id).catch(() => null)
        if (stats) {
          verified = true
          break
        }
      }
      if (verified) {
        updateStep('verify', 'success', 'Agent reporting data')
      } else {
        updateStep('verify', 'error', 'Timeout — agent may still be starting')
      }

      setPhase('done')
      onSuccess()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Deploy failed')
    }
  }

  const update = (field: keyof AddNodePayload, value: string | number) => {
    setForm(f => ({ ...f, [field]: value }))
  }

  const hasFailedStep = steps.some(s => s.status === 'error')
  const failedBeforeRegister = hasFailedStep && !nodeResult

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={phase === 'form' ? onClose : undefined} />
      <div className="relative w-full max-w-lg mx-4 rounded-2xl border border-border/50 bg-card shadow-2xl animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-border/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Server className="w-4 h-4 text-primary" />
            </div>
            <h2 className="text-lg font-semibold">
              {phase === 'form' ? 'Add Node' : phase === 'deploying' ? 'Deploying...' : 'Deploy Complete'}
            </h2>
          </div>
          {(phase === 'form' || phase === 'done' || hasFailedStep) && (
            <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-muted transition-colors">
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Form phase */}
        {phase === 'form' && (
          <div className="p-5 space-y-4">
            {error && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                <p className="text-xs text-red-400">{error}</p>
              </div>
            )}

            <Field label="Node Name" required>
              <input
                type="text"
                placeholder="my-server"
                value={form.name}
                onChange={e => update("name", e.target.value)}
                required
                className="input"
                autoFocus
              />
            </Field>

            <div className="grid grid-cols-2 gap-3">
              <Field label="Host" required>
                <input
                  type="text"
                  placeholder="192.168.1.50"
                  value={form.host}
                  onChange={e => update("host", e.target.value)}
                  required
                  className="input"
                />
              </Field>
              <Field label="SSH Port">
                <input
                  type="number"
                  placeholder="22"
                  value={form.port ?? 22}
                  onChange={e => update("port", parseInt(e.target.value) || 22)}
                  className="input"
                />
              </Field>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <Field label="SSH User" required>
                <input
                  type="text"
                  placeholder="root"
                  value={form.ssh_user}
                  onChange={e => update("ssh_user", e.target.value)}
                  required
                  className="input"
                />
              </Field>
              {form.ssh_user !== "root" && (
                <Field label="Sudo Password" hint="Optional">
                  <input
                    type="password"
                    placeholder="For privileged ops"
                    value={form.sudo_password}
                    onChange={e => update("sudo_password", e.target.value)}
                    className="input"
                  />
                </Field>
              )}
            </div>

            <Field label="SSH Private Key" required>
              <textarea
                placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
                value={form.ssh_key}
                onChange={e => update("ssh_key", e.target.value)}
                required
                rows={4}
                className="input font-mono text-[11px] resize-none"
              />
            </Field>

            <button
              type="button"
              onClick={handleDeploy}
              disabled={!canDeploy}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              Deploy Agent
            </button>
          </div>
        )}

        {/* Deploying / Done phase — stepper */}
        {(phase === 'deploying' || phase === 'done') && (
          <div className="p-5">
            <div className="space-y-0">
              {steps.map((step, i) => (
                <div key={step.id} className="flex gap-3">
                  {/* Icon + line */}
                  <div className="flex flex-col items-center">
                    <StepIcon status={step.status} />
                    {i < steps.length - 1 && (
                      <div className={`w-px flex-1 min-h-[20px] ${
                        step.status === 'success' ? 'bg-emerald-500/30' :
                        step.status === 'error' ? 'bg-red-500/30' :
                        'bg-border/30'
                      }`} />
                    )}
                  </div>
                  {/* Content */}
                  <div className="pb-5 min-w-0">
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

            {/* Manual install info */}
            {manualInstall && nodeResult && checkInfo?.arch && (
              <div className="mt-4 p-4 rounded-xl bg-muted/30 border border-border/30">
                <p className="text-xs text-muted-foreground mb-2">Manual install on the target node:</p>
                <div className="p-3 rounded-lg bg-background/50 font-mono text-[11px] text-muted-foreground leading-relaxed">
                  <span className="text-emerald-400">$</span> # Copy stardust-spider to the node<br />
                  <span className="text-emerald-400">$</span> sudo cp stardust-spider /usr/local/bin/<br />
                  <span className="text-emerald-400">$</span> sudo chmod +x /usr/local/bin/stardust-spider<br />
                  <span className="text-emerald-400">$</span> stardust-spider \<br />
                  &nbsp;&nbsp;--server wss://stardust.meshnet.lol/ws \<br />
                  &nbsp;&nbsp;--token {nodeResult.token.slice(0, 8)}... \<br />
                  &nbsp;&nbsp;--agent-id {nodeResult.id.slice(0, 8)}...
                </div>
              </div>
            )}

            {/* Buttons */}
            <div className="mt-4 flex gap-2">
              {failedBeforeRegister && (
                <button
                  onClick={() => { setPhase('form'); setError(null); setSteps(INITIAL_STEPS) }}
                  className="flex-1 py-2.5 rounded-lg bg-secondary text-secondary-foreground text-sm font-medium hover:bg-secondary/80 transition-colors"
                >
                  Retry
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

function StepIcon({ status }: { status: StepStatus }) {
  switch (status) {
    case 'pending':
      return <div className="w-5 h-5 rounded-full border-2 border-border/40 shrink-0" />
    case 'running':
      return <Loader2 className="w-5 h-5 text-primary animate-spin shrink-0" />
    case 'success':
      return (
        <div className="w-5 h-5 rounded-full bg-emerald-500/20 flex items-center justify-center shrink-0">
          <Check className="w-3 h-3 text-emerald-400" />
        </div>
      )
    case 'error':
      return (
        <div className="w-5 h-5 rounded-full bg-red-500/20 flex items-center justify-center shrink-0">
          <X className="w-3 h-3 text-red-400" />
        </div>
      )
    case 'skipped':
      return (
        <div className="w-5 h-5 rounded-full border-2 border-border/20 flex items-center justify-center shrink-0">
          <Minus className="w-3 h-3 text-muted-foreground/40" />
        </div>
      )
  }
}

function Field({
  label,
  required,
  hint,
  children,
}: {
  label: string
  required?: boolean
  hint?: string
  children: React.ReactNode
}) {
  return (
    <label className="block">
      <span className="text-xs font-medium text-foreground">
        {label}
        {required && <span className="text-red-400 ml-0.5">*</span>}
      </span>
      {hint && <span className="text-[10px] text-muted-foreground ml-1.5">{hint}</span>}
      <div className="mt-1">{children}</div>
    </label>
  )
}
