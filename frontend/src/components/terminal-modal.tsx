import { useState, useEffect, useRef, useCallback } from "react"
import { deployStep, pkgRefreshStart, pkgRefreshPoll } from "@/lib/api"
import { X, Loader2, RefreshCw, Check, AlertCircle } from "lucide-react"

interface TerminalModalProps {
  nodeId: string
  onClose: () => void
}

type Phase = 'detecting' | 'ready' | 'running' | 'done' | 'error'

export function TerminalModal({ nodeId, onClose }: TerminalModalProps) {
  const [phase, setPhase] = useState<Phase>('detecting')
  const [pkgManager, setPkgManager] = useState<string | null>(null)
  const [output, setOutput] = useState("")
  const [error, setError] = useState<string | null>(null)
  const outputRef = useRef<HTMLPreElement>(null)
  const jobRef = useRef<{ id: string; offset: number } | null>(null)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Auto-scroll to bottom
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [output])

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [])

  // Detect package manager on mount
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const res = await deployStep(nodeId, 'detect-pkg-manager')
        if (cancelled) return
        if (res.ok) {
          setPkgManager(res.message)
          setPhase('ready')
        } else {
          setError(res.message)
          setPhase('error')
        }
      } catch (err) {
        if (cancelled) return
        setError(err instanceof Error ? err.message : 'Detection failed')
        setPhase('error')
      }
    })()
    return () => { cancelled = true }
  }, [nodeId])

  const poll = useCallback(async () => {
    const job = jobRef.current
    if (!job) return

    try {
      const res = await pkgRefreshPoll(nodeId, job.id, job.offset)
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
        if (!res.ok) setError("Command failed")
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
  }, [nodeId])

  const handleRefresh = async () => {
    if (!pkgManager) return
    setPhase('running')
    setOutput("")
    setError(null)

    try {
      const jobId = await pkgRefreshStart(nodeId, pkgManager)
      jobRef.current = { id: jobId, offset: 0 }
      pollingRef.current = setInterval(poll, 300)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start')
      setPhase('error')
    }
  }

  const pkgLabel = pkgManager === 'apt' ? 'apt update'
    : pkgManager === 'dnf' ? 'dnf check-update'
    : pkgManager === 'yum' ? 'yum check-update'
    : pkgManager === 'pacman' ? 'pacman -Sy'
    : pkgManager === 'apk' ? 'apk update'
    : pkgManager ?? 'unknown'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={phase !== 'running' ? onClose : undefined} />
      <div className="relative w-full max-w-2xl mx-4 rounded-2xl border border-border/50 bg-[#0d1117] shadow-2xl animate-in fade-in zoom-in-95 duration-200 flex flex-col max-h-[80vh]">
        {/* Terminal header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border/30 bg-[#161b22] rounded-t-2xl">
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-[#ff5f57]" />
              <div className="w-3 h-3 rounded-full bg-[#febc2e]" />
              <div className="w-3 h-3 rounded-full bg-[#28c840]" />
            </div>
            <span className="text-xs text-[#8b949e] font-mono">
              {pkgManager ? `sudo ${pkgLabel}` : 'detecting package manager...'}
            </span>
          </div>
          {phase !== 'running' && (
            <button onClick={onClose} className="p-1 rounded hover:bg-[#30363d] transition-colors">
              <X className="w-4 h-4 text-[#8b949e]" />
            </button>
          )}
        </div>

        {/* Terminal body */}
        <pre
          ref={outputRef}
          className="flex-1 overflow-auto p-4 font-mono text-[13px] leading-relaxed text-[#c9d1d9] whitespace-pre-wrap break-all min-h-[200px] max-h-[50vh] scrollbar-thin"
        >
          {phase === 'detecting' && (
            <span className="text-[#8b949e] flex items-center gap-2">
              <Loader2 className="w-3.5 h-3.5 animate-spin inline" />
              Detecting package manager...
            </span>
          )}
          {phase === 'ready' && (
            <span className="text-[#58a6ff]">
              Detected: <span className="text-[#7ee787] font-semibold">{pkgManager}</span>
              {'\n\n'}
              <span className="text-[#8b949e]">Press "Run" to execute </span>
              <span className="text-[#c9d1d9]">sudo {pkgLabel}</span>
            </span>
          )}
          {phase === 'running' && !output && (
            <span className="text-[#8b949e] flex items-center gap-2">
              <Loader2 className="w-3.5 h-3.5 animate-spin inline" />
              Running sudo {pkgLabel}...
            </span>
          )}
          {output && (
            <>
              <span className="text-[#58a6ff]">$ sudo {pkgLabel}</span>
              {'\n'}
              {output}
              {phase === 'running' && <span className="animate-pulse">_</span>}
            </>
          )}
          {phase === 'error' && !output && error && (
            <span className="text-[#f85149]">{error}</span>
          )}
        </pre>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-border/30 bg-[#161b22] rounded-b-2xl">
          <div className="flex items-center gap-2">
            {phase === 'done' && (
              <span className="flex items-center gap-1.5 text-xs text-[#7ee787]">
                <Check className="w-3.5 h-3.5" />
                Complete
              </span>
            )}
            {phase === 'error' && error && output && (
              <span className="flex items-center gap-1.5 text-xs text-[#f85149]">
                <AlertCircle className="w-3.5 h-3.5" />
                {error}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {phase !== 'running' && phase !== 'detecting' && (
              <button
                onClick={onClose}
                className="px-3 py-1.5 rounded-lg text-xs text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#30363d] transition-colors"
              >
                Close
              </button>
            )}
            {(phase === 'ready' || phase === 'done' || phase === 'error') && pkgManager && (
              <button
                onClick={handleRefresh}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#238636] text-white text-xs font-medium hover:bg-[#2ea043] transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                {phase === 'ready' ? 'Run' : 'Run Again'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
