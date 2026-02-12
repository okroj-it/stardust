import { useState, useEffect, useRef, useCallback } from "react"
import { deployStep, pkgJobStart, pkgJobPoll, parseUpgradablePackages } from "@/lib/api"
import type { UpgradablePackage, PkgAction } from "@/lib/api"
import { X, Loader2, Check, AlertCircle, Search, ArrowUpCircle, Package } from "lucide-react"

interface TerminalModalProps {
  nodeId: string
  nodePkgManager?: string | null
  onClose: () => void
}

type Phase = 'detecting' | 'ready' | 'checking' | 'packages' | 'upgrading' | 'done' | 'error'

export function TerminalModal({ nodeId, nodePkgManager, onClose }: TerminalModalProps) {
  const [phase, setPhase] = useState<Phase>(nodePkgManager ? 'ready' : 'detecting')
  const [pkgManager, setPkgManager] = useState<string | null>(nodePkgManager ?? null)
  const [output, setOutput] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [packages, setPackages] = useState<UpgradablePackage[]>([])
  const outputRef = useRef<HTMLPreElement>(null)
  const jobRef = useRef<{ id: string; offset: number } | null>(null)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const phaseRef = useRef<Phase>(phase)

  // Keep phaseRef in sync
  useEffect(() => { phaseRef.current = phase }, [phase])

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

  // Detect package manager on mount (if not provided)
  useEffect(() => {
    if (nodePkgManager) return
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
  }, [nodeId, nodePkgManager])

  const poll = useCallback(async () => {
    const job = jobRef.current
    if (!job) return

    try {
      const res = await pkgJobPoll(nodeId, job.id, job.offset)
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

        const currentPhase = phaseRef.current
        if (currentPhase === 'checking') {
          // Parse packages from check-updates output
          if (res.ok && pkgManager) {
            setOutput(prev => {
              const pkgs = parseUpgradablePackages(prev + (res.output || ''), pkgManager)
              setPackages(pkgs)
              if (pkgs.length > 0) {
                setPhase('packages')
              } else {
                setPhase('done')
              }
              return prev
            })
          } else {
            setError("Check for updates failed")
            setPhase('error')
          }
        } else if (currentPhase === 'upgrading') {
          setPhase(res.ok ? 'done' : 'error')
          if (!res.ok) setError("Upgrade failed")
        }
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
  }, [nodeId, pkgManager])

  const startJob = async (action: PkgAction, newPhase: Phase) => {
    if (!pkgManager) return
    setPhase(newPhase)
    setOutput("")
    setError(null)

    try {
      const jobId = await pkgJobStart(nodeId, pkgManager, action)
      jobRef.current = { id: jobId, offset: 0 }
      pollingRef.current = setInterval(poll, 300)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start')
      setPhase('error')
    }
  }

  const handleCheckUpdates = () => startJob('check-updates', 'checking')
  const handleUpgrade = () => startJob('upgrade', 'upgrading')
  const handleFullUpgrade = () => startJob('full-upgrade', 'upgrading')

  const isBlocking = phase === 'detecting' || phase === 'checking' || phase === 'upgrading'
  const showPackman = pkgManager === 'pacman'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={!isBlocking ? onClose : undefined} />
      <div className="relative w-full max-w-3xl mx-4 rounded-2xl border border-border/50 bg-[#0d1117] shadow-2xl animate-in fade-in zoom-in-95 duration-200 flex flex-col max-h-[85vh]">
        {/* Terminal header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border/30 bg-[#161b22] rounded-t-2xl">
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-[#ff5f57]" />
              <div className="w-3 h-3 rounded-full bg-[#febc2e]" />
              <div className="w-3 h-3 rounded-full bg-[#28c840]" />
            </div>
            <span className="text-xs text-[#8b949e] font-mono">
              {pkgManager ? `Package Manager: ${pkgManager}` : 'detecting package manager...'}
            </span>
          </div>
          {!isBlocking && (
            <button onClick={onClose} className="p-1 rounded hover:bg-[#30363d] transition-colors">
              <X className="w-4 h-4 text-[#8b949e]" />
            </button>
          )}
        </div>

        {/* Terminal body */}
        {phase === 'packages' ? (
          <PackageTable packages={packages} pkgManager={pkgManager!} />
        ) : (
          <pre
            ref={outputRef}
            className="flex-1 overflow-auto p-4 font-mono text-[13px] leading-relaxed text-[#c9d1d9] whitespace-pre-wrap break-all min-h-[200px] max-h-[55vh] scrollbar-thin"
          >
            {phase === 'detecting' && (
              <span className="text-[#8b949e] flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin inline" />
                Detecting package manager...
              </span>
            )}
            {phase === 'ready' && (
              <span className="text-[#58a6ff]">
                Package manager: <span className="text-[#7ee787] font-semibold">{pkgManager}</span>
                {'\n\n'}
                <span className="text-[#8b949e]">Click "Check for Updates" to see available package upgrades.</span>
              </span>
            )}
            {(phase === 'checking' || phase === 'upgrading') && !output && (
              <span className="text-[#8b949e] flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin inline" />
                {phase === 'checking' ? 'Checking for updates...' : 'Running upgrade...'}
              </span>
            )}
            {output && (
              <>
                <span className="text-[#58a6ff]">$ {phase === 'upgrading' || phase === 'done' ? 'upgrade' : 'check-updates'}</span>
                {'\n'}
                {output}
                {(phase === 'checking' || phase === 'upgrading') && <span className="animate-pulse">_</span>}
              </>
            )}
            {phase === 'done' && (
              <>
                {output && '\n'}
                <span className="text-[#7ee787]">
                  {packages.length === 0 ? 'All packages are up to date.' : 'Upgrade complete.'}
                </span>
              </>
            )}
            {phase === 'error' && !output && error && (
              <span className="text-[#f85149]">{error}</span>
            )}
          </pre>
        )}

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-border/30 bg-[#161b22] rounded-b-2xl">
          <div className="flex items-center gap-2">
            {phase === 'done' && (
              <span className="flex items-center gap-1.5 text-xs text-[#7ee787]">
                <Check className="w-3.5 h-3.5" />
                Complete
              </span>
            )}
            {phase === 'packages' && (
              <span className="flex items-center gap-1.5 text-xs text-[#58a6ff]">
                <Package className="w-3.5 h-3.5" />
                {packages.length} package{packages.length !== 1 ? 's' : ''} can be upgraded
              </span>
            )}
            {phase === 'error' && error && (
              <span className="flex items-center gap-1.5 text-xs text-[#f85149]">
                <AlertCircle className="w-3.5 h-3.5" />
                {error}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {!isBlocking && (
              <button
                onClick={onClose}
                className="px-3 py-1.5 rounded-lg text-xs text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#30363d] transition-colors"
              >
                Close
              </button>
            )}

            {/* Check for Updates button */}
            {(phase === 'ready' || phase === 'done' || phase === 'error') && pkgManager && (
              <button
                onClick={handleCheckUpdates}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#238636] text-white text-xs font-medium hover:bg-[#2ea043] transition-colors"
              >
                <Search className="w-3.5 h-3.5" />
                Check for Updates
              </button>
            )}

            {/* Upgrade buttons on package list view */}
            {phase === 'packages' && pkgManager && (
              <>
                <button
                  onClick={handleUpgrade}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#238636] text-white text-xs font-medium hover:bg-[#2ea043] transition-colors"
                >
                  <ArrowUpCircle className="w-3.5 h-3.5" />
                  Upgrade
                </button>
                {!showPackman && (
                  <button
                    onClick={handleFullUpgrade}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#9e6a03] text-white text-xs font-medium hover:bg-[#bb8009] transition-colors"
                    title="May remove or replace packages to resolve dependencies"
                  >
                    <ArrowUpCircle className="w-3.5 h-3.5" />
                    Full Upgrade
                  </button>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function PackageTable({ packages, pkgManager }: { packages: UpgradablePackage[]; pkgManager: string }) {
  const showOldVersion = pkgManager !== 'dnf' && pkgManager !== 'yum'

  return (
    <div className="flex-1 overflow-auto min-h-[200px] max-h-[55vh]">
      <table className="w-full text-[13px] font-mono">
        <thead className="sticky top-0 bg-[#161b22] border-b border-border/30">
          <tr className="text-[#8b949e] text-left">
            <th className="px-4 py-2 font-medium">Package</th>
            {showOldVersion && <th className="px-4 py-2 font-medium">Current</th>}
            <th className="px-4 py-2 font-medium">{showOldVersion ? 'Available' : 'Version'}</th>
          </tr>
        </thead>
        <tbody>
          {packages.map((pkg, i) => (
            <tr key={`${pkg.name}-${i}`} className="border-b border-border/10 hover:bg-[#161b22]/50 transition-colors">
              <td className="px-4 py-1.5 text-[#c9d1d9]">{pkg.name}</td>
              {showOldVersion && <td className="px-4 py-1.5 text-[#8b949e]">{pkg.oldVersion}</td>}
              <td className="px-4 py-1.5 text-[#7ee787]">{pkg.newVersion}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
