import { useState, useEffect, useRef, useCallback } from "react"
import { deployStep, pkgJobStart, pkgJobPoll, parseUpgradablePackages } from "@/lib/api"
import type { UpgradablePackage, PkgAction } from "@/lib/api"
import { X, Loader2, Check, AlertCircle, Search, ArrowUpCircle, Package, Trash2, Download, List } from "lucide-react"

interface TerminalModalProps {
  nodeId: string
  nodePkgManager?: string | null
  onClose: () => void
}

type Tab = 'upgrades' | 'installed' | 'search'

type Phase =
  | 'detecting' | 'ready'
  // Upgrades
  | 'checking' | 'packages' | 'upgrading'
  // Installed
  | 'listing' | 'installed'
  // Search
  | 'searching' | 'search-results'
  // Actions
  | 'installing' | 'removing'
  | 'done' | 'error'

interface InstalledPkg {
  name: string
  version: string
}

interface SearchResult {
  name: string
  description: string
}

export function TerminalModal({ nodeId, nodePkgManager, onClose }: TerminalModalProps) {
  const [phase, setPhase] = useState<Phase>(nodePkgManager ? 'ready' : 'detecting')
  const [pkgManager, setPkgManager] = useState<string | null>(nodePkgManager ?? null)
  const [output, setOutput] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('upgrades')

  // Upgrades state
  const [packages, setPackages] = useState<UpgradablePackage[]>([])

  // Installed state
  const [installedPkgs, setInstalledPkgs] = useState<InstalledPkg[]>([])
  const [installedFilter, setInstalledFilter] = useState("")

  // Search state
  const [searchQuery, setSearchQuery] = useState("")
  const [searchResults, setSearchResults] = useState<SearchResult[]>([])

  // Action feedback
  const [actionPkg, setActionPkg] = useState<string | null>(null)
  const [actionOutput, setActionOutput] = useState("")

  const outputRef = useRef<HTMLPreElement>(null)
  const jobRef = useRef<{ id: string; offset: number } | null>(null)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const phaseRef = useRef<Phase>(phase)

  useEffect(() => { phaseRef.current = phase }, [phase])

  // Auto-scroll output
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [output, actionOutput])

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [])

  // Detect package manager on mount
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

  const stopPolling = useCallback(() => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current)
      pollingRef.current = null
    }
    jobRef.current = null
  }, [])

  const poll = useCallback(async () => {
    const job = jobRef.current
    if (!job) return

    try {
      const res = await pkgJobPoll(nodeId, job.id, job.offset)
      if (res.output) {
        const currentPhase = phaseRef.current
        if (currentPhase === 'installing' || currentPhase === 'removing') {
          setActionOutput(prev => prev + res.output)
        } else {
          setOutput(prev => prev + res.output)
        }
      }
      job.offset = res.offset

      if (res.done) {
        stopPolling()
        const currentPhase = phaseRef.current

        if (currentPhase === 'checking') {
          if (res.ok && pkgManager) {
            // Note: res.output already appended above, just parse current accumulated output
            setOutput(prev => {
              const pkgs = parseUpgradablePackages(prev, pkgManager)
              setPackages(pkgs)
              setPhase(pkgs.length > 0 ? 'packages' : 'done')
              return prev
            })
          } else {
            setError("Check for updates failed")
            setPhase('error')
          }
        } else if (currentPhase === 'upgrading') {
          setPhase(res.ok ? 'done' : 'error')
          if (!res.ok) setError("Upgrade failed")
        } else if (currentPhase === 'listing') {
          // Note: res.output already appended above, just parse current accumulated output
          setOutput(prev => {
            const pkgs = parseInstalledPackages(prev, pkgManager || '')
            setInstalledPkgs(pkgs)
            setPhase('installed')
            return prev
          })
        } else if (currentPhase === 'searching') {
          // Note: res.output already appended above, just parse current accumulated output
          setOutput(prev => {
            const results = parseSearchResults(prev, pkgManager || '')
            setSearchResults(results)
            setPhase('search-results')
            return prev
          })
        } else if (currentPhase === 'installing') {
          if (res.ok) {
            setActionPkg(null)
            setActionOutput("")
            // Refresh installed list if on installed tab
            if (tab === 'installed') {
              loadInstalled()
            } else {
              setPhase('search-results')
            }
          } else {
            setError(`Install failed`)
            setPhase('error')
          }
        } else if (currentPhase === 'removing') {
          if (res.ok) {
            setActionPkg(null)
            setActionOutput("")
            loadInstalled()
          } else {
            setError(`Remove failed`)
            setPhase('error')
          }
        }
      }
    } catch {
      stopPolling()
      setError("Polling failed")
      setPhase('error')
    }
  }, [nodeId, pkgManager, tab])

  const startJob = useCallback(async (action: PkgAction, newPhase: Phase) => {
    if (!pkgManager) return
    stopPolling()
    setPhase(newPhase)
    if (newPhase !== 'installing' && newPhase !== 'removing') {
      setOutput("")
    }
    setError(null)

    try {
      const jobId = await pkgJobStart(nodeId, pkgManager, action)
      jobRef.current = { id: jobId, offset: 0 }
      pollingRef.current = setInterval(poll, 300)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start')
      setPhase('error')
    }
  }, [nodeId, pkgManager, poll, stopPolling])

  const loadInstalled = useCallback(() => {
    startJob('list-installed', 'listing')
  }, [startJob])

  // Switch tabs
  const handleTabSwitch = useCallback((newTab: Tab) => {
    if (newTab === tab) return
    stopPolling()
    setTab(newTab)
    setError(null)
    setActionPkg(null)
    setActionOutput("")

    if (newTab === 'upgrades') {
      if (packages.length > 0) {
        setPhase('packages')
      } else {
        setPhase('ready')
        setOutput("")
      }
    } else if (newTab === 'installed') {
      setOutput("")
      loadInstalled()
    } else if (newTab === 'search') {
      setOutput("")
      setSearchResults([])
      setPhase('ready')
    }
  }, [tab, packages, stopPolling, loadInstalled])

  const handleCheckUpdates = () => startJob('check-updates', 'checking')
  const handleUpgrade = () => startJob('upgrade', 'upgrading')
  const handleFullUpgrade = () => startJob('full-upgrade', 'upgrading')

  const handleSearch = () => {
    if (!searchQuery.trim()) return
    setSearchResults([])
    startJob(`search:${searchQuery.trim()}`, 'searching')
  }

  const handleInstall = (pkg: string) => {
    setActionPkg(pkg)
    setActionOutput("")
    startJob(`install:${pkg}`, 'installing')
  }

  const handleRemove = (pkg: string) => {
    setActionPkg(pkg)
    setActionOutput("")
    startJob(`remove:${pkg}`, 'removing')
  }

  const isBlocking = phase === 'detecting' || phase === 'checking' || phase === 'upgrading'
    || phase === 'listing' || phase === 'searching' || phase === 'installing' || phase === 'removing'
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

        {/* Tab bar */}
        {pkgManager && phase !== 'detecting' && (
          <div className="flex border-b border-border/30 bg-[#161b22]">
            {([
              { key: 'upgrades' as Tab, label: 'Upgrades', icon: ArrowUpCircle },
              { key: 'installed' as Tab, label: 'Installed', icon: List },
              { key: 'search' as Tab, label: 'Search', icon: Search },
            ]).map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => handleTabSwitch(key)}
                disabled={isBlocking}
                className={`flex items-center gap-1.5 px-4 py-2 text-xs font-medium transition-colors border-b-2 ${
                  tab === key
                    ? 'text-[#58a6ff] border-[#58a6ff]'
                    : 'text-[#8b949e] border-transparent hover:text-[#c9d1d9] hover:border-[#30363d]'
                } ${isBlocking ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                <Icon className="w-3.5 h-3.5" />
                {label}
              </button>
            ))}
          </div>
        )}

        {/* Action overlay */}
        {(phase === 'installing' || phase === 'removing') && actionPkg && (
          <div className="px-4 py-2 bg-[#1c2333] border-b border-border/30 flex items-center gap-2">
            <Loader2 className="w-3.5 h-3.5 animate-spin text-[#58a6ff]" />
            <span className="text-xs text-[#c9d1d9] font-mono">
              {phase === 'installing' ? 'Installing' : 'Removing'} <span className="text-[#7ee787]">{actionPkg}</span>...
            </span>
            {actionOutput && (
              <pre className="text-xs text-[#8b949e] font-mono truncate ml-2 flex-1">
                {actionOutput.split('\n').filter(Boolean).slice(-1)[0]}
              </pre>
            )}
          </div>
        )}

        {/* Body */}
        {tab === 'upgrades' && (
          <UpgradesBody
            phase={phase}
            output={output}
            error={error}
            packages={packages}
            pkgManager={pkgManager}
            outputRef={outputRef}
          />
        )}
        {tab === 'installed' && (
          <InstalledBody
            phase={phase}
            installedPkgs={installedPkgs}
            filter={installedFilter}
            onFilterChange={setInstalledFilter}
            onRemove={handleRemove}
            isActioning={phase === 'removing'}
          />
        )}
        {tab === 'search' && (
          <SearchBody
            phase={phase}
            searchQuery={searchQuery}
            onQueryChange={setSearchQuery}
            onSearch={handleSearch}
            searchResults={searchResults}
            onInstall={handleInstall}
            isActioning={phase === 'installing'}
            output={output}
            outputRef={outputRef}
          />
        )}

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-border/30 bg-[#161b22] rounded-b-2xl">
          <div className="flex items-center gap-2">
            {phase === 'done' && tab === 'upgrades' && (
              <span className="flex items-center gap-1.5 text-xs text-[#7ee787]">
                <Check className="w-3.5 h-3.5" />
                {packages.length === 0 ? 'All packages are up to date' : 'Upgrade complete'}
              </span>
            )}
            {phase === 'packages' && (
              <span className="flex items-center gap-1.5 text-xs text-[#58a6ff]">
                <Package className="w-3.5 h-3.5" />
                {packages.length} package{packages.length !== 1 ? 's' : ''} can be upgraded
              </span>
            )}
            {phase === 'installed' && (
              <span className="flex items-center gap-1.5 text-xs text-[#8b949e]">
                <Package className="w-3.5 h-3.5" />
                {installedPkgs.length} installed package{installedPkgs.length !== 1 ? 's' : ''}
              </span>
            )}
            {phase === 'search-results' && (
              <span className="flex items-center gap-1.5 text-xs text-[#8b949e]">
                <Search className="w-3.5 h-3.5" />
                {searchResults.length} result{searchResults.length !== 1 ? 's' : ''}
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

            {/* Upgrades tab buttons */}
            {tab === 'upgrades' && (phase === 'ready' || phase === 'done' || phase === 'error') && pkgManager && (
              <button
                onClick={handleCheckUpdates}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#238636] text-white text-xs font-medium hover:bg-[#2ea043] transition-colors"
              >
                <Search className="w-3.5 h-3.5" />
                Check for Updates
              </button>
            )}
            {tab === 'upgrades' && phase === 'packages' && pkgManager && (
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

            {/* Installed tab refresh */}
            {tab === 'installed' && phase === 'installed' && (
              <button
                onClick={loadInstalled}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#30363d] text-[#c9d1d9] text-xs font-medium hover:bg-[#3d444d] transition-colors"
              >
                <List className="w-3.5 h-3.5" />
                Refresh
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// --- Upgrades Tab Body ---

function UpgradesBody({
  phase, output, error, packages, pkgManager, outputRef
}: {
  phase: Phase
  output: string
  error: string | null
  packages: UpgradablePackage[]
  pkgManager: string | null
  outputRef: React.RefObject<HTMLPreElement | null>
}) {
  if (phase === 'packages') {
    return <PackageTable packages={packages} pkgManager={pkgManager!} />
  }

  return (
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
  )
}

// --- Package Table (upgradable packages) ---

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

// --- Installed Tab Body ---

function InstalledBody({
  phase, installedPkgs, filter, onFilterChange, onRemove, isActioning
}: {
  phase: Phase
  installedPkgs: InstalledPkg[]
  filter: string
  onFilterChange: (v: string) => void
  onRemove: (pkg: string) => void
  isActioning: boolean
}) {
  if (phase === 'listing') {
    return (
      <div className="flex-1 flex items-center justify-center min-h-[200px] max-h-[55vh]">
        <span className="text-[#8b949e] flex items-center gap-2 text-sm">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading installed packages...
        </span>
      </div>
    )
  }

  const filtered = filter
    ? installedPkgs.filter(p => p.name.toLowerCase().includes(filter.toLowerCase()))
    : installedPkgs

  return (
    <div className="flex-1 flex flex-col min-h-[200px] max-h-[55vh]">
      {/* Search filter */}
      <div className="px-4 py-2 border-b border-border/30 bg-[#0d1117]">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#484f58]" />
          <input
            type="text"
            value={filter}
            onChange={e => onFilterChange(e.target.value)}
            placeholder="Filter installed packages..."
            className="w-full pl-8 pr-3 py-1.5 bg-[#0d1117] border border-border/30 rounded-lg text-xs text-[#c9d1d9] font-mono placeholder:text-[#484f58] focus:outline-none focus:border-[#58a6ff]/50"
          />
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-[13px] font-mono">
          <thead className="sticky top-0 bg-[#161b22] border-b border-border/30">
            <tr className="text-[#8b949e] text-left">
              <th className="px-4 py-2 font-medium">Package</th>
              <th className="px-4 py-2 font-medium">Version</th>
              <th className="px-4 py-2 font-medium w-20"></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((pkg, i) => (
              <tr key={`${pkg.name}-${i}`} className="border-b border-border/10 hover:bg-[#161b22]/50 transition-colors group">
                <td className="px-4 py-1.5 text-[#c9d1d9]">{pkg.name}</td>
                <td className="px-4 py-1.5 text-[#8b949e]">{pkg.version}</td>
                <td className="px-4 py-1.5">
                  <button
                    onClick={() => onRemove(pkg.name)}
                    disabled={isActioning}
                    className="opacity-0 group-hover:opacity-100 flex items-center gap-1 px-2 py-0.5 rounded text-[11px] text-[#f85149] hover:bg-[#f8514920] transition-all disabled:opacity-30"
                    title={`Uninstall ${pkg.name}`}
                  >
                    <Trash2 className="w-3 h-3" />
                    Remove
                  </button>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={3} className="px-4 py-8 text-center text-[#484f58] text-xs">
                  {filter ? 'No packages match filter' : 'No packages found'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// --- Search Tab Body ---

function SearchBody({
  phase, searchQuery, onQueryChange, onSearch, searchResults, onInstall, isActioning, output, outputRef
}: {
  phase: Phase
  searchQuery: string
  onQueryChange: (v: string) => void
  onSearch: () => void
  searchResults: SearchResult[]
  onInstall: (pkg: string) => void
  isActioning: boolean
  output: string
  outputRef: React.RefObject<HTMLPreElement | null>
}) {
  return (
    <div className="flex-1 flex flex-col min-h-[200px] max-h-[55vh]">
      {/* Search bar */}
      <div className="px-4 py-2 border-b border-border/30 bg-[#0d1117]">
        <form
          onSubmit={e => { e.preventDefault(); onSearch() }}
          className="flex gap-2"
        >
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#484f58]" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => onQueryChange(e.target.value)}
              placeholder="Search packages..."
              className="w-full pl-8 pr-3 py-1.5 bg-[#0d1117] border border-border/30 rounded-lg text-xs text-[#c9d1d9] font-mono placeholder:text-[#484f58] focus:outline-none focus:border-[#58a6ff]/50"
              disabled={phase === 'searching'}
            />
          </div>
          <button
            type="submit"
            disabled={!searchQuery.trim() || phase === 'searching'}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#238636] text-white text-xs font-medium hover:bg-[#2ea043] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {phase === 'searching' ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Search className="w-3.5 h-3.5" />
            )}
            Search
          </button>
        </form>
      </div>

      {/* Results */}
      {phase === 'searching' ? (
        <pre
          ref={outputRef}
          className="flex-1 overflow-auto p-4 font-mono text-[13px] leading-relaxed text-[#c9d1d9] whitespace-pre-wrap break-all scrollbar-thin"
        >
          <span className="text-[#58a6ff]">$ search {searchQuery}</span>
          {'\n'}
          {output}
          <span className="animate-pulse">_</span>
        </pre>
      ) : phase === 'search-results' && searchResults.length > 0 ? (
        <div className="flex-1 overflow-auto">
          <table className="w-full text-[13px] font-mono">
            <thead className="sticky top-0 bg-[#161b22] border-b border-border/30">
              <tr className="text-[#8b949e] text-left">
                <th className="px-4 py-2 font-medium">Package</th>
                <th className="px-4 py-2 font-medium">Description</th>
                <th className="px-4 py-2 font-medium w-20"></th>
              </tr>
            </thead>
            <tbody>
              {searchResults.map((r, i) => (
                <tr key={`${r.name}-${i}`} className="border-b border-border/10 hover:bg-[#161b22]/50 transition-colors group">
                  <td className="px-4 py-1.5 text-[#c9d1d9] whitespace-nowrap">{r.name}</td>
                  <td className="px-4 py-1.5 text-[#8b949e] text-[12px] truncate max-w-[300px]">{r.description}</td>
                  <td className="px-4 py-1.5">
                    <button
                      onClick={() => onInstall(r.name)}
                      disabled={isActioning}
                      className="opacity-0 group-hover:opacity-100 flex items-center gap-1 px-2 py-0.5 rounded text-[11px] text-[#7ee787] hover:bg-[#7ee78720] transition-all disabled:opacity-30"
                      title={`Install ${r.name}`}
                    >
                      <Download className="w-3 h-3" />
                      Install
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : phase === 'search-results' && searchResults.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <span className="text-[#484f58] text-xs">No packages found for "{searchQuery}"</span>
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center">
          <span className="text-[#484f58] text-xs">Search for packages to install</span>
        </div>
      )}
    </div>
  )
}

// --- Output Parsers ---

function parseInstalledPackages(output: string, pkgManager: string): InstalledPkg[] {
  const pkgs: InstalledPkg[] = []
  for (const line of output.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed) continue

    if (pkgManager === 'apk') {
      // apk list -I: "package-version-r0 x86_64 {origin} (license) [installed]"
      const match = trimmed.match(/^(\S+?)-(\d\S*)\s/)
      if (match) {
        pkgs.push({ name: match[1], version: match[2] })
      }
    } else {
      // dpkg/rpm/pacman: "name\tversion" or "name version"
      const parts = trimmed.split(/\t+|\s{2,}/)
      if (parts.length >= 2) {
        pkgs.push({ name: parts[0].trim(), version: parts[1].trim() })
      } else {
        // pacman: "name version" (single space)
        const spaceIdx = trimmed.indexOf(' ')
        if (spaceIdx > 0) {
          pkgs.push({ name: trimmed.slice(0, spaceIdx), version: trimmed.slice(spaceIdx + 1).trim() })
        }
      }
    }
  }
  return pkgs.sort((a, b) => a.name.localeCompare(b.name))
}

function parseSearchResults(output: string, pkgManager: string): SearchResult[] {
  const results: SearchResult[] = []

  if (pkgManager === 'apt') {
    // apt-cache search: "package-name - description"
    for (const line of output.split('\n')) {
      const match = line.match(/^(\S+)\s+-\s+(.+)/)
      if (match) {
        results.push({ name: match[1], description: match[2] })
      }
    }
  } else if (pkgManager === 'dnf' || pkgManager === 'yum') {
    // dnf search: "name.arch : description" (possibly multi-line)
    const lines = output.split('\n')
    for (let i = 0; i < lines.length; i++) {
      const match = lines[i].match(/^(\S+?)\.(\S+)\s+:\s+(.+)/)
      if (match) {
        let desc = match[3]
        // Collect continuation lines
        while (i + 1 < lines.length && lines[i + 1].match(/^\s+:\s+/)) {
          i++
          desc += ' ' + lines[i].replace(/^\s+:\s+/, '')
        }
        results.push({ name: match[1], description: desc })
      }
    }
  } else if (pkgManager === 'pacman') {
    // pacman -Ss: "repo/name version\n    description"
    const lines = output.split('\n')
    for (let i = 0; i < lines.length; i++) {
      const match = lines[i].match(/^(\S+)\/(\S+)\s+(\S+)/)
      if (match) {
        const desc = (i + 1 < lines.length && lines[i + 1].startsWith('    '))
          ? lines[i + 1].trim()
          : ''
        results.push({ name: match[2], description: desc })
        if (desc) i++
      }
    }
  } else if (pkgManager === 'apk') {
    // apk search: "package-version - description" or just "package-version"
    for (const line of output.split('\n')) {
      const trimmed = line.trim()
      if (!trimmed) continue
      const match = trimmed.match(/^(\S+?)-(\d\S*)\s+-\s+(.+)/)
      if (match) {
        results.push({ name: match[1], description: match[3] })
      } else {
        // Just package name, no description
        const nameMatch = trimmed.match(/^(\S+?)-(\d\S*)$/)
        if (nameMatch) {
          results.push({ name: nameMatch[1], description: '' })
        }
      }
    }
  }

  return results
}
