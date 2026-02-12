import { useState, useEffect, useCallback } from "react"
import { securityScan } from "@/lib/api"
import type { SecurityScanResult } from "@/lib/api"
import {
  X,
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Package,
  Lock,
  Wifi,
  RefreshCw,
  Loader2,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Server,
} from "lucide-react"

interface SecurityPostureProps {
  nodeId: string
  nodeName: string
  onClose: () => void
}

type Tab = 'overview' | 'packages' | 'ssh' | 'firewall' | 'updates'

const TAB_CONFIG = {
  overview: { label: 'Overview', icon: Shield },
  packages: { label: 'Packages', icon: Package },
  ssh: { label: 'SSH Config', icon: Lock },
  firewall: { label: 'Ports & Firewall', icon: Wifi },
  updates: { label: 'Auto-Updates', icon: Server },
} as const

export function SecurityPosture({ nodeId, nodeName, onClose }: SecurityPostureProps) {
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<SecurityScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<Tab>('overview')

  const runScan = useCallback(async () => {
    setScanning(true)
    setError(null)
    try {
      const data = await securityScan(nodeId)
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed')
    } finally {
      setScanning(false)
    }
  }, [nodeId])

  // Auto-scan on mount
  useEffect(() => { runScan() }, [runScan])

  const scoreColor = (score: number) => {
    if (score >= 70) return 'text-emerald-400'
    if (score >= 40) return 'text-amber-400'
    return 'text-red-400'
  }

  const scoreRingColor = (score: number) => {
    if (score >= 70) return 'stroke-emerald-400'
    if (score >= 40) return 'stroke-amber-400'
    return 'stroke-red-400'
  }

  const scoreBg = (score: number) => {
    if (score >= 70) return 'bg-emerald-500/10 border-emerald-500/20'
    if (score >= 40) return 'bg-amber-500/10 border-amber-500/20'
    return 'bg-red-500/10 border-red-500/20'
  }

  const ScoreIcon = (score: number) => {
    if (score >= 70) return ShieldCheck
    if (score >= 40) return ShieldAlert
    return ShieldX
  }

  const statusBadge = (status: string) => {
    switch (status) {
      case 'pass': return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"><CheckCircle className="w-3 h-3" />Pass</span>
      case 'warn': return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20"><AlertTriangle className="w-3 h-3" />Warn</span>
      case 'fail': return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/20"><XCircle className="w-3 h-3" />Fail</span>
      default: return null
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-5xl h-[85vh] flex flex-col rounded-2xl border border-border/50 bg-[#0d1117] shadow-2xl animate-in fade-in zoom-in-95 duration-200 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border/30 bg-[#161b22]">
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-[#ff5f57]" />
              <div className="w-3 h-3 rounded-full bg-[#febc2e]" />
              <div className="w-3 h-3 rounded-full bg-[#28c840]" />
            </div>
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-red-400" />
              <span className="text-sm font-medium text-foreground">Security</span>
              <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/20">
                {nodeName}
              </span>
              {result && !scanning && (
                <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${scoreBg(result.score)} ${scoreColor(result.score)}`}>
                  {result.score}/100
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={runScan}
              disabled={scanning}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-white/5 text-muted-foreground hover:text-foreground hover:bg-white/10 transition-colors disabled:opacity-50"
            >
              {scanning ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <RefreshCw className="w-3.5 h-3.5" />
              )}
              {scanning ? 'Scanning...' : 'Re-scan'}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex px-4 border-b border-border/30 bg-[#161b22]/50">
          {(Object.entries(TAB_CONFIG) as [Tab, typeof TAB_CONFIG[Tab]][]).map(([key, config]) => {
            const Icon = config.icon
            let badge: string | null = null
            if (result) {
              if (key === 'packages') badge = `${result.upgradable.length}`
              else if (key === 'ssh') badge = `${result.ssh_config.filter(c => c.status === 'pass').length}/${result.ssh_config.length}`
              else if (key === 'firewall') badge = `${result.ports.length}`
            }
            return (
              <button
                key={key}
                onClick={() => setActiveTab(key)}
                className={`flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium border-b-2 transition-colors ${
                  activeTab === key
                    ? 'border-red-400 text-red-400'
                    : 'border-transparent text-muted-foreground hover:text-foreground'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {config.label}
                {badge !== null && (
                  <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-white/5">{badge}</span>
                )}
              </button>
            )
          })}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-4">
          {error ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <ShieldX className="w-8 h-8 mx-auto mb-2 text-red-400 opacity-50" />
                <p className="text-sm text-red-400 mb-2">{error}</p>
                <button onClick={runScan} className="text-xs text-muted-foreground hover:text-foreground transition-colors">
                  Try again
                </button>
              </div>
            </div>
          ) : scanning && !result ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <Loader2 className="w-8 h-8 mx-auto mb-2 text-red-400 animate-spin" />
                <p className="text-sm text-muted-foreground">Running security scan via SSH...</p>
              </div>
            </div>
          ) : result ? (
            <>
              {activeTab === 'overview' && <OverviewTab result={result} scoreColor={scoreColor} scoreRingColor={scoreRingColor} ScoreIcon={ScoreIcon} onTabChange={setActiveTab} />}
              {activeTab === 'packages' && <PackagesTab result={result} />}
              {activeTab === 'ssh' && <SshConfigTab result={result} statusBadge={statusBadge} />}
              {activeTab === 'firewall' && <FirewallTab result={result} />}
              {activeTab === 'updates' && <AutoUpdatesTab result={result} />}
            </>
          ) : null}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 border-t border-border/30 bg-[#161b22]/50 flex items-center justify-between">
          <div className="flex items-center gap-2">
            {scanning && (
              <div className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />
                <span className="text-xs text-muted-foreground">Scanning</span>
              </div>
            )}
            {!scanning && result && (
              <span className="text-xs text-muted-foreground">Scan complete</span>
            )}
          </div>
          <span className="text-xs text-muted-foreground font-mono">{nodeName}</span>
        </div>
      </div>
    </div>
  )
}

// --- Tab Components ---

function OverviewTab({ result, scoreColor, scoreRingColor, ScoreIcon, onTabChange }: {
  result: SecurityScanResult
  scoreColor: (s: number) => string
  scoreRingColor: (s: number) => string
  ScoreIcon: (s: number) => React.ComponentType<{ className?: string }>
  onTabChange: (tab: Tab) => void
}) {
  const Icon = ScoreIcon(result.score)
  const sshPassed = result.ssh_config.filter(c => c.status === 'pass').length
  const sshTotal = result.ssh_config.length

  const circumference = 2 * Math.PI * 45
  const offset = circumference - (result.score / 100) * circumference

  return (
    <div className="space-y-6">
      {/* Score Circle */}
      <div className="flex items-center justify-center py-4">
        <div className="relative w-40 h-40">
          <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="45" fill="none" stroke="currentColor" strokeWidth="6" className="text-white/5" />
            <circle
              cx="50" cy="50" r="45" fill="none" strokeWidth="6"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              className={`${scoreRingColor(result.score)} transition-all duration-1000`}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <Icon className={`w-6 h-6 mb-1 ${scoreColor(result.score)}`} />
            <span className={`text-3xl font-bold ${scoreColor(result.score)}`}>{result.score}</span>
            <span className="text-xs text-muted-foreground">/100</span>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <button
          onClick={() => onTabChange('packages')}
          className={`p-4 rounded-xl border text-left transition-colors hover:bg-white/5 ${
            result.upgradable.length === 0 ? 'border-emerald-500/20 bg-emerald-500/5' : 'border-amber-500/20 bg-amber-500/5'
          }`}
        >
          <Package className={`w-5 h-5 mb-2 ${result.upgradable.length === 0 ? 'text-emerald-400' : 'text-amber-400'}`} />
          <div className="text-lg font-bold text-foreground">{result.upgradable.length}</div>
          <div className="text-xs text-muted-foreground">Upgradable packages</div>
        </button>

        <button
          onClick={() => onTabChange('ssh')}
          className={`p-4 rounded-xl border text-left transition-colors hover:bg-white/5 ${
            sshPassed === sshTotal ? 'border-emerald-500/20 bg-emerald-500/5' : 'border-amber-500/20 bg-amber-500/5'
          }`}
        >
          <Lock className={`w-5 h-5 mb-2 ${sshPassed === sshTotal ? 'text-emerald-400' : 'text-amber-400'}`} />
          <div className="text-lg font-bold text-foreground">{sshPassed}/{sshTotal}</div>
          <div className="text-xs text-muted-foreground">SSH checks passed</div>
        </button>

        <button
          onClick={() => onTabChange('firewall')}
          className={`p-4 rounded-xl border text-left transition-colors hover:bg-white/5 ${
            result.firewall.active ? 'border-emerald-500/20 bg-emerald-500/5' : 'border-red-500/20 bg-red-500/5'
          }`}
        >
          <Wifi className={`w-5 h-5 mb-2 ${result.firewall.active ? 'text-emerald-400' : 'text-red-400'}`} />
          <div className="text-lg font-bold text-foreground">{result.firewall.active ? 'Active' : 'Inactive'}</div>
          <div className="text-xs text-muted-foreground">Firewall ({result.firewall.type})</div>
        </button>

        <button
          onClick={() => onTabChange('updates')}
          className={`p-4 rounded-xl border text-left transition-colors hover:bg-white/5 ${
            result.autoupdate.enabled ? 'border-emerald-500/20 bg-emerald-500/5' : 'border-red-500/20 bg-red-500/5'
          }`}
        >
          <Server className={`w-5 h-5 mb-2 ${result.autoupdate.enabled ? 'text-emerald-400' : 'text-red-400'}`} />
          <div className="text-lg font-bold text-foreground">{result.autoupdate.enabled ? 'Configured' : 'Not configured'}</div>
          <div className="text-xs text-muted-foreground">Auto-updates</div>
        </button>
      </div>

      {/* Ports summary */}
      <div className="p-4 rounded-xl border border-border/30 bg-white/[0.02]">
        <div className="flex items-center gap-2 mb-2">
          <Wifi className="w-4 h-4 text-muted-foreground" />
          <span className="text-sm font-medium">Open Ports</span>
          <span className="text-xs text-muted-foreground">({result.ports.length})</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {result.ports.length === 0 ? (
            <span className="text-xs text-muted-foreground">No listening ports detected</span>
          ) : (
            result.ports.slice(0, 20).map((p, i) => (
              <span key={i} className="px-2 py-1 rounded-md text-xs font-mono bg-white/5 text-muted-foreground">
                {p.port}{p.process ? ` (${p.process})` : ''}
              </span>
            ))
          )}
          {result.ports.length > 20 && (
            <span className="px-2 py-1 text-xs text-muted-foreground">+{result.ports.length - 20} more</span>
          )}
        </div>
      </div>
    </div>
  )
}

function PackagesTab({ result }: { result: SecurityScanResult }) {
  if (result.upgradable.length === 0) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <CheckCircle className="w-8 h-8 mx-auto mb-2 text-emerald-400 opacity-50" />
          <p className="text-sm text-emerald-400">All packages are up to date</p>
        </div>
      </div>
    )
  }

  return (
    <div className="rounded-xl border border-border/30 overflow-hidden">
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-white/[0.02] border-b border-border/30">
            <th className="text-left px-4 py-2.5 font-medium text-muted-foreground">Package</th>
            <th className="text-left px-4 py-2.5 font-medium text-muted-foreground">Current</th>
            <th className="text-left px-4 py-2.5 font-medium text-muted-foreground">Available</th>
          </tr>
        </thead>
        <tbody>
          {result.upgradable.map((pkg, i) => (
            <tr key={i} className="border-b border-border/10 hover:bg-white/[0.02]">
              <td className="px-4 py-2 font-mono text-foreground">{pkg.name}</td>
              <td className="px-4 py-2 font-mono text-muted-foreground">{pkg.current || '—'}</td>
              <td className="px-4 py-2 font-mono text-amber-400">{pkg.available || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function SshConfigTab({ result, statusBadge }: { result: SecurityScanResult; statusBadge: (s: string) => React.ReactNode }) {
  if (result.ssh_config.length === 0) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <Lock className="w-8 h-8 mx-auto mb-2 text-muted-foreground opacity-30" />
          <p className="text-sm text-muted-foreground">Could not read SSH configuration</p>
          <p className="text-xs text-muted-foreground/50 mt-1">sshd -T may require root privileges</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {result.ssh_config.map((check, i) => (
        <div key={i} className="flex items-center justify-between p-3 rounded-xl border border-border/30 bg-white/[0.02] hover:bg-white/[0.03]">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm font-mono font-medium text-foreground">{check.key}</span>
              <span className="text-xs font-mono text-muted-foreground px-1.5 py-0.5 rounded bg-white/5">{check.value}</span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">{check.detail}</p>
          </div>
          <div className="ml-3 flex-shrink-0">
            {statusBadge(check.status)}
          </div>
        </div>
      ))}
    </div>
  )
}

function FirewallTab({ result }: { result: SecurityScanResult }) {
  return (
    <div className="space-y-4">
      {/* Firewall Status */}
      <div className="p-4 rounded-xl border border-border/30 bg-white/[0.02]">
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm font-medium">Firewall Status</span>
          <div className="flex items-center gap-2">
            <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
              result.firewall.active
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                : 'bg-red-500/10 text-red-400 border border-red-500/20'
            }`}>
              {result.firewall.active ? 'Active' : 'Inactive'}
            </span>
            <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-white/5 text-muted-foreground">
              {result.firewall.type}
            </span>
          </div>
        </div>
        {result.firewall.rules && result.firewall.type !== 'none' && (
          <pre className="text-xs font-mono text-muted-foreground bg-black/30 rounded-lg p-3 overflow-auto max-h-48 whitespace-pre-wrap">
            {result.firewall.rules}
          </pre>
        )}
      </div>

      {/* Open Ports Table */}
      <div className="rounded-xl border border-border/30 overflow-hidden">
        <div className="px-4 py-2.5 bg-white/[0.02] border-b border-border/30">
          <span className="text-sm font-medium">Listening Ports</span>
          <span className="ml-2 text-xs text-muted-foreground">({result.ports.length})</span>
        </div>
        {result.ports.length === 0 ? (
          <div className="px-4 py-8 text-center text-xs text-muted-foreground">No listening ports detected</div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-white/[0.01] border-b border-border/20">
                <th className="text-left px-4 py-2 font-medium text-muted-foreground">Proto</th>
                <th className="text-left px-4 py-2 font-medium text-muted-foreground">Address</th>
                <th className="text-left px-4 py-2 font-medium text-muted-foreground">Port</th>
                <th className="text-left px-4 py-2 font-medium text-muted-foreground">Process</th>
              </tr>
            </thead>
            <tbody>
              {result.ports.map((p, i) => (
                <tr key={i} className="border-b border-border/10 hover:bg-white/[0.02]">
                  <td className="px-4 py-2 font-mono text-muted-foreground">{p.proto}</td>
                  <td className="px-4 py-2 font-mono text-muted-foreground">{p.address}</td>
                  <td className="px-4 py-2 font-mono text-foreground">{p.port}</td>
                  <td className="px-4 py-2 font-mono text-muted-foreground">{p.process || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function AutoUpdatesTab({ result }: { result: SecurityScanResult }) {
  return (
    <div className="space-y-4">
      <div className="p-4 rounded-xl border border-border/30 bg-white/[0.02]">
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm font-medium">Auto-Update Status</span>
          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
            result.autoupdate.enabled
              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
              : 'bg-red-500/10 text-red-400 border border-red-500/20'
          }`}>
            {result.autoupdate.enabled ? 'Configured' : 'Not Configured'}
          </span>
        </div>

        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">Package:</span>
            <span className="text-xs font-mono text-foreground">
              {result.autoupdate.package === 'none' ? 'Not installed' : result.autoupdate.package}
            </span>
          </div>

          {result.autoupdate.detail && result.autoupdate.package !== 'none' && (
            <pre className="text-xs font-mono text-muted-foreground bg-black/30 rounded-lg p-3 overflow-auto max-h-48 whitespace-pre-wrap">
              {result.autoupdate.detail}
            </pre>
          )}
        </div>

        {!result.autoupdate.enabled && (
          <div className="mt-3 p-3 rounded-lg bg-red-500/5 border border-red-500/10">
            <p className="text-xs text-red-400">
              Automatic security updates are not configured. Consider installing <code className="px-1 py-0.5 rounded bg-red-500/10">unattended-upgrades</code> (Debian/Ubuntu) or enabling <code className="px-1 py-0.5 rounded bg-red-500/10">dnf-automatic</code> (RHEL/Fedora).
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
