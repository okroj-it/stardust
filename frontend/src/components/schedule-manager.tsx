import { useState, useEffect, useCallback } from "react"
import {
  fetchSchedules,
  createSchedule,
  updateSchedule,
  deleteSchedule,
  toggleSchedule,
  triggerSchedule,
  fetchScheduleRuns,
  describeCron,
  fetchAllTags,
} from "@/lib/api"
import type { NodeStatus, Schedule, ScheduleRun } from "@/lib/api"
import {
  X,
  Loader2,
  Plus,
  Play,
  Pause,
  Trash2,
  Clock,
  Terminal,
  Package,
  ChevronDown,
  ChevronRight,
  Check,
  AlertCircle,
  Pencil,
  RotateCw,
  Search,
  BookOpen,
} from "lucide-react"

interface ScheduleManagerProps {
  nodes: NodeStatus[]
  onClose: () => void
}

type View = 'list' | 'create' | 'edit'

const JOB_TYPE_LABELS: Record<string, { label: string; icon: typeof Terminal }> = {
  command: { label: 'Command', icon: Terminal },
  ansible: { label: 'Ansible', icon: BookOpen },
  package_update: { label: 'Package Update', icon: Package },
}

const CRON_PRESETS = [
  { label: 'Every minute', min: '*', hour: '*', dom: '*', month: '*', dow: '*' },
  { label: 'Every 5 minutes', min: '*/5', hour: '*', dom: '*', month: '*', dow: '*' },
  { label: 'Every 15 minutes', min: '*/15', hour: '*', dom: '*', month: '*', dow: '*' },
  { label: 'Every hour', min: '0', hour: '*', dom: '*', month: '*', dow: '*' },
  { label: 'Every 6 hours', min: '0', hour: '*/6', dom: '*', month: '*', dow: '*' },
  { label: 'Every day at midnight', min: '0', hour: '0', dom: '*', month: '*', dow: '*' },
  { label: 'Every day at 3:00 AM', min: '0', hour: '3', dom: '*', month: '*', dow: '*' },
  { label: 'Every Sunday at 3:00 AM', min: '0', hour: '3', dom: '*', month: '*', dow: '0' },
  { label: 'Every Monday at 6:00 AM', min: '0', hour: '6', dom: '*', month: '*', dow: '1' },
  { label: '1st of month at midnight', min: '0', hour: '0', dom: '1', month: '*', dow: '*' },
]

function StatusDot({ schedule }: { schedule: Schedule }) {
  if (!schedule.enabled) return <div className="w-2 h-2 rounded-full bg-muted-foreground/30" title="Disabled" />
  if (!schedule.last_run) return <div className="w-2 h-2 rounded-full bg-blue-400" title="Never run" />
  if (schedule.last_status === 'ok') return <div className="w-2 h-2 rounded-full bg-emerald-400" title="Last run OK" />
  if (schedule.last_status === 'failed') return <div className="w-2 h-2 rounded-full bg-red-400" title="Last run failed" />
  return <div className="w-2 h-2 rounded-full bg-yellow-400" title={schedule.last_status ?? 'Unknown'} />
}

function timeAgo(ts: number): string {
  const diff = Math.floor(Date.now() / 1000) - ts
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export function ScheduleManager({ nodes, onClose }: ScheduleManagerProps) {
  const [view, setView] = useState<View>('list')
  const [schedules, setSchedules] = useState<Schedule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [runs, setRuns] = useState<ScheduleRun[]>([])
  const [runsLoading, setRunsLoading] = useState(false)
  const [editingSchedule, setEditingSchedule] = useState<Schedule | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<number | null>(null)
  const [allTags, setAllTags] = useState<string[]>([])

  const load = useCallback(async () => {
    try {
      const data = await fetchSchedules()
      setSchedules(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load schedules')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    fetchAllTags().then(setAllTags).catch(() => {})
  }, [load])

  const handleExpand = useCallback(async (id: number) => {
    if (expandedId === id) {
      setExpandedId(null)
      return
    }
    setExpandedId(id)
    setRunsLoading(true)
    try {
      const data = await fetchScheduleRuns(id, 10)
      setRuns(data)
    } catch {
      setRuns([])
    } finally {
      setRunsLoading(false)
    }
  }, [expandedId])

  const handleToggle = useCallback(async (id: number) => {
    try {
      await toggleSchedule(id)
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Toggle failed')
    }
  }, [load])

  const handleTrigger = useCallback(async (id: number) => {
    try {
      await triggerSchedule(id)
      setError(null)
      // Refresh after a short delay to show the new run
      setTimeout(load, 1500)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Trigger failed')
    }
  }, [load])

  const handleDelete = useCallback(async (id: number) => {
    try {
      await deleteSchedule(id)
      setConfirmDelete(null)
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Delete failed')
    }
  }, [load])

  const handleEdit = useCallback((schedule: Schedule) => {
    setEditingSchedule(schedule)
    setView('edit')
  }, [])

  const filtered = search
    ? schedules.filter(s => s.name.toLowerCase().includes(search.toLowerCase()))
    : schedules

  const nodeNameMap = Object.fromEntries(nodes.map(n => [n.agent_id, n.name]))

  if (view === 'create' || view === 'edit') {
    return (
      <ScheduleForm
        nodes={nodes}
        allTags={allTags}
        existing={view === 'edit' ? editingSchedule : null}
        onSave={async (data) => {
          try {
            if (view === 'edit' && editingSchedule) {
              await updateSchedule(editingSchedule.id, data)
            } else {
              await createSchedule(data)
            }
            setView('list')
            setEditingSchedule(null)
            load()
          } catch (e) {
            throw e
          }
        }}
        onCancel={() => {
          setView('list')
          setEditingSchedule(null)
        }}
      />
    )
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-start justify-center pt-[5vh] overflow-y-auto">
      <div className="bg-card border border-border/50 rounded-2xl shadow-2xl w-full max-w-4xl mx-4 mb-8">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-border/50">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500/80" />
              <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
              <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
            </div>
            <Clock className="w-5 h-5 text-primary" />
            <h2 className="text-lg font-semibold">Scheduled Automation</h2>
            <span className="text-xs text-muted-foreground">(Station to Station)</span>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-muted transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Toolbar */}
        <div className="flex items-center gap-3 p-4 border-b border-border/30">
          <button
            onClick={() => setView('create')}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            New Schedule
          </button>
          <div className="flex-1" />
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              placeholder="Filter..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-8 pr-3 py-1.5 text-sm rounded-lg border border-border/50 bg-background/50 focus:outline-none focus:ring-1 focus:ring-primary/50 w-48"
            />
          </div>
          <button onClick={load} className="p-1.5 rounded-lg hover:bg-muted transition-colors" title="Refresh">
            <RotateCw className="w-4 h-4 text-muted-foreground" />
          </button>
        </div>

        {error && (
          <div className="mx-4 mt-3 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            {error}
            <button onClick={() => setError(null)} className="ml-auto text-red-400/60 hover:text-red-400"><X className="w-3.5 h-3.5" /></button>
          </div>
        )}

        {/* Content */}
        <div className="p-4">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin text-primary" />
            </div>
          ) : schedules.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Clock className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p className="text-sm">No schedules configured</p>
              <p className="text-xs mt-1">Create a schedule to automate tasks across your fleet</p>
            </div>
          ) : filtered.length === 0 ? (
            <p className="text-center py-8 text-sm text-muted-foreground">No schedules match &quot;{search}&quot;</p>
          ) : (
            <div className="space-y-2">
              {filtered.map(schedule => {
                const JobIcon = JOB_TYPE_LABELS[schedule.job_type]?.icon ?? Terminal
                const expanded = expandedId === schedule.id
                const cronDesc = describeCron(schedule.cron_minute, schedule.cron_hour, schedule.cron_dom, schedule.cron_month, schedule.cron_dow)

                let targetDesc = 'All nodes'
                if (schedule.target_type === 'tags') targetDesc = `Tag: ${schedule.target_value ?? '?'}`
                if (schedule.target_type === 'nodes') {
                  const ids = (schedule.target_value ?? '').split(',').filter(Boolean)
                  targetDesc = ids.map(id => nodeNameMap[id] ?? id.slice(0, 8)).join(', ')
                }

                return (
                  <div key={schedule.id} className="border border-border/30 rounded-lg overflow-hidden">
                    {/* Row */}
                    <div
                      className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-muted/30 transition-colors"
                      onClick={() => handleExpand(schedule.id)}
                    >
                      {expanded ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground shrink-0" />}
                      <StatusDot schedule={schedule} />
                      <span className={`text-sm font-medium truncate ${!schedule.enabled ? 'text-muted-foreground line-through' : ''}`}>
                        {schedule.name}
                      </span>
                      <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-muted/50 text-muted-foreground shrink-0">
                        <JobIcon className="w-3 h-3" />
                        {JOB_TYPE_LABELS[schedule.job_type]?.label ?? schedule.job_type}
                      </span>
                      <span className="text-xs text-muted-foreground truncate hidden sm:block" title={`${schedule.cron_minute} ${schedule.cron_hour} ${schedule.cron_dom} ${schedule.cron_month} ${schedule.cron_dow}`}>
                        {cronDesc}
                      </span>
                      <span className="text-xs text-muted-foreground/60 truncate hidden md:block max-w-[150px]">{targetDesc}</span>
                      <div className="ml-auto flex items-center gap-1 shrink-0" onClick={e => e.stopPropagation()}>
                        {schedule.last_run && (
                          <span className="text-[10px] text-muted-foreground/50 mr-2 hidden lg:block">{timeAgo(schedule.last_run)}</span>
                        )}
                        <button
                          onClick={() => handleTrigger(schedule.id)}
                          className="p-1 rounded hover:bg-muted transition-colors" title="Run Now"
                        >
                          <Play className="w-3.5 h-3.5 text-emerald-400" />
                        </button>
                        <button
                          onClick={() => handleToggle(schedule.id)}
                          className="p-1 rounded hover:bg-muted transition-colors" title={schedule.enabled ? 'Disable' : 'Enable'}
                        >
                          {schedule.enabled ? <Pause className="w-3.5 h-3.5 text-yellow-400" /> : <Play className="w-3.5 h-3.5 text-muted-foreground" />}
                        </button>
                        <button
                          onClick={() => handleEdit(schedule)}
                          className="p-1 rounded hover:bg-muted transition-colors" title="Edit"
                        >
                          <Pencil className="w-3.5 h-3.5 text-muted-foreground" />
                        </button>
                        {confirmDelete === schedule.id ? (
                          <div className="flex items-center gap-1">
                            <button onClick={() => handleDelete(schedule.id)} className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 text-[10px] font-medium hover:bg-red-500/30">Delete</button>
                            <button onClick={() => setConfirmDelete(null)} className="px-2 py-0.5 rounded bg-muted text-muted-foreground text-[10px] font-medium hover:bg-muted/80">Cancel</button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setConfirmDelete(schedule.id)}
                            className="p-1 rounded hover:bg-muted transition-colors" title="Delete"
                          >
                            <Trash2 className="w-3.5 h-3.5 text-muted-foreground hover:text-red-400" />
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Expanded: Execution History */}
                    {expanded && (
                      <div className="border-t border-border/20 bg-muted/10 px-4 py-3">
                        <p className="text-xs font-medium text-muted-foreground mb-2">Recent Runs</p>
                        {runsLoading ? (
                          <div className="flex items-center gap-2 py-2">
                            <Loader2 className="w-3.5 h-3.5 animate-spin text-muted-foreground" />
                            <span className="text-xs text-muted-foreground">Loading...</span>
                          </div>
                        ) : runs.length === 0 ? (
                          <p className="text-xs text-muted-foreground/50 py-2">No runs yet</p>
                        ) : (
                          <div className="space-y-1.5 max-h-60 overflow-y-auto">
                            {runs.map(run => (
                              <RunRow key={run.id} run={run} />
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function RunRow({ run }: { run: ScheduleRun }) {
  const [expanded, setExpanded] = useState(false)

  const statusIcon = run.status === 'ok' ? <Check className="w-3 h-3 text-emerald-400" />
    : run.status === 'failed' ? <AlertCircle className="w-3 h-3 text-red-400" />
    : run.status === 'running' ? <Loader2 className="w-3 h-3 animate-spin text-blue-400" />
    : <Clock className="w-3 h-3 text-muted-foreground" />

  const duration = run.finished_at
    ? `${Math.max(1, run.finished_at - run.started_at)}s`
    : 'running...'

  return (
    <div className="rounded border border-border/20 bg-background/30">
      <div
        className="flex items-center gap-2 px-3 py-1.5 cursor-pointer hover:bg-muted/20 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        {statusIcon}
        <span className={`text-[11px] font-medium ${
          run.status === 'ok' ? 'text-emerald-400' : run.status === 'failed' ? 'text-red-400' : 'text-muted-foreground'
        }`}>
          {run.status}
        </span>
        <span className="text-[10px] text-muted-foreground">{new Date(run.started_at * 1000).toLocaleString()}</span>
        <span className="text-[10px] text-muted-foreground/50 ml-auto">{duration}</span>
        {run.output && (
          expanded ? <ChevronDown className="w-3 h-3 text-muted-foreground/50" /> : <ChevronRight className="w-3 h-3 text-muted-foreground/50" />
        )}
      </div>
      {expanded && run.output && (
        <pre className="px-3 py-2 text-[11px] text-muted-foreground font-mono bg-black/20 border-t border-border/10 max-h-40 overflow-auto whitespace-pre-wrap break-all">
          {run.output}
        </pre>
      )}
    </div>
  )
}

// --- Schedule Form ---

interface ScheduleFormProps {
  nodes: NodeStatus[]
  allTags: string[]
  existing: Schedule | null
  onSave: (data: Partial<Schedule>) => Promise<void>
  onCancel: () => void
}

function ScheduleForm({ nodes, allTags, existing, onSave, onCancel }: ScheduleFormProps) {
  const [name, setName] = useState(existing?.name ?? '')
  const [jobType, setJobType] = useState<string>(existing?.job_type ?? 'command')
  const [targetType, setTargetType] = useState<string>(existing?.target_type ?? 'all')
  const [targetValue, setTargetValue] = useState<string>(existing?.target_value ?? '')
  const [enabled, setEnabled] = useState(existing?.enabled ?? true)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  // Config fields
  const existingConfig = existing ? (() => { try { return JSON.parse(existing.config) } catch { return {} } })() : {}
  const [command, setCommand] = useState<string>(existingConfig.command ?? '')
  const [sudo, setSudo] = useState<boolean>(existingConfig.sudo ?? false)
  const [playbook, setPlaybook] = useState<string>(existingConfig.playbook ?? '')
  const [requirements, setRequirements] = useState<string>(existingConfig.requirements ?? '')
  const [pkgAction, setPkgAction] = useState<string>(existingConfig.pkg_action ?? 'upgrade')

  // Cron fields
  const [cronMin, setCronMin] = useState(existing?.cron_minute ?? '0')
  const [cronHour, setCronHour] = useState(existing?.cron_hour ?? '*')
  const [cronDom, setCronDom] = useState(existing?.cron_dom ?? '*')
  const [cronMonth, setCronMonth] = useState(existing?.cron_month ?? '*')
  const [cronDow, setCronDow] = useState(existing?.cron_dow ?? '*')
  const [showCustomCron, setShowCustomCron] = useState(false)

  // Node selection for target_type="nodes"
  const [selectedNodeIds, setSelectedNodeIds] = useState<Set<string>>(() => {
    if (existing?.target_type === 'nodes' && existing.target_value) {
      return new Set(existing.target_value.split(',').filter(Boolean))
    }
    return new Set()
  })

  const toggleNodeId = (id: string) => {
    setSelectedNodeIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const applyPreset = (preset: typeof CRON_PRESETS[number]) => {
    setCronMin(preset.min)
    setCronHour(preset.hour)
    setCronDom(preset.dom)
    setCronMonth(preset.month)
    setCronDow(preset.dow)
  }

  const handleSubmit = async () => {
    setFormError(null)
    if (!name.trim()) { setFormError('Name is required'); return }

    let config: Record<string, unknown> = {}
    if (jobType === 'command') {
      if (!command.trim()) { setFormError('Command is required'); return }
      config = { command: command.trim(), sudo }
    } else if (jobType === 'ansible') {
      if (!playbook.trim()) { setFormError('Playbook is required'); return }
      config = { playbook: playbook.trim(), ...(requirements.trim() ? { requirements: requirements.trim() } : {}) }
    } else if (jobType === 'package_update') {
      config = { pkg_action: pkgAction }
    }

    let tv: string | null = null
    if (targetType === 'tags') {
      if (!targetValue.trim()) { setFormError('Tag is required'); return }
      tv = targetValue.trim()
    } else if (targetType === 'nodes') {
      if (selectedNodeIds.size === 0) { setFormError('Select at least one node'); return }
      tv = Array.from(selectedNodeIds).join(',')
    }

    setSaving(true)
    try {
      await onSave({
        name: name.trim(),
        job_type: jobType as Schedule['job_type'],
        config: JSON.stringify(config),
        target_type: targetType as Schedule['target_type'],
        target_value: tv,
        cron_minute: cronMin,
        cron_hour: cronHour,
        cron_dom: cronDom,
        cron_month: cronMonth,
        cron_dow: cronDow,
        enabled,
      })
    } catch (e) {
      setFormError(e instanceof Error ? e.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  const cronPreview = describeCron(cronMin, cronHour, cronDom, cronMonth, cronDow)
  const connectedNodes = nodes.filter(n => n.connected)

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-start justify-center pt-[5vh] overflow-y-auto">
      <div className="bg-card border border-border/50 rounded-2xl shadow-2xl w-full max-w-2xl mx-4 mb-8">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-border/50">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500/80" />
              <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
              <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
            </div>
            <Clock className="w-5 h-5 text-primary" />
            <h2 className="text-lg font-semibold">{existing ? 'Edit Schedule' : 'New Schedule'}</h2>
          </div>
          <button onClick={onCancel} className="p-1.5 rounded-lg hover:bg-muted transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-5">
          {formError && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              {formError}
            </div>
          )}

          {/* Name */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g. Nightly Package Update"
              className="w-full px-3 py-2 text-sm rounded-lg border border-border/50 bg-background/50 focus:outline-none focus:ring-1 focus:ring-primary/50"
            />
          </div>

          {/* Job Type */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Job Type</label>
            <div className="flex gap-2">
              {Object.entries(JOB_TYPE_LABELS).map(([key, { label, icon: Icon }]) => (
                <button
                  key={key}
                  onClick={() => setJobType(key)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm font-medium transition-all ${
                    jobType === key
                      ? 'border-primary/40 bg-primary/10 text-primary'
                      : 'border-border/50 bg-background/30 text-muted-foreground hover:border-primary/20'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Config (conditional) */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Configuration</label>
            {jobType === 'command' && (
              <div className="space-y-2">
                <textarea
                  value={command}
                  onChange={e => setCommand(e.target.value)}
                  placeholder="e.g. apt update && apt upgrade -y"
                  rows={3}
                  className="w-full px-3 py-2 text-sm font-mono rounded-lg border border-border/50 bg-background/50 focus:outline-none focus:ring-1 focus:ring-primary/50 resize-none"
                />
                <label className="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer">
                  <input type="checkbox" checked={sudo} onChange={e => setSudo(e.target.checked)} className="rounded" />
                  Run with sudo
                </label>
              </div>
            )}
            {jobType === 'ansible' && (
              <div className="space-y-2">
                <input
                  type="text"
                  value={playbook}
                  onChange={e => setPlaybook(e.target.value)}
                  placeholder="Playbook name (e.g. site.yml)"
                  className="w-full px-3 py-2 text-sm rounded-lg border border-border/50 bg-background/50 focus:outline-none focus:ring-1 focus:ring-primary/50"
                />
                <input
                  type="text"
                  value={requirements}
                  onChange={e => setRequirements(e.target.value)}
                  placeholder="Requirements file (optional)"
                  className="w-full px-3 py-2 text-sm rounded-lg border border-border/50 bg-background/50 focus:outline-none focus:ring-1 focus:ring-primary/50"
                />
              </div>
            )}
            {jobType === 'package_update' && (
              <div className="flex gap-2">
                <button
                  onClick={() => setPkgAction('upgrade')}
                  className={`px-3 py-2 rounded-lg border text-sm font-medium transition-all ${
                    pkgAction === 'upgrade' ? 'border-primary/40 bg-primary/10 text-primary' : 'border-border/50 bg-background/30 text-muted-foreground hover:border-primary/20'
                  }`}
                >
                  Upgrade
                </button>
                <button
                  onClick={() => setPkgAction('full-upgrade')}
                  className={`px-3 py-2 rounded-lg border text-sm font-medium transition-all ${
                    pkgAction === 'full-upgrade' ? 'border-primary/40 bg-primary/10 text-primary' : 'border-border/50 bg-background/30 text-muted-foreground hover:border-primary/20'
                  }`}
                >
                  Full Upgrade
                </button>
              </div>
            )}
          </div>

          {/* Target */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Target</label>
            <div className="flex gap-2 mb-2">
              {(['all', 'tags', 'nodes'] as const).map(t => (
                <button
                  key={t}
                  onClick={() => setTargetType(t)}
                  className={`px-3 py-1.5 rounded-lg border text-sm font-medium transition-all ${
                    targetType === t
                      ? 'border-primary/40 bg-primary/10 text-primary'
                      : 'border-border/50 bg-background/30 text-muted-foreground hover:border-primary/20'
                  }`}
                >
                  {t === 'all' ? 'All Nodes' : t === 'tags' ? 'By Tag' : 'Specific Nodes'}
                </button>
              ))}
            </div>
            {targetType === 'tags' && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {allTags.length === 0 ? (
                  <p className="text-xs text-muted-foreground/50">No tags available</p>
                ) : allTags.map(tag => (
                  <button
                    key={tag}
                    onClick={() => setTargetValue(tag)}
                    className={`px-2.5 py-1 rounded-full text-xs font-medium border transition-all ${
                      targetValue === tag
                        ? 'bg-primary/15 border-primary/40 text-primary'
                        : 'bg-card/50 border-border/50 text-muted-foreground hover:border-primary/30'
                    }`}
                  >
                    {tag}
                  </button>
                ))}
              </div>
            )}
            {targetType === 'nodes' && (
              <div className="flex flex-wrap gap-1.5 mt-2 max-h-32 overflow-y-auto">
                {connectedNodes.map(n => (
                  <button
                    key={n.agent_id}
                    onClick={() => toggleNodeId(n.agent_id)}
                    className={`px-2.5 py-1 rounded-full text-xs font-medium border transition-all ${
                      selectedNodeIds.has(n.agent_id)
                        ? 'bg-primary/15 border-primary/40 text-primary'
                        : 'bg-card/50 border-border/50 text-muted-foreground hover:border-primary/30'
                    }`}
                  >
                    {n.name}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Schedule (Cron) */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Schedule</label>
            <div className="flex flex-wrap gap-1.5 mb-3">
              {CRON_PRESETS.map(preset => {
                const active = preset.min === cronMin && preset.hour === cronHour && preset.dom === cronDom && preset.month === cronMonth && preset.dow === cronDow
                return (
                  <button
                    key={preset.label}
                    onClick={() => { applyPreset(preset); setShowCustomCron(false) }}
                    className={`px-2.5 py-1 rounded-full text-xs font-medium border transition-all ${
                      active
                        ? 'bg-primary/15 border-primary/40 text-primary'
                        : 'bg-card/50 border-border/50 text-muted-foreground hover:border-primary/30'
                    }`}
                  >
                    {preset.label}
                  </button>
                )
              })}
              <button
                onClick={() => setShowCustomCron(!showCustomCron)}
                className={`px-2.5 py-1 rounded-full text-xs font-medium border transition-all ${
                  showCustomCron
                    ? 'bg-primary/15 border-primary/40 text-primary'
                    : 'bg-card/50 border-border/50 text-muted-foreground hover:border-primary/30'
                }`}
              >
                Custom...
              </button>
            </div>
            {showCustomCron && (
              <div className="grid grid-cols-5 gap-2 mb-3">
                {[
                  { label: 'Minute', value: cronMin, set: setCronMin },
                  { label: 'Hour', value: cronHour, set: setCronHour },
                  { label: 'Day', value: cronDom, set: setCronDom },
                  { label: 'Month', value: cronMonth, set: setCronMonth },
                  { label: 'Weekday', value: cronDow, set: setCronDow },
                ].map(f => (
                  <div key={f.label}>
                    <label className="text-[10px] text-muted-foreground/60 block mb-0.5">{f.label}</label>
                    <input
                      type="text"
                      value={f.value}
                      onChange={e => f.set(e.target.value)}
                      className="w-full px-2 py-1.5 text-xs font-mono rounded border border-border/50 bg-background/50 focus:outline-none focus:ring-1 focus:ring-primary/50 text-center"
                    />
                  </div>
                ))}
              </div>
            )}
            <div className="px-3 py-2 rounded-lg bg-muted/30 text-sm text-muted-foreground flex items-center gap-2">
              <Clock className="w-3.5 h-3.5 shrink-0" />
              {cronPreview}
              <span className="text-[10px] text-muted-foreground/40 ml-auto font-mono">{cronMin} {cronHour} {cronDom} {cronMonth} {cronDow}</span>
            </div>
          </div>

          {/* Enabled toggle */}
          <label className="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer">
            <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} className="rounded" />
            Enabled
          </label>

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-2 border-t border-border/30">
            <button
              onClick={onCancel}
              className="px-4 py-2 text-sm rounded-lg border border-border/50 text-muted-foreground hover:bg-muted transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSubmit}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 text-sm rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
            >
              {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              {existing ? 'Update' : 'Create'} Schedule
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
