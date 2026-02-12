import { useState, useEffect, useRef, useCallback } from "react"
import { startLogStream, pollLogStream, stopLogStream } from "@/lib/api"
import type { LogSource } from "@/lib/api"
import {
  X,
  Play,
  Square,
  Pause,
  Search,
  ScrollText,
  FileText,
  BookOpen,
  Loader2,
} from "lucide-react"

interface LogViewerProps {
  nodeId: string
  nodeName: string
  onClose: () => void
}

export function LogViewer({ nodeId, nodeName, onClose }: LogViewerProps) {
  const [source, setSource] = useState<LogSource>('journal')
  const [service, setService] = useState('')
  const [filePath, setFilePath] = useState('')
  const [lines, setLines] = useState(100)
  const [streaming, setStreaming] = useState(false)
  const [output, setOutput] = useState('')
  const [offset, setOffset] = useState(0)
  const [paused, setPaused] = useState(false)
  const [filter, setFilter] = useState('')
  const [jobId, setJobId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)
  const [lineCount, setLineCount] = useState(0)

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const outputRef = useRef<HTMLPreElement>(null)
  const autoScrollRef = useRef(true)
  const offsetRef = useRef(0)
  const jobIdRef = useRef<string | null>(null)

  // Sync refs
  useEffect(() => { offsetRef.current = offset }, [offset])
  useEffect(() => { jobIdRef.current = jobId }, [jobId])

  // Auto-scroll detection
  const handleScroll = useCallback(() => {
    if (!outputRef.current) return
    const el = outputRef.current
    autoScrollRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 100
  }, [])

  // Auto-scroll on new output
  useEffect(() => {
    if (autoScrollRef.current && outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [output])

  // Count lines
  useEffect(() => {
    if (output) {
      setLineCount(output.split('\n').filter(l => l.length > 0).length)
    } else {
      setLineCount(0)
    }
  }, [output])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
      if (jobIdRef.current) {
        stopLogStream(nodeId, jobIdRef.current).catch(() => {})
      }
    }
  }, [nodeId])

  const handleStart = async () => {
    setError(null)
    setOutput('')
    setOffset(0)
    offsetRef.current = 0
    setStarting(true)
    autoScrollRef.current = true

    try {
      const id = await startLogStream(
        nodeId,
        source,
        source === 'journal' && service ? service : undefined,
        source === 'file' && filePath ? filePath : undefined,
        lines,
      )
      setJobId(id)
      jobIdRef.current = id
      setStreaming(true)
      setPaused(false)

      // Start polling
      intervalRef.current = setInterval(async () => {
        try {
          const result = await pollLogStream(nodeId, id, offsetRef.current)
          if (result.output) {
            setOutput(prev => prev + result.output)
          }
          setOffset(result.offset)
          offsetRef.current = result.offset
          if (result.done) {
            if (intervalRef.current) clearInterval(intervalRef.current)
            intervalRef.current = null
            setStreaming(false)
          }
        } catch {
          // Poll error — ignore, will retry
        }
      }, 300)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start log stream')
    } finally {
      setStarting(false)
    }
  }

  const handleStop = async () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current)
      intervalRef.current = null
    }
    if (jobId) {
      try {
        await stopLogStream(nodeId, jobId)
      } catch {}
    }
    setStreaming(false)
    setPaused(false)
    setJobId(null)
    jobIdRef.current = null
  }

  const handlePause = () => {
    if (paused) {
      // Resume polling
      if (jobId) {
        intervalRef.current = setInterval(async () => {
          try {
            const result = await pollLogStream(nodeId, jobId, offsetRef.current)
            if (result.output) {
              setOutput(prev => prev + result.output)
            }
            setOffset(result.offset)
            offsetRef.current = result.offset
            if (result.done) {
              if (intervalRef.current) clearInterval(intervalRef.current)
              intervalRef.current = null
              setStreaming(false)
            }
          } catch {}
        }, 300)
      }
      setPaused(false)
    } else {
      // Pause polling
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
      setPaused(true)
    }
  }

  // Filter output
  const displayOutput = filter
    ? output.split('\n').filter(line => line.toLowerCase().includes(filter.toLowerCase())).join('\n')
    : output

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={!streaming ? onClose : undefined} />
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
              <ScrollText className="w-4 h-4 text-emerald-400" />
              <span className="text-sm font-medium text-foreground">Logs</span>
              <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                {nodeName}
              </span>
            </div>
          </div>
          <button
            onClick={streaming ? handleStop : onClose}
            className="p-1.5 rounded-lg hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Toolbar */}
        <div className="px-4 py-2.5 border-b border-border/30 bg-[#161b22]/50">
          {!streaming ? (
            <div className="flex items-center gap-3">
              {/* Source Toggle */}
              <div className="flex rounded-lg border border-border/30 overflow-hidden">
                <button
                  onClick={() => setSource('journal')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
                    source === 'journal'
                      ? 'bg-emerald-500/20 text-emerald-400'
                      : 'text-muted-foreground hover:text-foreground hover:bg-white/5'
                  }`}
                >
                  <BookOpen className="w-3.5 h-3.5" />
                  Journal
                </button>
                <button
                  onClick={() => setSource('file')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors border-l border-border/30 ${
                    source === 'file'
                      ? 'bg-emerald-500/20 text-emerald-400'
                      : 'text-muted-foreground hover:text-foreground hover:bg-white/5'
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  File
                </button>
              </div>

              {/* Source-specific input */}
              {source === 'journal' ? (
                <input
                  type="text"
                  value={service}
                  onChange={e => setService(e.target.value)}
                  placeholder="Service (optional, e.g. nginx.service)"
                  className="flex-1 px-3 py-1.5 rounded-lg text-xs bg-[#0d1117] border border-border/30 text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-emerald-500/40 font-mono"
                />
              ) : (
                <input
                  type="text"
                  value={filePath}
                  onChange={e => setFilePath(e.target.value)}
                  placeholder="File path (e.g. /var/log/syslog)"
                  className="flex-1 px-3 py-1.5 rounded-lg text-xs bg-[#0d1117] border border-border/30 text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-emerald-500/40 font-mono"
                />
              )}

              {/* Lines */}
              <div className="flex items-center gap-1.5">
                <span className="text-xs text-muted-foreground">Lines:</span>
                <input
                  type="number"
                  value={lines}
                  onChange={e => setLines(Math.max(1, Math.min(10000, parseInt(e.target.value) || 100)))}
                  className="w-16 px-2 py-1.5 rounded-lg text-xs bg-[#0d1117] border border-border/30 text-foreground focus:outline-none focus:border-emerald-500/40 font-mono text-center"
                />
              </div>

              {/* Start button */}
              <button
                onClick={handleStart}
                disabled={starting || (source === 'file' && !filePath)}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-medium bg-emerald-600 text-white hover:bg-emerald-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {starting ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Play className="w-3.5 h-3.5" />
                )}
                Start
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-3">
              {/* Filter */}
              <div className="relative flex-1">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/50" />
                <input
                  type="text"
                  value={filter}
                  onChange={e => setFilter(e.target.value)}
                  placeholder="Filter logs..."
                  className="w-full pl-8 pr-3 py-1.5 rounded-lg text-xs bg-[#0d1117] border border-border/30 text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-emerald-500/40 font-mono"
                />
              </div>

              {/* Line count */}
              <span className="text-xs text-muted-foreground font-mono">{lineCount} lines</span>

              {/* Pause/Resume */}
              <button
                onClick={handlePause}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  paused
                    ? 'bg-amber-500/20 text-amber-400 hover:bg-amber-500/30'
                    : 'bg-white/5 text-muted-foreground hover:text-foreground hover:bg-white/10'
                }`}
              >
                {paused ? (
                  <>
                    <Play className="w-3.5 h-3.5" />
                    Resume
                  </>
                ) : (
                  <>
                    <Pause className="w-3.5 h-3.5" />
                    Pause
                  </>
                )}
              </button>

              {/* Stop */}
              <button
                onClick={handleStop}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors"
              >
                <Square className="w-3.5 h-3.5" />
                Stop
              </button>
            </div>
          )}
        </div>

        {/* Output */}
        <div className="flex-1 overflow-hidden">
          {error ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <p className="text-sm text-red-400 mb-2">{error}</p>
                <button
                  onClick={() => setError(null)}
                  className="text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  Dismiss
                </button>
              </div>
            </div>
          ) : !streaming && !output ? (
            <div className="flex items-center justify-center h-full text-muted-foreground/50">
              <div className="text-center">
                <ScrollText className="w-8 h-8 mx-auto mb-2 opacity-30" />
                <p className="text-sm">Select a source and start streaming</p>
              </div>
            </div>
          ) : (
            <pre
              ref={outputRef}
              onScroll={handleScroll}
              className="h-full overflow-auto p-4 text-xs font-mono text-[#c9d1d9] leading-5 whitespace-pre-wrap break-all selection:bg-emerald-500/30"
            >
              {displayOutput || (streaming ? 'Waiting for output...' : '')}
            </pre>
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 border-t border-border/30 bg-[#161b22]/50 flex items-center justify-between">
          <div className="flex items-center gap-2">
            {streaming && (
              <div className="flex items-center gap-1.5">
                <div className={`w-2 h-2 rounded-full ${paused ? 'bg-amber-400' : 'bg-emerald-400 animate-pulse'}`} />
                <span className="text-xs text-muted-foreground">
                  {paused ? 'Paused' : 'Streaming'}
                </span>
              </div>
            )}
            {!streaming && output && (
              <span className="text-xs text-muted-foreground">Stopped</span>
            )}
          </div>
          <span className="text-xs text-muted-foreground font-mono">{nodeName}</span>
        </div>
      </div>
    </div>
  )
}
