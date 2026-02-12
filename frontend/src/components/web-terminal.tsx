import { useEffect, useRef, useState } from "react"
import { Terminal } from "@xterm/xterm"
import { FitAddon } from "@xterm/addon-fit"
import "@xterm/xterm/css/xterm.css"
import { getToken } from "@/lib/auth"
import { X, Terminal as TerminalIcon } from "lucide-react"

interface WebTerminalProps {
  nodeId: string
  nodeName: string
  onClose: () => void
}

export function WebTerminal({ nodeId, nodeName, onClose }: WebTerminalProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const termRef = useRef<Terminal | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const [status, setStatus] = useState<'connecting' | 'ready' | 'closed' | 'error'>('connecting')

  useEffect(() => {
    if (!containerRef.current) return

    // Load Nerd Font symbols as fallback for powerline glyphs
    const nerdFont = new FontFace(
      'Symbols Nerd Font Mono',
      'url(https://cdn.jsdelivr.net/gh/ryanoasis/nerd-fonts@latest/patched-fonts/NerdFontsSymbolsOnly/SymbolsNerdFontMono-Regular.ttf)',
    )
    nerdFont.load().then((loaded) => {
      document.fonts.add(loaded)
    }).catch(() => { /* font load failed, local fonts may still work */ })

    const term = new Terminal({
      theme: {
        background: '#0d1117',
        foreground: '#c9d1d9',
        cursor: '#58a6ff',
        selectionBackground: '#58a6ff33',
        black: '#0d1117',
        red: '#f85149',
        green: '#7ee787',
        yellow: '#e3b341',
        blue: '#58a6ff',
        magenta: '#bc8cff',
        cyan: '#76e3ea',
        white: '#c9d1d9',
        brightBlack: '#484f58',
        brightRed: '#ff7b72',
        brightGreen: '#7ee787',
        brightYellow: '#e3b341',
        brightBlue: '#79c0ff',
        brightMagenta: '#d2a8ff',
        brightCyan: '#76e3ea',
        brightWhite: '#f0f6fc',
      },
      fontFamily: '"JetBrainsMono Nerd Font Mono", "JetBrainsMono NF", "FiraCode Nerd Font Mono", "Hack Nerd Font Mono", "MesloLGS NF", "Symbols Nerd Font Mono", ui-monospace, "SF Mono", "Cascadia Code", Menlo, monospace',
      fontSize: 14,
      cursorBlink: true,
      cursorStyle: 'bar',
      allowProposedApi: true,
    })

    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(containerRef.current)
    fit.fit()

    termRef.current = term
    fitRef.current = fit

    // Connect WebSocket
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${location.host}/ws/terminal`)
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws

    ws.onopen = () => {
      const token = getToken()
      fit.fit()
      const dims = fit.proposeDimensions()
      ws.send(JSON.stringify({
        type: 'auth',
        token,
        node_id: nodeId,
        cols: dims?.cols ?? 80,
        rows: dims?.rows ?? 24,
      }))
    }

    ws.onmessage = (event) => {
      if (typeof event.data === 'string') {
        // Text frame = JSON control message
        try {
          const msg = JSON.parse(event.data)
          if (msg.type === 'ready') {
            setStatus('ready')
            term.focus()
          } else if (msg.type === 'error') {
            setStatus('error')
            term.writeln(`\r\n\x1b[31mError: ${msg.message}\x1b[0m`)
          } else if (msg.type === 'closed') {
            setStatus('closed')
            term.writeln('\r\n\x1b[33mSession ended.\x1b[0m')
          }
        } catch { /* ignore parse errors */ }
      } else {
        // Binary frame = terminal data
        term.write(new Uint8Array(event.data))
      }
    }

    ws.onclose = () => {
      if (status !== 'error') {
        setStatus('closed')
        term.writeln('\r\n\x1b[33mDisconnected.\x1b[0m')
      }
    }

    ws.onerror = () => {
      setStatus('error')
      term.writeln('\r\n\x1b[31mWebSocket connection failed.\x1b[0m')
    }

    // Terminal input → WebSocket binary
    const dataDisposable = term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(new TextEncoder().encode(data))
      }
    })

    // Resize handling
    const handleWindowResize = () => {
      fit.fit()
      const dims = fit.proposeDimensions()
      if (dims && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'resize',
          cols: dims.cols,
          rows: dims.rows,
        }))
      }
    }
    window.addEventListener('resize', handleWindowResize)

    // Cleanup
    return () => {
      window.removeEventListener('resize', handleWindowResize)
      dataDisposable.dispose()
      ws.close()
      term.dispose()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeId])

  const canClose = status !== 'connecting'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={canClose ? onClose : undefined}
      />
      <div className="relative w-full max-w-5xl mx-4 rounded-2xl border border-border/50 bg-[#0d1117] shadow-2xl animate-in fade-in zoom-in-95 duration-200 flex flex-col" style={{ height: '80vh' }}>
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border/30 bg-[#161b22] rounded-t-2xl">
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-[#ff5f57]" />
              <div className="w-3 h-3 rounded-full bg-[#febc2e]" />
              <div className="w-3 h-3 rounded-full bg-[#28c840]" />
            </div>
            <div className="flex items-center gap-2">
              <TerminalIcon className="w-3.5 h-3.5 text-[#8b949e]" />
              <span className="text-xs text-[#8b949e] font-mono">{nodeName}</span>
              <span className="text-[10px] text-[#58a6ff] bg-[#58a6ff]/10 px-1.5 py-0.5 rounded font-mono">SSH</span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-[#30363d] transition-colors"
          >
            <X className="w-4 h-4 text-[#8b949e]" />
          </button>
        </div>

        {/* Terminal */}
        <div
          className="flex-1 min-h-0 p-1"
          ref={containerRef}
          style={{ background: '#0d1117' }}
        />

        {/* Status bar */}
        <div className="flex items-center px-4 py-1.5 border-t border-border/30 bg-[#161b22] rounded-b-2xl">
          <span className="text-[10px] text-[#8b949e] font-mono flex items-center gap-1.5">
            <div className={`w-1.5 h-1.5 rounded-full ${
              status === 'ready' ? 'bg-emerald-400' :
              status === 'connecting' ? 'bg-amber-400 animate-pulse' :
              status === 'error' ? 'bg-red-400' :
              'bg-[#484f58]'
            }`} />
            {status === 'ready' && 'Connected'}
            {status === 'connecting' && 'Connecting...'}
            {status === 'closed' && 'Disconnected'}
            {status === 'error' && 'Connection failed'}
          </span>
        </div>
      </div>
    </div>
  )
}
