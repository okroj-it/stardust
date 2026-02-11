import { cn } from "@/lib/utils"

interface MiniChartProps {
  data: number[]
  height?: number
  color?: string
  className?: string
}

export function MiniChart({ data, height = 40, color = "var(--primary)", className }: MiniChartProps) {
  if (data.length < 2) return null

  const max = Math.max(...data, 1)
  const min = 0
  const range = max - min || 1
  const w = 200
  const h = height

  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w
    const y = h - ((v - min) / range) * h
    return `${x},${y}`
  })

  const fillPoints = [`0,${h}`, ...points, `${w},${h}`].join(" ")
  const linePoints = points.join(" ")

  return (
    <div className={cn("w-full", className)}>
      <svg
        viewBox={`0 0 ${w} ${h}`}
        preserveAspectRatio="none"
        className="w-full"
        style={{ height }}
      >
        <defs>
          <linearGradient id={`grad-${color.replace(/[^a-z0-9]/gi, '')}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.3" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
        </defs>
        <polygon
          points={fillPoints}
          fill={`url(#grad-${color.replace(/[^a-z0-9]/gi, '')})`}
        />
        <polyline
          points={linePoints}
          fill="none"
          stroke={color}
          strokeWidth="2"
          strokeLinejoin="round"
          strokeLinecap="round"
          vectorEffect="non-scaling-stroke"
        />
      </svg>
    </div>
  )
}
