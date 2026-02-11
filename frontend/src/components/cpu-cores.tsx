import { cn } from "@/lib/utils"

interface CpuCoresProps {
  cores: Array<{ core_id: number; usage_percent: number }>
  className?: string
}

function getBarColor(pct: number): string {
  if (pct < 30) return "bg-emerald-500"
  if (pct < 60) return "bg-amber-500"
  if (pct < 85) return "bg-orange-500"
  return "bg-red-500"
}

export function CpuCores({ cores, className }: CpuCoresProps) {
  return (
    <div className={cn("space-y-1.5", className)}>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-foreground">CPU Cores</h3>
        <span className="text-xs text-muted-foreground">{cores.length} cores</span>
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1">
        {cores.map((core) => (
          <div key={core.core_id} className="flex items-center gap-2">
            <span className="text-[10px] text-muted-foreground w-5 text-right font-mono">
              {core.core_id}
            </span>
            <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
              <div
                className={cn(
                  "h-full rounded-full transition-all duration-500 ease-out",
                  getBarColor(core.usage_percent)
                )}
                style={{ width: `${Math.max(core.usage_percent, 0.5)}%` }}
              />
            </div>
            <span className="text-[10px] text-muted-foreground w-8 text-right font-mono">
              {core.usage_percent.toFixed(0)}%
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
