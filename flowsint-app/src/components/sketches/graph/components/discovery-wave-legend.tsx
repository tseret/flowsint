import { useGraphStore } from '@/stores/graph-store'
import { cn } from '@/lib/utils'
import type { DiscoveryWaves } from '../utils/discovery-waves'
import { MAX_WAVE, waveColor } from '../utils/discovery-waves'

export function DiscoveryWaveLegend({ waves }: Pick<DiscoveryWaves, 'waves'>) {
  const hiddenWaves = useGraphStore((s) => s.filters.hiddenWaves)
  const toggleWaveFilter = useGraphStore((s) => s.toggleWaveFilter)
  return (
    <div className="absolute bottom-16 left-3 max-h-48 max-w-72 overflow-y-auto rounded-lg border border-border bg-background/90 px-2 py-1.5 text-xs backdrop-blur-sm">
      <div className="mb-1 font-medium text-muted-foreground">Pivot depth</div>
      {waves.map(({ nodes, enrichers }, wave) => {
        if (!nodes) return null
        const hidden = hiddenWaves.includes(wave)
        return (
          <button
            key={wave}
            type="button"
            aria-pressed={!hidden}
            onClick={() => toggleWaveFilter(wave)}
            className={cn(
              'flex w-full items-center gap-1.5 rounded px-0.5 text-left hover:bg-muted',
              hidden && 'opacity-50 line-through'
            )}
            title={`${hidden ? 'Show' : 'Hide'} this depth${enrichers.length ? ` · ${enrichers.join(', ')}` : ''}`}
          >
            <span
              className="h-2.5 w-2.5 shrink-0 rounded-full border-2"
              style={{ borderColor: waveColor(wave) }}
            />
            <span className="truncate">
              {wave ? `Pivot ${wave}${wave === MAX_WAVE ? '+' : ''}` : 'Seeds'} · {nodes}
              {enrichers.length > 0 && (
                <span className="text-muted-foreground"> · {enrichers.join(', ')}</span>
              )}
            </span>
          </button>
        )
      })}
    </div>
  )
}
