import type { DiscoveryWaves } from '../utils/discovery-waves'
import { waveColor } from '../utils/discovery-waves'

export function DiscoveryWaveLegend({ waves }: Pick<DiscoveryWaves, 'waves'>) {
  return (
    <div className="absolute bottom-16 left-3 max-h-48 overflow-y-auto rounded-lg border border-border bg-background/90 px-2 py-1.5 text-xs backdrop-blur-sm">
      <div className="mb-1 font-medium text-muted-foreground">Discovery waves</div>
      {[{ scanId: 'seed', enricher: 'Seeds', nodes: 1 }, ...waves].map(
        ({ scanId, enricher, nodes }, wave) => (
          <div key={scanId} className="flex items-center gap-1.5" title={wave ? scanId : undefined}>
            <span
              className="h-2.5 w-2.5 shrink-0 rounded-full border-2"
              style={{ borderColor: waveColor(wave) }}
            />
            <span className="truncate">
              {wave
                ? `${wave}. ${enricher ?? 'unknown'}${nodes ? '' : ' · no new nodes'}`
                : enricher}
            </span>
          </div>
        )
      )}
    </div>
  )
}
