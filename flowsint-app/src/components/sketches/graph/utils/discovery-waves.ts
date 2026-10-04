import type { GraphNode } from '@/types'
import { WAVE_RING_COLORS, WAVE_SEED_COLOR } from './constants'

export type DiscoveryWaves = {
  // nodeId -> wave (0 = seed: manual, imported or created before provenance existed)
  waveOf: Map<string, number>
  // waves[i] describes wave i + 1
  waves: { scanId: string; enricher: string }[]
}

// Wave N = the Nth enricher run (scan) that first created nodes in this sketch,
// ordered by its earliest node creation. Runs that only matched existing nodes leave no trace.
export function computeDiscoveryWaves(nodes: GraphNode[]): DiscoveryWaves {
  const runs = new Map<string, { enricher: string; firstSeen: number }>()
  for (const node of nodes) {
    const { origin, created_by_scan, created_by_enricher, created_at } = node.nodeMetadata
    if (origin !== 'enricher' || !created_by_scan) continue
    const t = Date.parse(created_at ?? '') || Infinity
    const run = runs.get(created_by_scan)
    if (!run)
      runs.set(created_by_scan, { enricher: created_by_enricher ?? 'unknown', firstSeen: t })
    else if (t < run.firstSeen) run.firstSeen = t
  }

  const ordered = [...runs.entries()].sort(
    ([a, ra], [b, rb]) => ra.firstSeen - rb.firstSeen || a.localeCompare(b)
  )
  const waveOfScan = new Map(ordered.map(([scanId], i) => [scanId, i + 1]))

  const waveOf = new Map<string, number>()
  for (const node of nodes) {
    const { origin, created_by_scan } = node.nodeMetadata
    waveOf.set(
      node.id,
      (origin === 'enricher' && created_by_scan && waveOfScan.get(created_by_scan)) || 0
    )
  }
  return {
    waveOf,
    waves: ordered.map(([scanId, run]) => ({ scanId, enricher: run.enricher }))
  }
}

export const waveColor = (wave: number) =>
  wave === 0 ? WAVE_SEED_COLOR : WAVE_RING_COLORS[(wave - 1) % WAVE_RING_COLORS.length]
