import type { GraphNode } from '@/types'
import { WAVE_RING_COLORS, WAVE_SEED_COLOR } from './constants'

export type ScanRun = { id: string; started_at?: string | null }

export type DiscoveryWaves = {
  // nodeId -> wave (0 = seed: manual, imported or created before provenance existed)
  waveOf: Map<string, number>
  // waves[i] describes wave i + 1; enricher is undefined for a run that created no node
  waves: { scanId: string; enricher?: string }[]
}

// Scan timestamps are naive UTC; without a zone suffix Date.parse would read them as local time.
const toMs = (iso?: string | null) =>
  (iso && Date.parse(/z|[+-]\d\d:?\d\d$/i.test(iso) ? iso : `${iso}Z`)) || Infinity

// Wave N = the Nth enricher run (scan) of this sketch, ordered by start time. Runs that found
// nothing new keep their number; a run whose scan row is gone is placed by its earliest node.
export function computeDiscoveryWaves(nodes: GraphNode[], scans: ScanRun[] = []): DiscoveryWaves {
  const known = new Set(scans.map((s) => s.id))
  const runs = new Map<string, { enricher?: string; at: number }>(
    scans.map((s) => [s.id, { at: toMs(s.started_at) }])
  )
  for (const node of nodes) {
    const { origin, created_by_scan, created_by_enricher, created_at } = node.nodeMetadata
    if (origin !== 'enricher' || !created_by_scan) continue
    const t = toMs(created_at)
    const run = runs.get(created_by_scan)
    if (!run) runs.set(created_by_scan, { enricher: created_by_enricher ?? 'unknown', at: t })
    else {
      run.enricher ??= created_by_enricher ?? 'unknown'
      if (!known.has(created_by_scan) && t < run.at) run.at = t
    }
  }

  const ordered = [...runs.entries()].sort(
    ([a, ra], [b, rb]) => ra.at - rb.at || a.localeCompare(b)
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
