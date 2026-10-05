import type { GraphEdge, GraphNode } from '@/types'
import { WAVE_RING_COLORS, WAVE_SEED_COLOR } from './constants'

export type DiscoveryWaves = {
  // nodeId -> wave: pivot steps from a seed, capped at the last ring color ("N+")
  waveOf: Map<string, number>
  // waves[w] = nodes in wave w and the enrichers that created them (when recorded)
  waves: { nodes: number; enrichers: string[] }[]
}

export const MAX_WAVE = WAVE_RING_COLORS.length

// Wave = shortest pivot path from a seed along edge direction (enrichers link input -> output).
// Seeds are nodes nothing points to; a cycle no seed reaches is entered at its first node.
export function computeDiscoveryWaves(nodes: GraphNode[], edges: GraphEdge[]): DiscoveryWaves {
  const out = new Map<string, string[]>()
  const pointedTo = new Set<string>()
  for (const { source, target } of edges) {
    if (source === target) continue
    const targets = out.get(source)
    if (targets) targets.push(target)
    else out.set(source, [target])
    pointedTo.add(target)
  }

  const hop = new Map<string, number>()
  const bfs = (starts: string[]) => {
    for (const id of starts) hop.set(id, 0)
    for (let i = 0; i < starts.length; i++) {
      const next = hop.get(starts[i])! + 1
      for (const target of out.get(starts[i]) ?? []) {
        if (hop.has(target)) continue
        hop.set(target, next)
        starts.push(target)
      }
    }
  }
  bfs(nodes.filter((n) => !pointedTo.has(n.id)).map((n) => n.id))
  for (const n of nodes) if (!hop.has(n.id)) bfs([n.id])

  const waveOf = new Map<string, number>()
  const waves: { nodes: number; enrichers: Set<string> }[] = []
  for (const n of nodes) {
    const wave = Math.min(hop.get(n.id)!, MAX_WAVE)
    waveOf.set(n.id, wave)
    for (let w = waves.length; w <= wave; w++) waves.push({ nodes: 0, enrichers: new Set() })
    waves[wave].nodes++
    const enricher = n.nodeMetadata.created_by_enricher
    if (wave && enricher) waves[wave].enrichers.add(enricher)
  }
  return {
    waveOf,
    waves: waves.map(({ nodes, enrichers }) => ({ nodes, enrichers: [...enrichers].sort() }))
  }
}

export const waveColor = (wave: number) =>
  wave === 0 ? WAVE_SEED_COLOR : WAVE_RING_COLORS[Math.min(wave, MAX_WAVE) - 1]
