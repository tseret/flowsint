import { expect, it } from 'vitest'
import { performance } from 'node:perf_hooks'
import {
  infrastructureOverview,
  boundedNeighborhood,
  compareHosts,
  compareObservationDates
} from './infrastructure-analysis'
import { applyLayoutPositions } from '@/hooks/use-layout'
import type { GraphNode, GraphEdge } from '@/types'

// Reproducible CPU benchmark only: no provider calls, database writes or renderer FPS claims.
it.each([1000, 10000, 100000])('benchmarks infrastructure helpers with %i entities', (count) => {
  const nodes: GraphNode[] = Array.from({ length: count }, (_, i) => ({
    id: String(i),
    nodeType: i % 2 ? 'port' : 'ip',
    nodeLabel: String(i),
    nodeProperties:
      i % 2
        ? { number: 443, protocol: 'TCP', fingerprints: { jarm: 'shared' } }
        : { asn: `AS${i % 200}` },
    nodeMetadata: {},
    nodeSize: 5,
    nodeColor: null,
    nodeIcon: null,
    nodeImage: null,
    nodeFlag: null,
    nodeShape: null,
    x: i,
    y: i % 100
  }))
  const edges: GraphEdge[] = Array.from({ length: count - 1 }, (_, i) => ({
    id: `e${i}`,
    source: String(i % 2 ? i - 1 : i),
    target: String(i + 1),
    label: i % 2 ? 'RELATED_TO' : 'HAS_PORT',
    observations: [
      { provider: 'fixture', observed_at: '2026-10-01', evidence: { state: 'open' } },
      { provider: 'fixture', observed_at: '2026-10-02', evidence: { state: 'filtered' } }
    ]
  }))
  const positions = nodes.map((node) => ({ id: node.id, x: node.x + 1, y: node.y + 1 }))
  const timings: Record<string, number> = {}
  const measure = <T>(name: string, action: () => T): T => {
    const start = performance.now()
    const result = action()
    timings[name] = Math.round((performance.now() - start) * 100) / 100
    return result
  }
  const overview = measure('overview_ms', () =>
    infrastructureOverview(nodes, edges, 'asn', new Set())
  )
  const focus = measure('focus_ms', () => boundedNeighborhood(nodes, edges, ['0']))
  const hosts = measure('compare_12_hosts_ms', () =>
    compareHosts(
      nodes,
      edges,
      Array.from({ length: 12 }, (_, i) => String(i * 2))
    )
  )
  const changes = measure('compare_dates_ms', () =>
    compareObservationDates(edges, '2026-10-01', '2026-10-02')
  )
  measure('apply_layout_ms', () => applyLayoutPositions(nodes, positions))
  expect(overview.groups).toHaveLength(100)
  expect(focus.nodes.length).toBeLessThanOrEqual(500)
  expect(hosts).toHaveLength(66)
  expect(changes.changed).toHaveLength(count - 1)
  expect(nodes[count - 1].x).toBe(count)
  console.info(JSON.stringify({ entities: count, relationships: edges.length, ...timings }))
})
