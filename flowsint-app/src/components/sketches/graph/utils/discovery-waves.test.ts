import { describe, it, expect } from 'vitest'
import { computeDiscoveryWaves } from './discovery-waves'
import { GraphNode, NodeMetadata } from '@/types'

const makeNode = (id: string, nodeMetadata: NodeMetadata = {}): GraphNode => ({
  id,
  nodeType: 'test',
  nodeLabel: id,
  nodeProperties: {},
  nodeSize: 1,
  nodeColor: null,
  nodeIcon: null,
  nodeImage: null,
  nodeFlag: null,
  nodeShape: null,
  nodeMetadata,
  x: 0,
  y: 0
})

const found = (id: string, scan: string, created_at: string) =>
  makeNode(id, {
    origin: 'enricher',
    created_by_scan: scan,
    created_by_enricher: `e-${scan}`,
    created_at
  })

const nodes = [
  makeNode('seed', { origin: 'manual', created_at: '2026-01-01T00:00:00Z' }),
  makeNode('legacy'),
  found('b1', 'b', '2026-01-01T00:01:00Z'),
  // "a" started first but wrote its first node later (concurrent runs).
  found('a1', 'a', '2026-01-01T00:05:00Z'),
  found('b2', 'b', '2026-01-01T00:03:00Z')
]

describe('computeDiscoveryWaves', () => {
  it('numbers runs by start time, keeping runs that created nothing', () => {
    // Naive (zone-less) UTC timestamps, as the scans API returns them.
    const scans = [
      { id: 'empty', started_at: '2026-01-01T00:00:10' },
      { id: 'a', started_at: '2026-01-01T00:00:20' },
      { id: 'b', started_at: '2026-01-01T00:00:30' }
    ]
    const { waveOf, waves } = computeDiscoveryWaves(nodes, scans)
    expect(Object.fromEntries(waveOf)).toEqual({ seed: 0, legacy: 0, a1: 2, b1: 3, b2: 3 })
    expect(waves).toEqual([
      { scanId: 'empty', enricher: undefined },
      { scanId: 'a', enricher: 'e-a' },
      { scanId: 'b', enricher: 'e-b' }
    ])
  })

  it('places runs missing from the scan list by their earliest node', () => {
    const { waveOf } = computeDiscoveryWaves(nodes, [
      { id: 'a', started_at: '2026-01-01T00:02:00Z' }
    ])
    expect(Object.fromEntries(waveOf)).toMatchObject({ b1: 1, b2: 1, a1: 2 })
  })
})
