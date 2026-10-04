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

const found = (id: string, scan_id: string, created_at: string) =>
  makeNode(id, { origin: 'enricher', scan_id, enricher: `e-${scan_id}`, created_at })

const nodes = [
  makeNode('seed', { origin: 'manual', created_at: '2026-01-01T00:00:00Z' }),
  makeNode('legacy'),
  // Run "b" started first, so it is wave 1 even though its id sorts later.
  found('b1', 'b', '2026-01-01T00:01:00Z'),
  found('a1', 'a', '2026-01-01T00:02:00Z'),
  found('b2', 'b', '2026-01-01T00:03:00Z')
]

describe('computeDiscoveryWaves', () => {
  it('numbers enricher runs by first creation and treats the rest as seeds', () => {
    const { waveOf, waves } = computeDiscoveryWaves(nodes)
    expect(Object.fromEntries(waveOf)).toEqual({ seed: 0, legacy: 0, b1: 1, b2: 1, a1: 2 })
    expect(waves).toEqual([
      { scanId: 'b', enricher: 'e-b' },
      { scanId: 'a', enricher: 'e-a' }
    ])
  })
})
