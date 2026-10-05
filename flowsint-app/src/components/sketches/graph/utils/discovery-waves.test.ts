import { describe, it, expect } from 'vitest'
import { computeDiscoveryWaves, MAX_WAVE } from './discovery-waves'
import { GraphEdge, GraphNode, NodeMetadata } from '@/types'

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

const edge = (source: string, target: string): GraphEdge => ({
  id: `${source}-${target}`,
  source,
  target,
  label: 'TO'
})

describe('computeDiscoveryWaves', () => {
  it('numbers nodes by shortest pivot path from the seeds', () => {
    const nodes = ['d1', 'd2', 'ip', 'port', 'rev'].map((id) => makeNode(id))
    nodes[2] = makeNode('ip', { created_by_enricher: 'domain_to_ip' })
    // d2 -> ip is a shortcut, so ip stays at wave 1; rev -> ip back-edge changes nothing.
    const edges = [
      edge('d1', 'ip'),
      edge('d2', 'ip'),
      edge('ip', 'port'),
      edge('ip', 'rev'),
      edge('rev', 'ip')
    ]
    const { waveOf, waves } = computeDiscoveryWaves(nodes, edges)
    expect(Object.fromEntries(waveOf)).toEqual({ d1: 0, d2: 0, ip: 1, port: 2, rev: 2 })
    expect(waves).toEqual([
      { nodes: 2, enrichers: [] },
      { nodes: 1, enrichers: ['domain_to_ip'] },
      { nodes: 2, enrichers: [] }
    ])
  })

  it('enters a seedless cycle at its first node and caps deep chains', () => {
    const ids = Array.from({ length: MAX_WAVE + 3 }, (_, i) => `n${i}`)
    const nodes = [...ids, 'a', 'b'].map((id) => makeNode(id))
    const edges = [...ids.slice(1).map((id, i) => edge(ids[i], id)), edge('a', 'b'), edge('b', 'a')]
    const { waveOf, waves } = computeDiscoveryWaves(nodes, edges)
    expect(waveOf.get('a')).toBe(0)
    expect(waveOf.get('b')).toBe(1)
    expect(waveOf.get(ids.at(-1)!)).toBe(MAX_WAVE)
    expect(waves).toHaveLength(MAX_WAVE + 1)
    expect(waves[MAX_WAVE].nodes).toBe(3)
  })
})
