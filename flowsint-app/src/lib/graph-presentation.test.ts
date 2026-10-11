import { describe, it, expect } from 'vitest'
import type { GraphNode, GraphEdge } from '@/types/graph'
import {
  edgeMatchesEvidence,
  preserveGraphPositions,
  graphChanges,
  compactPivotGraph,
  edgeDisplayLabel,
  fingerprintPivotEvidence
} from './graph-presentation'

const node = (id: string, overrides: Partial<GraphNode> = {}): GraphNode => ({
  id,
  nodeType: 'ip',
  nodeLabel: id,
  nodeProperties: {},
  nodeMetadata: {},
  nodeSize: 1,
  nodeColor: null,
  nodeIcon: null,
  nodeImage: null,
  nodeFlag: null,
  nodeShape: null,
  x: 0,
  y: 0,
  ...overrides
})
const edge: GraphEdge = { id: 'edge', source: 'a', target: 'b', label: 'resolves' }

describe('compact fingerprint pivots', () => {
  const nodes = [
    node('a', { nodeProperties: { address: '192.0.2.1' } }),
    node('b', { nodeProperties: { address: '192.0.2.2' } }),
    node('source-port', {
      nodeType: 'port',
      nodeProperties: { host: '192.0.2.1', number: 22, protocol: 'TCP', service: 'SSH' }
    }),
    node('candidate-port', {
      nodeType: 'port',
      nodeProperties: { host: '192.0.2.2', number: 22, protocol: 'tcp', service: 'ssh' }
    }),
    node('unrelated-port', {
      nodeType: 'port',
      nodeProperties: { host: '192.0.2.2', number: 443, protocol: 'tcp', service: 'https' }
    })
  ]
  const observation = {
    evidence: {
      query: 'port=22 ssh.hassh="hash"',
      source: {
        service_id: 'source-port',
        host: '192.0.2.1',
        port: 22,
        transport: 'tcp',
        service: 'ssh'
      },
      candidate: { ip: '192.0.2.2', port: 22, transport: 'TCP', protocol: 'SSH' },
      matching_fingerprints: ['ssh.hassh']
    }
  }
  const pivot: GraphEdge = {
    id: 'pivot',
    source: 'a',
    target: 'b',
    label: 'SHARES_FINGERPRINT',
    caption: 'Shared SSH HASSH · port 22',
    observations: [observation]
  }
  const edges: GraphEdge[] = [
    { id: 'a-port', source: 'a', target: 'source-port', label: 'HAS_PORT' },
    { id: 'b-port', source: 'b', target: 'candidate-port', label: 'HAS_PORT' },
    { id: 'other-port', source: 'b', target: 'unrelated-port', label: 'HAS_PORT' },
    pivot
  ]
  it('hides only matching pivot services and keeps full input graph/evidence untouched', () => {
    const result = compactPivotGraph(nodes, edges)
    expect(result.nodes.map((node) => node.id)).toEqual(['a', 'b', 'unrelated-port'])
    expect(result.edges.map((edge) => edge.id)).toEqual(['other-port', 'pivot'])
    expect(result.edges[1]).toBe(pivot)
    expect(nodes).toHaveLength(5)
    expect(edges).toHaveLength(4)
    expect(compactPivotGraph(nodes, edges, { expanded: true })).toEqual({ nodes, edges })
  })
  it('preserves selected services and endpoints of selected evidence links', () => {
    expect(
      compactPivotGraph(nodes, edges, { selectedNodeIds: ['source-port'] }).nodes.map(
        (node) => node.id
      )
    ).toContain('source-port')
    expect(
      compactPivotGraph(nodes, edges, { selectedEdgeIds: ['b-port'] }).nodes.map((node) => node.id)
    ).toContain('candidate-port')
  })
  it('keeps ports with other evidence relationships visible', () => {
    const result = compactPivotGraph(nodes, [
      ...edges,
      { id: 'evidence', source: 'source-port', target: 'unrelated-port', label: 'USES_CERTIFICATE' }
    ])
    expect(result.nodes.map((node) => node.id)).toContain('source-port')
    expect(result.edges.map((edge) => edge.id)).toContain('evidence')
  })
  it('does not collapse ambiguous ownership or mismatched host/number/protocol', () => {
    expect(
      compactPivotGraph(nodes, [
        ...edges,
        { id: 'ambiguous', source: 'a', target: 'candidate-port', label: 'HAS_PORT' }
      ]).nodes
    ).toEqual(nodes)
    for (const property of [
      { host: 'other' },
      { number: 23 },
      { protocol: 'udp' },
      { service: 'http' }
    ]) {
      const changed = nodes.map((node) =>
        node.id === 'candidate-port'
          ? { ...node, nodeProperties: { ...node.nodeProperties, ...property } }
          : node
      )
      expect(compactPivotGraph(changed, edges).nodes).toEqual(changed)
    }
  })
  it('handles null or missing snapshots without collapsing services', () => {
    for (const observations of [undefined, [null], [{ evidence: null }], [{ evidence: {} }]]) {
      expect(
        compactPivotGraph(nodes, [...edges.slice(0, 3), { ...pivot, observations } as GraphEdge])
          .nodes
      ).toEqual(nodes)
    }
    expect(fingerprintPivotEvidence(null)).toBeNull()
  })
  it('does not collapse services for legacy service-to-service pivot links', () => {
    expect(
      compactPivotGraph(nodes, [
        ...edges.slice(0, 3),
        { ...pivot, source: 'source-port', target: 'candidate-port' }
      ]).nodes
    ).toEqual(nodes)
  })
  it('uses a readable caption without changing the relationship type', () => {
    expect(edgeDisplayLabel(pivot)).toBe('Shared SSH HASSH · port 22')
    expect(edgeDisplayLabel({ label: 'HAS_PORT', caption: '' })).toBe('HAS_PORT')
    expect(
      graphChanges(nodes, [{ ...pivot, caption: 'Updated caption' }], nodes, [pivot]).updatedEdges
    ).toEqual(['pivot'])
  })
})

describe('enrichment graph refresh', () => {
  it('retains local positions and pins while accepting enriched properties', () => {
    const result = preserveGraphPositions(
      [node('a', { nodeProperties: { reputation: 80 } })],
      [node('a', { x: 12, y: 34 })],
      []
    )
    expect(result[0]).toMatchObject({
      x: 12,
      y: 34,
      fx: 12,
      fy: 34,
      nodeProperties: { reputation: 80 }
    })
  })
  it('places new neighbors deterministically nearby without moving existing nodes', () => {
    const incoming = [node('a'), node('b')]
    const old = [node('a', { x: 100, y: 200 })]
    const result = preserveGraphPositions(incoming, old, [edge])
    expect(result).toEqual(preserveGraphPositions(incoming, old, [edge]))
    expect(result[1].x).not.toBe(0)
    expect(Math.hypot(result[1].x - 100, result[1].y - 200)).toBeLessThan(100)
  })
  it('does not report position changes as evidence changes', () => {
    expect(graphChanges([node('a', { x: 12 })], [], [node('a')], []).updatedNodes).toEqual([])
    expect(
      graphChanges(
        [node('a', { nodeMetadata: { scan_id: 'run' } }), node('b')],
        [edge],
        [node('a')],
        []
      )
    ).toMatchObject({ updatedNodes: ['a'], addedNodes: ['b'], addedEdges: ['edge'] })
  })
})

describe('evidence filters', () => {
  const observations = [
    { provider: 'provider A', observed_at: '2026-09-01T12:00:00Z' },
    { provider: 'provider B', observed_at: '2026-10-01T12:00:00Z' }
  ]
  it('requires provider and date to match the same observation', () => {
    expect(
      edgeMatchesEvidence(
        { ...edge, observations },
        { types: [], rules: [], provider: 'provider A', observedAfter: '2026-09-15' }
      )
    ).toBe(false)
    expect(
      edgeMatchesEvidence(
        { ...edge, observations },
        { types: [], rules: [], provider: 'provider B', observedAfter: '2026-09-15' }
      )
    ).toBe(true)
  })
  it('keeps unknown evidence unfiltered unless a source/date filter is active', () => {
    expect(edgeMatchesEvidence(edge, { types: [], rules: [] })).toBe(true)
    expect(edgeMatchesEvidence(edge, { types: [], rules: [], observedBefore: '2026-10-01' })).toBe(
      false
    )
  })
  it('filters relationship type independently of evidence and includes end dates', () => {
    expect(
      edgeMatchesEvidence(
        { ...edge, observations },
        {
          types: [],
          rules: [],
          relationship: 'resolves',
          observedAfter: '2026-10-01',
          observedBefore: '2026-10-01'
        }
      )
    ).toBe(true)
    expect(edgeMatchesEvidence(edge, { types: [], rules: [], relationship: 'contains' })).toBe(
      false
    )
  })
})
