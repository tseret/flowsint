import { describe, it, expect } from 'vitest'
import type { GraphNode, GraphEdge } from '@/types/graph'
import { edgeMatchesEvidence, preserveGraphPositions, graphChanges } from './graph-presentation'

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
