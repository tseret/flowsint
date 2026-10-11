import { describe, expect, it } from 'vitest'
import {
  boundedNeighborhood,
  compareHosts,
  compareObservationDates,
  parseObservationDate,
  infrastructureOverview
} from './infrastructure-analysis'
import type { GraphEdge, GraphNode } from '@/types'

const node = (id: string, nodeType = 'ip', nodeProperties = {}): GraphNode => ({
  id,
  nodeType,
  nodeLabel: id,
  nodeProperties,
  nodeMetadata: {},
  nodeSize: 5,
  nodeColor: null,
  nodeIcon: null,
  nodeImage: null,
  nodeFlag: null,
  nodeShape: null,
  x: 10,
  y: 20
})
const edge = (source: string, target: string, label = 'RELATED_TO'): GraphEdge => ({
  id: `${source}-${target}`,
  source,
  target,
  label
})

describe('infrastructure overview', () => {
  it('aggregates hosts and exclusive service details, counts crossgroup links, and preserves expanded positions', () => {
    const nodes = [
      node('a'),
      node('b'),
      node('c'),
      node('AS1', 'asn'),
      node('AS2', 'asn'),
      node('port', 'port')
    ]
    const edges = [
      edge('a', 'AS1'),
      edge('b', 'AS1'),
      edge('c', 'AS2'),
      edge('a', 'port', 'HAS_PORT'),
      edge('a', 'c'),
      edge('b', 'c')
    ]
    const overview = infrastructureOverview(nodes, edges, 'asn', new Set())
    expect(overview.nodes).toHaveLength(2)
    expect(overview.groups.map((group) => [group.hosts, group.members.length])).toEqual([
      [2, 4],
      [1, 2]
    ])
    expect(overview.edges).toHaveLength(1)
    expect(overview.edges[0].weight).toBe(2)
    const expanded = infrastructureOverview(nodes, edges, 'asn', new Set([overview.groups[0].id]))
    expect(expanded.nodes.find((item) => item.id === 'a')).not.toBe(nodes[0])
    expect(nodes[0]).toMatchObject({ x: 10, y: 20 })
    expect(expanded.nodes.find((item) => item.id === overview.groups[1].id)?.nodeLabel).toEqual(
      overview.nodes[1].nodeLabel
    )
    expect(nodes.every((item) => !item.nodeProperties.infrastructure_group)).toBe(true)
  })
  it('keeps shared detail visible and labels missing memberships', () => {
    const nodes = [
      node('a', 'ip', { asn: 'AS1' }),
      node('b', 'ip', { asn: 'AS2' }),
      node('cert', 'certificate'),
      node('unknown')
    ]
    const overview = infrastructureOverview(
      nodes,
      [edge('a', 'cert'), edge('b', 'cert')],
      'asn',
      new Set()
    )
    expect(overview.nodes.find((item) => item.id === 'cert')).toMatchObject({
      id: 'cert',
      nodeType: 'certificate'
    })
    expect(overview.groups.some((group) => group.label === 'No recorded asn')).toBe(true)
  })
})
it('bounds a single neighborhood without implicitly expanding another hop or moving nodes', () => {
  const nodes = ['a', 'b', 'c', 'd'].map((id) => node(id))
  const edges = [edge('a', 'b'), edge('a', 'c'), edge('b', 'd')]
  const result = boundedNeighborhood(nodes, edges, ['a'], 2)
  expect(result.nodes.map((item) => item.id)).toEqual(['a', 'b'])
  expect(result.nodes[0]).toBe(nodes[0])
  expect(result.truncated).toBe(true)
  expect(boundedNeighborhood(nodes, edges, ['a']).nodes.map((item) => item.id)).toEqual([
    'a',
    'b',
    'c'
  ])
})
it('compares stored services with exact fingerprint reasons, frequency, differences and dates', () => {
  const nodes = [
    node('a'),
    node('b'),
    node('c'),
    node('pa', 'port', {
      number: 443,
      protocol: 'TCP',
      service: 'https',
      fingerprints: { jarm: 'same', cert: 'left' }
    }),
    node('pb', 'port', {
      number: 443,
      protocol: 'tcp',
      service: 'https',
      fingerprints: { jarm: 'same', cert: 'right' }
    }),
    node('pc', 'port', { number: 22, protocol: 'TCP' })
  ]
  const edges = [
    edge('a', 'pa', 'HAS_PORT'),
    edge('b', 'pb', 'HAS_PORT'),
    edge('c', 'pc', 'HAS_PORT')
  ]
  edges[0].observations = [{ provider: 'Modat', observed_at: '2026-10-01' }]
  const comparisons = compareHosts(nodes, edges, ['a', 'c', 'b'])
  expect(comparisons[0].sharedServices).toEqual(['443/tcp'])
  expect(comparisons[0].fingerprints).toEqual(['443/tcp jarm=same (2/3 loaded hosts)'])
  expect(comparisons[0].differences).toContain('443/tcp cert: left vs right')
  expect(comparisons[0].evidence[0].observations[0]).toMatchObject({
    provider: 'Modat',
    observed_at: '2026-10-01'
  })
})
it('compares observations on exact dates without using retrieval time as observation time', () => {
  const relationship = edge('a', 'b')
  relationship.observations = [
    { provider: 'one', observed_at: '2026-10-01T01:00:00Z', evidence: { cert: 'old' } },
    { provider: 'one', observed_at: '2026-10-02T01:00:00Z', evidence: { cert: 'new' } },
    { provider: 'two', observed_at: '2026-10-02T01:00:00Z', evidence: { cert: 'other' } },
    { provider: 'unknown', retrieved_at: '2026-10-02T01:00:00Z' }
  ]
  const missing = {
    ...edge('a', 'c'),
    observations: [{ provider: 'one', observed_at: '2026-10-01' }]
  }
  const result = compareObservationDates([relationship, missing], '2026-10-01', '2026-10-02')
  expect(result.changed).toHaveLength(1)
  expect(result.changed[0].previous.evidence).toEqual({ cert: 'old' })
  expect(result.added).toHaveLength(1)
  expect(result.notReobserved[0].edge.target).toBe('c')
  expect(result.disagreements).toHaveLength(1)
  expect(result.undated).toBe(1)
  expect(compareObservationDates([relationship], '2026-10-01', '2026-10-01').undated).toBe(1)
})
it('ignores evidence object key ordering and chooses the last observation on each day', () => {
  const relationship = {
    ...edge('a', 'b'),
    observations: [
      { provider: 'one', observed_at: '2026-10-01T10:00:00Z', evidence: { a: 1, b: 2 } },
      { provider: 'one', observed_at: '2026-10-02T01:00:00Z', evidence: { a: 2 } },
      { provider: 'one', observed_at: '2026-10-02T10:00:00Z', evidence: { b: 2, a: 1 } }
    ]
  }
  expect(compareObservationDates([relationship], '2026-10-01', '2026-10-02').changed).toEqual([])
})

it('retains duplicate endpoint records and compares actual dated provider evidence', () => {
  const nodes = [
    node('a'),
    node('b'),
    node('p1', 'port', { number: 443, protocol: 'TCP', fingerprints: { cert: 'shared' } }),
    node('p2', 'port', { number: 443, protocol: 'TCP', fingerprints: { cert: 'changed' } }),
    node('p3', 'port', { number: 443, protocol: 'TCP', fingerprints: { cert: 'shared' } })
  ]
  const first = {
    ...edge('a', 'p1', 'HAS_PORT'),
    observations: [
      { provider: 'one', observed_at: '2026-10-01', evidence: { fingerprints: { cert: 'shared' } } }
    ]
  }
  const second = {
    ...edge('a', 'p2', 'HAS_PORT'),
    observations: [
      {
        provider: 'two',
        observed_at: '2026-10-01',
        evidence: { fingerprints: { cert: 'changed' } }
      }
    ]
  }
  const result = compareHosts(nodes, [first, second, edge('b', 'p3', 'HAS_PORT')], ['a', 'b'])[0]
  expect(result.evidence).toHaveLength(3)
  expect(result.fingerprints).toContain('443/tcp cert=shared (2/2 loaded hosts)')
  expect(result.differences.some((item) => item.includes('provider evidence differs'))).toBe(true)
})
it('compares UTC dates when source observation timestamps include an offset', () => {
  const relationship = {
    ...edge('a', 'b'),
    observations: [{ provider: 'one', observed_at: '2026-10-02T01:00:00+02:00' }]
  }
  expect(compareObservationDates([relationship], '2026-10-01', '2026-10-02').beforeCount).toBe(1)
})

it('accepts explicit timezones and date-only observations, excluding ambiguous local timestamps', () => {
  expect(parseObservationDate('2026-10-05T03:12:37.176374')).toBeNull()
  expect(parseObservationDate('2026-10-05T03:12:37')).toBeNull()
  expect(parseObservationDate('2026-02-30')).toBeNull()
  expect(parseObservationDate('2026-10-05')).toMatchObject({ day: '2026-10-05' })
  expect(parseObservationDate('2026-10-05T03:12:37.176374Z')).toMatchObject({ day: '2026-10-05' })
  expect(parseObservationDate('2026-10-05T01:12:37+02:00')).toMatchObject({ day: '2026-10-04' })
  expect(parseObservationDate('2026-10-05T23:12:37-0200')).toMatchObject({ day: '2026-10-06' })
  const relationship = {
    ...edge('a', 'b'),
    observations: [
      { provider: 'naive', observed_at: '2026-10-05T03:12:37.176374' },
      { provider: 'dated', observed_at: '2026-10-05' },
      { provider: 'offset', observed_at: '2026-10-06T01:12:37+02:00' }
    ]
  }
  const result = compareObservationDates([relationship], '2026-10-05', '2026-10-06')
  expect(result.undated).toBe(1)
  expect(result.beforeCount).toBe(2)
  expect(result.afterCount).toBe(0)
})
it('does not use timezone-naive observations to claim same-day provider disagreements', () => {
  const nodes = [node('a'), node('b'), node('port', 'port', { number: 443, protocol: 'TCP' })]
  const relationship = {
    ...edge('a', 'port', 'HAS_PORT'),
    observations: [
      {
        provider: 'one',
        observed_at: '2026-10-05T03:12:37.176374',
        evidence: { fingerprints: { cert: 'first' } }
      },
      {
        provider: 'two',
        observed_at: '2026-10-05T03:12:37Z',
        evidence: { fingerprints: { cert: 'second' } }
      }
    ]
  }
  expect(
    compareHosts(nodes, [relationship], ['a', 'b'])[0].differences.some((item) =>
      item.includes('provider evidence differs')
    )
  ).toBe(false)
  relationship.observations[0].observed_at = '2026-10-05T05:12:37+02:00'
  expect(
    compareHosts(nodes, [relationship], ['a', 'b'])[0].differences.some((item) =>
      item.includes('provider evidence differs')
    )
  ).toBe(true)
})

it('keeps collapsed groups compact and expands without moving stored nodes', () => {
  const nodes = Array.from({ length: 80 }, (_, i) => node(`host-${i}`, 'ip', { asn: `AS${i % 8}` }))
  const original = structuredClone(nodes)
  const overview = infrastructureOverview(nodes, [], 'asn', new Set())
  expect(new Set(overview.nodes.map((item) => `${item.x}:${item.y}`)).size).toBe(8)
  expect(
    overview.nodes.every((item) => item.nodeSize === 10 && item.nodeType === 'infrastructure group')
  ).toBe(true)
  for (const a of overview.nodes)
    for (const b of overview.nodes) {
      if (a.id !== b.id) expect(Math.hypot(a.x - b.x, a.y - b.y)).toBeGreaterThanOrEqual(70)
    }
  const expanded = infrastructureOverview(nodes, [], 'asn', new Set([overview.groups[0].id]))
  expect(new Set(expanded.nodes.map((item) => `${item.x}:${item.y}`)).size).toBe(
    expanded.nodes.length
  )
  expect(
    expanded.nodes.filter((item) => item.nodeProperties.infrastructure_group).map((item) => item.id)
  ).toEqual(overview.nodes.slice(1).map((item) => item.id))
  expect(nodes).toEqual(original)
  const reordered = infrastructureOverview([...nodes].reverse(), [], 'asn', new Set())
  expect(reordered.nodes.map(({ id, x, y }) => ({ id, x, y }))).toEqual(
    overview.nodes.map(({ id, x, y }) => ({ id, x, y }))
  )
})
