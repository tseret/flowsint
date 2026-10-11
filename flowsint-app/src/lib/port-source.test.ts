import { describe, it, expect } from 'vitest'
import type { GraphNode, GraphEdge } from '@/types/graph'
import { resolvePortSource } from './port-source'

const node = (
  id: string,
  nodeType: string,
  nodeProperties: GraphNode['nodeProperties']
): GraphNode => ({
  id,
  nodeType,
  nodeProperties,
  nodeLabel: id,
  nodeMetadata: {},
  nodeSize: 1,
  nodeColor: null,
  nodeIcon: null,
  nodeImage: null,
  nodeFlag: null,
  nodeShape: null,
  x: 0,
  y: 0
})
const ip = node('ip', 'ip', { address: '192.0.2.1' })
const port = node('port', 'port', { host: '192.0.2.1', number: 443 })
const edge: GraphEdge = { id: 'owns', source: ip.id, target: port.id, label: 'HAS_PORT' }

describe('port passive refresh ownership', () => {
  it('accepts one matching incoming IP owner and duplicate observations of that owner', () => {
    expect(
      resolvePortSource(port, [ip, port], [edge, { ...edge, id: 'second-observation' }])
    ).toEqual({ node: ip, reason: null })
  })
  it('requires a graph relationship rather than launching the raw host value', () => {
    expect(resolvePortSource(port, [ip, port], []).node).toBeNull()
    expect(resolvePortSource(port, [ip, port], [{ ...edge, label: 'RELATED_TO' }]).node).toBeNull()
    expect(
      resolvePortSource(port, [ip, port], [{ ...edge, source: port.id, target: ip.id }]).node
    ).toBeNull()
  })
  it('rejects missing hosts and missing/non-IP/mismatching source nodes', () => {
    expect(resolvePortSource(node('port', 'port', { number: 443 }), [ip], [edge]).node).toBeNull()
    expect(resolvePortSource(port, [port], [edge]).node).toBeNull()
    expect(
      resolvePortSource(port, [node('ip', 'domain', { address: '192.0.2.1' })], [edge]).node
    ).toBeNull()
    expect(
      resolvePortSource(port, [node('ip', 'ip', { address: '192.0.2.2' })], [edge]).node
    ).toBeNull()
  })
  it('rejects ambiguous ownership even when one linked IP matches the host', () => {
    expect(
      resolvePortSource(
        port,
        [ip, node('other', 'ip', { address: '192.0.2.2' })],
        [edge, { ...edge, id: 'other-owner', source: 'other' }]
      ).node
    ).toBeNull()
  })
  it('handles force-graph runtime node references without following additional neighbors', () => {
    const runtimeEdge = {
      ...edge,
      source: { id: ip.id },
      target: { id: port.id }
    } as unknown as GraphEdge
    expect(resolvePortSource(port, [ip, port], [runtimeEdge]).node?.id).toBe(ip.id)
  })
})
