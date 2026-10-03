import type { GraphNode, GraphEdge } from '@/types/graph'
import type { Filters } from '@/types/filter'

export function graphChanges(
  nodes: GraphNode[],
  edges: GraphEdge[],
  previousNodes: GraphNode[],
  previousEdges: GraphEdge[]
) {
  const oldNodes = new Map(previousNodes.map((node) => [node.id, node]))
  const oldEdges = new Map(previousEdges.map((edge) => [edge.id, edge]))
  return {
    addedNodes: nodes.filter((node) => !oldNodes.has(node.id)).map((node) => node.id),
    updatedNodes: nodes
      .filter((node) => {
        const old = oldNodes.get(node.id)
        return (
          old &&
          JSON.stringify([old.nodeLabel, old.nodeProperties, old.nodeMetadata]) !==
            JSON.stringify([node.nodeLabel, node.nodeProperties, node.nodeMetadata])
        )
      })
      .map((node) => node.id),
    addedEdges: edges.filter((edge) => !oldEdges.has(edge.id)).map((edge) => edge.id),
    updatedEdges: edges
      .filter((edge) => {
        const old = oldEdges.get(edge.id)
        return (
          old &&
          JSON.stringify([old.label, old.caption, old.observations]) !==
            JSON.stringify([edge.label, edge.caption, edge.observations])
        )
      })
      .map((edge) => edge.id)
  }
}

const record = (value: unknown): Record<string, unknown> | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null

export function fingerprintPivotEvidence(observation: unknown) {
  const evidence = record(record(observation)?.evidence)
  const source = record(evidence?.source)
  const candidate = record(evidence?.candidate)
  return evidence && source && candidate ? { evidence, source, candidate } : null
}

export const edgeDisplayLabel = (edge: Pick<GraphEdge, 'label' | 'caption'>) =>
  edge.caption || edge.label

export function compactPivotGraph(
  nodes: GraphNode[],
  edges: GraphEdge[],
  {
    expanded = false,
    selectedNodeIds = [],
    selectedEdgeIds = []
  }: { expanded?: boolean; selectedNodeIds?: string[]; selectedEdgeIds?: string[] } = {}
) {
  if (expanded) return { nodes, edges }
  const byId = new Map(nodes.map((node) => [node.id, node]))
  const protectedIds = new Set(selectedNodeIds)
  const selectedEdges = new Set(selectedEdgeIds)
  const owners = new Map<string, string[]>()
  const incident = new Map<string, GraphEdge[]>()
  for (const edge of edges) {
    for (const id of [edge.source, edge.target]) {
      const list = incident.get(id) ?? []
      list.push(edge)
      incident.set(id, list)
      if (selectedEdges.has(edge.id)) protectedIds.add(id)
    }
    if ((edge.type || edge.label) === 'HAS_PORT') {
      const list = owners.get(edge.target) ?? []
      list.push(edge.source)
      owners.set(edge.target, list)
    }
  }
  const hidden = new Set<string>()
  const ownedPorts = new Map<string, GraphNode[]>()
  for (const node of nodes) {
    const owner = owners.get(node.id)
    if (node.nodeType.toLowerCase() !== 'port' || owner?.length !== 1) continue
    const list = ownedPorts.get(owner[0]) ?? []
    list.push(node)
    ownedPorts.set(owner[0], list)
  }
  const normalize = (value: unknown) => (typeof value === 'string' ? value.toLowerCase() : '')
  function matchesService(
    port: GraphNode | undefined,
    owner: GraphNode,
    endpoint: Record<string, unknown>
  ) {
    return (
      typeof endpoint.transport === 'string' &&
      !!endpoint.transport &&
      typeof endpoint.service === 'string' &&
      !!endpoint.service &&
      Number.isInteger(Number(endpoint.port)) &&
      Number(endpoint.port) > 0 &&
      Number(endpoint.port) <= 65535 &&
      port?.nodeType.toLowerCase() === 'port' &&
      owners.get(port.id)?.length === 1 &&
      owners.get(port.id)?.[0] === owner.id &&
      port.nodeProperties.host === owner.nodeProperties.address &&
      endpoint.host === owner.nodeProperties.address &&
      Number(port.nodeProperties.number) === Number(endpoint.port) &&
      normalize(port.nodeProperties.protocol) === normalize(endpoint.transport) &&
      normalize(port.nodeProperties.service) === normalize(endpoint.service)
    )
  }
  function hide(port: GraphNode) {
    if (
      !protectedIds.has(port.id) &&
      incident.get(port.id)?.every((edge) => (edge.type || edge.label) === 'HAS_PORT')
    )
      hidden.add(port.id)
  }
  for (const edge of edges) {
    if ((edge.type || edge.label) !== 'SHARES_FINGERPRINT') continue
    const sourceIP = byId.get(edge.source),
      candidateIP = byId.get(edge.target)
    if (sourceIP?.nodeType.toLowerCase() !== 'ip' || candidateIP?.nodeType.toLowerCase() !== 'ip')
      continue
    for (const observation of edge.observations ?? []) {
      const pivot = fingerprintPivotEvidence(observation)
      if (
        !pivot ||
        typeof pivot.source.service_id !== 'string' ||
        typeof pivot.candidate.ip !== 'string'
      )
        continue
      const sourcePort = byId.get(pivot.source.service_id)
      if (
        !matchesService(sourcePort, sourceIP, pivot.source) ||
        pivot.candidate.ip !== candidateIP.nodeProperties.address
      )
        continue
      const endpoint = {
        host: pivot.candidate.ip,
        port: pivot.candidate.port,
        transport: pivot.candidate.transport,
        service: pivot.candidate.protocol
      }
      const candidatePorts = (ownedPorts.get(candidateIP.id) ?? []).filter((node) =>
        matchesService(node, candidateIP, endpoint)
      )
      if (candidatePorts.length !== 1 || !sourcePort) continue
      hide(sourcePort)
      hide(candidatePorts[0])
    }
  }
  return {
    nodes: nodes.filter((node) => !hidden.has(node.id)),
    edges: edges.filter((edge) => !hidden.has(edge.source) && !hidden.has(edge.target))
  }
}

export function preserveGraphPositions(
  incoming: GraphNode[],
  previous: GraphNode[],
  edges: GraphEdge[]
): GraphNode[] {
  const existing = new Map(previous.map((node) => [node.id, node]))
  const anchors = new Map<string, GraphNode>()
  for (const edge of edges) {
    const source = existing.get(edge.source)
    const target = existing.get(edge.target)
    if (source && !existing.has(edge.target)) anchors.set(edge.target, source)
    if (target && !existing.has(edge.source)) anchors.set(edge.source, target)
  }
  return incoming.map((node, index) => {
    const old = existing.get(node.id)
    if (old && Number.isFinite(old.x) && Number.isFinite(old.y)) {
      return { ...node, x: old.x, y: old.y, fx: old.x, fy: old.y }
    }
    const anchor = anchors.get(node.id)
    if (!anchor || !Number.isFinite(anchor.x) || !Number.isFinite(anchor.y)) return node
    const angle = index * 2.399963229728653
    const radius = 30 + 10 * Math.sqrt(index + 1)
    const x = anchor.x + Math.cos(angle) * radius
    const y = anchor.y + Math.sin(angle) * radius
    return { ...node, x, y, fx: x, fy: y }
  })
}

export function edgeMatchesEvidence(edge: GraphEdge, filters: Filters): boolean {
  if (filters.relationship && (edge.type || edge.label) !== filters.relationship) return false
  const needsEvidence = filters.provider || filters.observedAfter || filters.observedBefore
  if (!needsEvidence) return true
  // Match all conditions against one observation, rather than combining different providers/dates.
  return (edge.observations || []).some((observation) => {
    if (filters.provider && observation.provider !== filters.provider) return false
    const date = observation.observed_at?.slice(0, 10)
    if (filters.observedAfter && (!date || date < filters.observedAfter)) return false
    if (filters.observedBefore && (!date || date > filters.observedBefore)) return false
    return true
  })
}
