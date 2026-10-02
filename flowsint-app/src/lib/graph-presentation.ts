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
          JSON.stringify([old.label, old.observations]) !==
            JSON.stringify([edge.label, edge.observations])
        )
      })
      .map((edge) => edge.id)
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
