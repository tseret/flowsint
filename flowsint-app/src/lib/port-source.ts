import type { GraphNode, GraphEdge } from '@/types/graph'

// Resolve only graph-owned IP endpoints; a host string alone is never a launch target.
export function resolvePortSource(
  port: GraphNode | null | undefined,
  nodes: GraphNode[],
  edges: GraphEdge[]
): { node: GraphNode | null; reason: string | null } {
  const host = port?.nodeProperties.host
  if (!port || typeof host !== 'string' || !host.trim())
    return {
      node: null,
      reason: 'This port has no recorded host. Refresh requires an unambiguous owning IP.'
    }
  const sources = new Set(
    edges
      .filter((edge) => {
        const target =
          typeof edge.target === 'object' ? (edge.target as { id: string }).id : edge.target
        return target === port.id && (edge.type || edge.label) === 'HAS_PORT'
      })
      .map((edge) =>
        typeof edge.source === 'object' ? (edge.source as { id: string }).id : edge.source
      )
  )
  if (sources.size !== 1)
    return {
      node: null,
      reason: sources.size
        ? 'Multiple IP owners are linked to this port. Resolve ownership before refreshing.'
        : 'No owning IP is linked by HAS_PORT. Refresh is unavailable.'
    }
  const source = nodes.find((node) => sources.has(node.id))
  const address = source?.nodeProperties.address
  if (
    !source ||
    source.nodeType.toLowerCase() !== 'ip' ||
    typeof address !== 'string' ||
    address.trim().toLowerCase() !== host.trim().toLowerCase()
  )
    return {
      node: null,
      reason:
        'The linked IP does not match this port’s recorded host. Resolve ownership before refreshing.'
    }
  return { node: source, reason: null }
}
