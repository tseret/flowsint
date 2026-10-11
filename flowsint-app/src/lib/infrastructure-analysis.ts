import type { EvidenceObservation, GraphEdge, GraphNode } from '@/types/graph'

export function parseObservationDate(value?: string): { day: string; timestamp: number } | null {
  if (
    !value ||
    !/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2}))?$/i.test(value)
  )
    return null
  const calendarDay = value.slice(0, 10)
  const calendarTimestamp = Date.parse(calendarDay)
  if (
    !Number.isFinite(calendarTimestamp) ||
    new Date(calendarTimestamp).toISOString().slice(0, 10) !== calendarDay
  )
    return null
  const timestamp = Date.parse(value)
  return Number.isFinite(timestamp)
    ? { day: new Date(timestamp).toISOString().slice(0, 10), timestamp }
    : null
}

export type InfrastructureGrouping = 'asn' | 'prefix' | 'domain'
export const isHost = (node: GraphNode) =>
  ['ip', 'domain', 'hostname'].includes(node.nodeType.toLowerCase())
const object = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
const text = (value: unknown) =>
  typeof value === 'string' || typeof value === 'number' ? String(value) : ''

export function infrastructureOverview(
  nodes: GraphNode[],
  edges: GraphEdge[],
  grouping: InfrastructureGrouping,
  expanded: Set<string>
) {
  const byId = new Map(nodes.map((node) => [node.id, node]))
  const adjacent = new Map<string, GraphNode[]>()
  for (const edge of edges) {
    const source = byId.get(edge.source),
      target = byId.get(edge.target)
    if (!source || !target) continue
    for (const [node, neighbor] of [
      [source, target],
      [target, source]
    ]) {
      const list = adjacent.get(node.id) ?? []
      list.push(neighbor)
      adjacent.set(node.id, list)
    }
  }
  const assignment = new Map<string, string>()
  const labels = new Map<string, string>()
  for (const node of nodes.filter(isHost)) {
    const types = grouping === 'prefix' ? ['cidr', 'network'] : [grouping]
    const neighbors = (adjacent.get(node.id) ?? []).filter((item) =>
      types.includes(item.nodeType.toLowerCase())
    )
    // Multiple recorded memberships remain explicit rather than implying a single owner.
    const recorded = neighbors
      .map((item) => item.nodeLabel)
      .sort()
      .join(' / ')
    const own = grouping === 'domain' && node.nodeType === 'domain' ? node.nodeLabel : ''
    const property = text(node.nodeProperties[grouping === 'prefix' ? 'prefix' : grouping])
    const label = recorded || own || property || `No recorded ${grouping}`
    const id = `infrastructure:${grouping}:${label}`
    assignment.set(node.id, id)
    labels.set(id, label)
  }
  // Only collapse detail that belongs to exactly one group; shared detail stays visible.
  for (const node of nodes) {
    if (assignment.has(node.id)) continue
    const groups = new Set(
      (adjacent.get(node.id) ?? []).filter(isHost).map((host) => assignment.get(host.id)!)
    )
    if (groups.size === 1) assignment.set(node.id, [...groups][0])
  }
  const groups = new Map<string, GraphNode[]>()
  for (const node of nodes) {
    const id = assignment.get(node.id)
    if (!id) continue
    const members = groups.get(id) ?? []
    members.push(node)
    groups.set(id, members)
  }
  const orderedGroups = [...groups].sort(([a], [b]) => a.localeCompare(b))
  const ungrouped = nodes
    .filter((node) => !assignment.has(node.id))
    .sort((a, b) => a.id.localeCompare(b.id))
  const slots = [
    ...orderedGroups.map(([id, members]) => ({ id, members })),
    ...ungrouped.map((node) => ({ id: node.id, members: [node] }))
  ]
  const columns = Math.max(1, Math.ceil(Math.sqrt(slots.length)))
  const widths = Array.from({ length: columns }, () => 150)
  const heights = Array.from({ length: Math.ceil(slots.length / columns) }, () => 70)
  slots.forEach((slot, index) => {
    if (!expanded.has(slot.id)) return
    const memberColumns = Math.ceil(Math.sqrt(slot.members.length))
    widths[index % columns] = Math.max(widths[index % columns], memberColumns * 90 + 100)
    heights[Math.floor(index / columns)] = Math.max(
      heights[Math.floor(index / columns)],
      Math.ceil(slot.members.length / memberColumns) * 60 + 100
    )
  })
  const offsets = (sizes: number[]) => {
    let offset = 0
    return sizes.map((size) => {
      const center = offset + size / 2
      offset += size
      return center
    })
  }
  const xs = offsets(widths),
    ys = offsets(heights)
  const anchors = new Map(
    slots.map((slot, index) => [
      slot.id,
      { x: xs[index % columns], y: ys[Math.floor(index / columns)] }
    ])
  )
  const result: GraphNode[] = ungrouped.map((node) => ({
    ...node,
    ...anchors.get(node.id)!,
    fx: anchors.get(node.id)!.x,
    fy: anchors.get(node.id)!.y
  }))
  const summaries = orderedGroups.map(([id, members]) => {
    const hosts = members.filter(isHost).length
    const flagged = members.filter((node) => node.nodeFlag).length
    const { x, y } = anchors.get(id)!
    if (expanded.has(id)) {
      const ordered = [...members].sort((a, b) => a.id.localeCompare(b.id))
      const memberColumns = Math.ceil(Math.sqrt(ordered.length))
      const rows = Math.ceil(ordered.length / memberColumns)
      ordered.forEach((node, index) => {
        const memberX = x + ((index % memberColumns) - (memberColumns - 1) / 2) * 90
        const memberY = y + (Math.floor(index / memberColumns) - (rows - 1) / 2) * 60
        result.push({ ...node, x: memberX, y: memberY, fx: memberX, fy: memberY })
      })
    } else {
      result.push({
        id,
        nodeType: 'infrastructure group',
        nodeLabel: `${labels.get(id)} · ${hosts} hosts · ${members.length} entities`,
        nodeProperties: { infrastructure_group: true, members: members.map((node) => node.id) },
        nodeMetadata: {},
        nodeSize: 10,
        nodeColor: '#38bdf8',
        nodeIcon: 'Network',
        nodeImage: null,
        nodeFlag: null,
        nodeShape: 'hexagon',
        x,
        y,
        fx: x,
        fy: y
      })
    }
    return { id, label: labels.get(id)!, members, hosts, flagged }
  })
  const endpoint = (id: string) => {
    const group = assignment.get(id)
    return group && !expanded.has(group) ? group : id
  }
  const links = new Map<string, GraphEdge>()
  for (const edge of edges) {
    const source = endpoint(edge.source),
      target = endpoint(edge.target)
    if (source === target) continue
    if (source === edge.source && target === edge.target) {
      links.set(edge.id, edge)
      continue
    }
    const id = `aggregate:${JSON.stringify([source, target])}`
    const previous = links.get(id)
    const weight = (previous?.weight ?? 0) + 1
    links.set(id, { id, source, target, label: `${weight} recorded relationships`, weight })
  }
  return { nodes: result, edges: [...links.values()], groups: summaries }
}

export function boundedNeighborhood(
  nodes: GraphNode[],
  edges: GraphEdge[],
  seeds: string[],
  limit = 500
) {
  const byId = new Map(nodes.map((node) => [node.id, node]))
  const ids = new Set(seeds.filter((id) => byId.has(id)).slice(0, limit))
  const candidates = new Set<string>()
  for (const edge of edges) {
    if (ids.has(edge.source)) candidates.add(edge.target)
    if (ids.has(edge.target)) candidates.add(edge.source)
  }
  for (const id of candidates) if (byId.has(id) && ids.size < limit) ids.add(id)
  return {
    nodes: nodes.filter((node) => ids.has(node.id)),
    edges: edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)),
    truncated: [...candidates].some((id) => byId.has(id) && !ids.has(id))
  }
}

export function compareHosts(nodes: GraphNode[], edges: GraphEdge[], hostIds: string[]) {
  const byId = new Map(nodes.map((node) => [node.id, node]))
  const hosts = nodes.filter(isHost)
  type Service = { node: GraphNode; observations: EvidenceObservation[] }
  const services = new Map<string, Map<string, Service[]>>()
  for (const edge of edges) {
    const port = byId.get(edge.target)
    if ((edge.type || edge.label) !== 'HAS_PORT' || port?.nodeType.toLowerCase() !== 'port')
      continue
    const props = port.nodeProperties
    const key = `${text(props.number)}/${text(props.protocol).toLowerCase() || 'unknown transport'}`
    const map = services.get(edge.source) ?? new Map<string, Service[]>()
    const entries = map.get(key) ?? []
    entries.push({ node: port, observations: edge.observations ?? [] })
    map.set(key, entries)
    services.set(edge.source, map)
  }
  const fingerprintsOf = (entries: Service[]) => {
    const fields = new Map<string, Set<string>>()
    for (const { node } of entries)
      for (const [field, value] of Object.entries(object(node.nodeProperties.fingerprints))) {
        if (!text(value)) continue
        const values = fields.get(field) ?? new Set<string>()
        values.add(text(value))
        fields.set(field, values)
      }
    return fields
  }
  const frequency = new Map<string, Set<string>>()
  for (const [host, ports] of services)
    for (const entries of ports.values()) {
      for (const [field, values] of fingerprintsOf(entries))
        for (const value of values) {
          const key = `${field}:${value}`
          const owners = frequency.get(key) ?? new Set<string>()
          owners.add(host)
          frequency.set(key, owners)
        }
    }
  const providerDifferences = (host: GraphNode, ports: Map<string, Service[]>) => {
    const differences: string[] = []
    for (const [service, entries] of ports) {
      const facts = new Map<string, Map<string, Set<string>>>()
      for (const entry of entries)
        for (const observation of entry.observations) {
          const observed = parseObservationDate(observation.observed_at)
          if (!observation.provider || !observed) continue
          const evidence = object(observation.evidence)
          const values = {
            ...object(evidence.fingerprints),
            ...(evidence.service ? { service: evidence.service } : {}),
            ...(evidence.state ? { state: evidence.state } : {})
          }
          for (const [field, value] of Object.entries(values)) {
            if (!text(value)) continue
            const key = `${observed.day} ${field}`
            const providers = facts.get(key) ?? new Map<string, Set<string>>()
            const recorded = providers.get(observation.provider) ?? new Set<string>()
            recorded.add(text(value))
            providers.set(observation.provider, recorded)
            facts.set(key, providers)
          }
        }
      for (const [key, providers] of facts) {
        const values = new Set([...providers.values()].flatMap((items) => [...items]))
        if (providers.size > 1 && values.size > 1)
          differences.push(
            `${host.nodeLabel} ${service} ${key}: provider evidence differs (${[...providers].map(([provider, items]) => `${provider}: ${[...items].join(', ')}`).join('; ')})`
          )
      }
    }
    return differences
  }
  const selected = hostIds
    .map((id) => byId.get(id))
    .filter((node): node is GraphNode => !!node && isHost(node))
    .slice(0, 12)
  const comparisons = []
  for (let i = 0; i < selected.length; i++)
    for (let j = i + 1; j < selected.length; j++) {
      const left = selected[i],
        right = selected[j]
      const a = services.get(left.id) ?? new Map<string, Service[]>(),
        b = services.get(right.id) ?? new Map<string, Service[]>()
      const sharedServices: string[] = [],
        fingerprints: string[] = []
      const differences = [...providerDifferences(left, a), ...providerDifferences(right, b)]
      for (const [key, entries] of a) {
        const peers = b.get(key)
        if (!peers) {
          differences.push(`${key} recorded only on ${left.nodeLabel}`)
          continue
        }
        sharedServices.push(key)
        const names = (items: Service[]) =>
          [...new Set(items.map(({ node }) => text(node.nodeProperties.service)).filter(Boolean))]
            .sort()
            .join(', ')
        const leftName = names(entries),
          rightName = names(peers)
        if (leftName && rightName && leftName !== rightName)
          differences.push(`${key}: service ${leftName} vs ${rightName}`)
        const af = fingerprintsOf(entries),
          bf = fingerprintsOf(peers)
        for (const [field, values] of af) {
          const peerValues = bf.get(field)
          if (!peerValues) continue
          for (const value of values)
            if (peerValues.has(value))
              fingerprints.push(
                `${key} ${field}=${value} (${frequency.get(`${field}:${value}`)?.size ?? 0}/${hosts.length} loaded hosts)`
              )
          if (
            [...values].some((value) => !peerValues.has(value)) ||
            [...peerValues].some((value) => !values.has(value))
          )
            differences.push(
              `${key} ${field}: ${[...values].join(', ')} vs ${[...peerValues].join(', ')}`
            )
        }
      }
      for (const key of b.keys())
        if (!a.has(key)) differences.push(`${key} recorded only on ${right.nodeLabel}`)
      const evidence = [left, right].flatMap((host) =>
        [...(services.get(host.id) ?? new Map<string, Service[]>()).values()]
          .flat()
          .map(({ node, observations }) => ({
            host: host.nodeLabel,
            nodeId: node.id,
            service: node.nodeLabel,
            observations: observations.length
              ? observations
              : [
                  {
                    provider: text(node.nodeProperties.provider) || undefined,
                    observed_at: text(node.nodeProperties.observed_at) || undefined,
                    retrieved_at: text(node.nodeProperties.retrieved_at) || undefined
                  }
                ]
          }))
      )
      comparisons.push({ left, right, sharedServices, fingerprints, differences, evidence })
    }
  return comparisons.sort(
    (a, b) =>
      b.fingerprints.length - a.fingerprints.length ||
      b.sharedServices.length - a.sharedServices.length
  )
}

const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (value && typeof value === 'object')
    return `{${Object.entries(object(value))
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
      .join(',')}}`
  return JSON.stringify(value) ?? 'null'
}

export function compareObservationDates(edges: GraphEdge[], before: string, after: string) {
  let undated = 0
  const snapshots = [before, after].map((date, index) => {
    const map = new Map<string, { edge: GraphEdge; observation: EvidenceObservation }>()
    for (const edge of edges)
      for (const observation of edge.observations ?? []) {
        const observed = parseObservationDate(observation.observed_at)
        if (!observed) {
          if (index === 0) undated++
          continue
        }
        if (observed.day !== date) continue
        const key = JSON.stringify([
          edge.id,
          observation.provider ?? '',
          observation.enricher ?? ''
        ])
        const previous = map.get(key)
        if (
          !previous ||
          observed.timestamp > parseObservationDate(previous.observation.observed_at)!.timestamp
        )
          map.set(key, { edge, observation })
      }
    return map
  })
  const [a, b] = snapshots
  const byRelationship = new Map<
    string,
    {
      sample: { edge: GraphEdge; observation: EvidenceObservation }
      providers: Set<string>
      payloads: Set<string>
    }
  >()
  for (const value of b.values()) {
    if (!value.observation.provider || value.observation.evidence == null) continue
    const group = byRelationship.get(value.edge.id) ?? {
      sample: value,
      providers: new Set<string>(),
      payloads: new Set<string>()
    }
    group.providers.add(value.observation.provider)
    group.payloads.add(canonical(value.observation.evidence))
    byRelationship.set(value.edge.id, group)
  }
  return {
    beforeCount: a.size,
    afterCount: b.size,
    undated,
    added: [...b].filter(([key]) => !a.has(key)).map(([, value]) => value),
    notReobserved: [...a].filter(([key]) => !b.has(key)).map(([, value]) => value),
    changed: [...b]
      .filter(
        ([key, value]) =>
          a.has(key) &&
          canonical(a.get(key)!.observation.evidence) !== canonical(value.observation.evidence)
      )
      .map(([key, value]) => ({ ...value, previous: a.get(key)!.observation })),
    disagreements: [...byRelationship.values()]
      .filter((group) => group.providers.size > 1 && group.payloads.size > 1)
      .map((group) => group.sample)
  }
}
