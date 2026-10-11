import { beforeEach, describe, it, expect } from 'vitest'
import { useGraphStore } from './graph-store'
import { GraphEdge, GraphNode } from '@/types'

const makeNode = (id: string): GraphNode => ({
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
  nodeMetadata: {},
  x: 0,
  y: 0
})

const edge = (source: string, target: string): GraphEdge => ({
  id: `${source}-${target}`,
  source,
  target,
  label: 'TO'
})

const visible = () => useGraphStore.getState().filteredNodes.map((n) => n.id)

describe('pivot depth filter', () => {
  beforeEach(() => {
    const store = useGraphStore.getState()
    store.setFilters({ types: [], rules: [], hiddenWaves: [] })
    // seed -> hop1 -> hop2, plus an unlinked seed x
    store.updateGraphData(['seed', 'hop1', 'hop2', 'x'].map(makeNode), [
      edge('seed', 'hop1'),
      edge('hop1', 'hop2')
    ])
  })

  it('hides one depth without renumbering the deeper ones', () => {
    useGraphStore.getState().toggleWaveFilter(1)
    expect(visible()).toEqual(['seed', 'hop2', 'x'])
    expect(useGraphStore.getState().filteredEdges).toEqual([])
    useGraphStore.getState().toggleWaveFilter(1)
    expect(visible()).toEqual(['seed', 'hop1', 'hop2', 'x'])
  })

  it('re-evaluates depth when a new edge moves a node into a hidden depth', () => {
    useGraphStore.getState().toggleWaveFilter(1)
    useGraphStore.getState().addEdge(edge('seed', 'x'))
    expect(visible()).toEqual(['seed', 'hop2'])
  })

  it('clears the depth filter when switching sketches', () => {
    useGraphStore.getState().toggleWaveFilter(0)
    useGraphStore.getState().reset()
    expect(useGraphStore.getState().filters.hiddenWaves).toEqual([])
    expect(visible()).toEqual(['seed', 'hop1', 'hop2', 'x'])
  })
})
it('keeps the persisted identity and version when replacing a newly added node', () => {
  const temporary: GraphNode = {
    id: 'temporary',
    nodeType: 'phrase',
    nodeLabel: 'Example',
    nodeProperties: { text: 'Example' },
    nodeMetadata: {},
    version: 0,
    nodeSize: 1,
    nodeColor: null,
    nodeIcon: null,
    nodeImage: null,
    nodeFlag: null,
    nodeShape: null,
    x: 123,
    y: 456
  }
  const graph = useGraphStore.getState()
  graph.updateGraphData(
    [temporary],
    [{ id: 'edge', source: temporary.id, target: 'neighbor', label: 'RELATED_TO' }]
  )
  graph.setCurrentNodeId(temporary.id)
  graph.replaceNode(temporary.id, { ...temporary, id: 'persisted', version: 7 })
  const saved = useGraphStore.getState()
  expect(saved.getCurrentNode()).toMatchObject({
    id: 'persisted',
    version: 7,
    x: 123,
    y: 456
  })
  expect(saved.nodesMapping.has('temporary')).toBe(false)
  expect(saved.edges[0].source).toBe('persisted')
})

it('includes every selected relationship in chains, cycles and shared endpoints', () => {
  const nodes = ['a', 'b', 'c', 'isolated', 'outside'].map(makeNode)
  const store = useGraphStore.getState()
  store.updateGraphData(nodes, [
    edge('a', 'b'),
    edge('b', 'c'),
    edge('c', 'a'),
    edge('c', 'outside')
  ])
  store.setSelectedNodes(nodes.slice(0, 4))
  const context = useGraphStore.getState().selectedNodesWithEdgesAsList
  expect(context.filter((item) => item.type === 'relation')).toHaveLength(3)
  expect(context.filter((item) => item.type === 'node')).toMatchObject([{ nodeLabel: 'isolated' }])
})
