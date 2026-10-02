import { expect, it } from 'vitest'
import type { GraphNode } from '@/types/graph'
import { useGraphStore } from './graph-store'

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
