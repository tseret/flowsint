import { expect, it } from 'vitest'
import { fitGraphViewport } from './fit-graph'
import type { GraphNode } from '@/types'

it('fits displayed node extents, including large cards and screen-sized labels, below the toolbar', () => {
  const nodes = [
    { id: 'left', x: 0, y: 0 },
    { id: 'right', x: 1000, y: 200 }
  ] as GraphNode[]
  const measure = (node: GraphNode, zoom: number) => ({
    left: node.x - 160 - 60 / zoom,
    right: node.x + 160 + 60 / zoom,
    top: node.y - 80,
    bottom: node.y + 120
  })
  const view = fitGraphViewport(nodes, 900, 600, measure)!
  expect(view.zoom).toBeLessThan(900 / 1000)
  for (const node of nodes) {
    const box = measure(node, view.zoom)
    expect((box.left - view.x) * view.zoom + 450).toBeGreaterThan(0)
    expect((box.right - view.x) * view.zoom + 450).toBeLessThan(900)
    expect((box.top - view.y) * view.zoom + 300).toBeGreaterThan(90)
    expect((box.bottom - view.y) * view.zoom + 300).toBeLessThan(600)
  }
})
it('fits a single large card and ignores invalid positions', () => {
  const node = { id: 'group', x: 10, y: 20 } as GraphNode
  const view = fitGraphViewport([node, { ...node, x: NaN }], 500, 400, (item) => ({
    left: item.x - 300,
    right: item.x + 300,
    top: item.y - 100,
    bottom: item.y + 100
  }))!
  expect(view.zoom * 600).toBeLessThan(500)
  expect(view.x).toBe(10)
  expect(
    fitGraphViewport([], 500, 400, () => ({ left: 0, right: 0, top: 0, bottom: 0 }))
  ).toBeNull()
})
