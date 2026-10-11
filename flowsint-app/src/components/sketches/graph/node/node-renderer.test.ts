import { expect, it, vi } from 'vitest'
import { getNodeDisplayBounds, renderNode } from './node-renderer'
import { createRenderContext } from '../utils/render-context'
import { fitGraphViewport } from '../utils/fit-graph'
import { infrastructureOverview } from '@/lib/infrastructure-analysis'
import type { GraphNode } from '@/types'
import type { GraphForceSettings } from '@/stores/graph-settings-store'

vi.mock('../utils/image-cache', () => ({
  getCachedImage: vi.fn(),
  getCachedFlagImage: vi.fn(),
  getCachedIconByName: vi.fn(),
  getCachedExternalImage: vi.fn()
}))
const node = (id: string): GraphNode => ({
  id,
  nodeLabel: 'AS64500 · 220 hosts · 220 entities',
  nodeType: 'infrastructure group',
  nodeSize: 10,
  nodeProperties: { infrastructure_group: true },
  nodeMetadata: {},
  nodeColor: '#38bdf8',
  nodeIcon: null,
  nodeImage: null,
  nodeFlag: null,
  nodeShape: null,
  x: 20,
  y: 20
})
function canvas() {
  const fills: unknown[] = []
  const ctx = {
    font: '',
    fillStyle: '',
    canvas: { width: 1200, height: 700 },
    getTransform: () => ({ a: 1, d: 1, e: 0, f: 0 }),
    beginPath: vi.fn(),
    arc: vi.fn(),
    roundRect: vi.fn(),
    fill: vi.fn(),
    stroke: vi.fn(),
    save: vi.fn(),
    restore: vi.fn(),
    clip: vi.fn(),
    fillRect: vi.fn(),
    fillText: vi.fn(),
    measureText: (text: string) => ({
      width: text.length * Number(ctx.font.match(/[\d.]+/)?.[0] ?? 5) * 0.55
    })
  }
  ctx.fill.mockImplementation(() => {
    fills.push(ctx.fillStyle)
  })
  return { ctx: ctx as unknown as CanvasRenderingContext2D, fills, text: ctx.fillText }
}
it('renders group labels below the normal detail cutoff with outlined contrast and fixed card scale', () => {
  const { ctx, fills, text } = canvas()
  const settings = { dotStyle: { value: false }, nodeSize: { value: 1 } } as GraphForceSettings
  const group = node('group')
  const rc = createRenderContext(1, new Set(), new Set(), [], 'dark')
  expect(rc.shouldRenderDetails).toBe(false)
  renderNode({
    node: group,
    ctx,
    globalScale: 1,
    forceSettings: settings,
    showLabels: false,
    showIcons: false,
    isCurrent: () => false,
    isSelected: () => false,
    theme: 'dark',
    highlightNodes: new Set(),
    highlightLinks: new Set(),
    hoverNode: null,
    rc
  })
  expect(text).toHaveBeenCalledWith(group.nodeLabel, expect.any(Number), expect.any(Number))
  expect(fills).toContain(rc.themeBgFill)
  const bounds = getNodeDisplayBounds(group, ctx, settings, 1, false)
  expect(
    getNodeDisplayBounds(
      group,
      ctx,
      { ...settings, nodeSize: { value: 100 } } as GraphForceSettings,
      1,
      false
    )
  ).toEqual(bounds)
  text.mockClear()
  renderNode({
    node: { ...group, nodeProperties: {} },
    ctx,
    globalScale: 1,
    forceSettings: settings,
    showLabels: false,
    showIcons: false,
    isCurrent: () => false,
    isSelected: () => false,
    theme: 'dark',
    highlightNodes: new Set(),
    highlightLinks: new Set(),
    hoverNode: null,
    rc
  })
  expect(text).not.toHaveBeenCalled()
})
it('fits eight collapsed groups compactly even when one contains 220 members', () => {
  const nodes = Array.from({ length: 227 }, (_, i) => ({
    ...node(String(i)),
    nodeType: 'ip',
    nodeProperties: { asn: i < 220 ? 'AS0' : `AS${i - 219}` }
  }))
  const overview = infrastructureOverview(nodes, [], 'asn', new Set())
  expect(overview.nodes).toHaveLength(8)
  expect(
    Math.max(...overview.nodes.map((item) => item.x)) -
      Math.min(...overview.nodes.map((item) => item.x))
  ).toBe(300)
  expect(
    Math.max(...overview.nodes.map((item) => item.y)) -
      Math.min(...overview.nodes.map((item) => item.y))
  ).toBe(140)
  const { ctx } = canvas()
  const settings = { dotStyle: { value: false } } as GraphForceSettings
  const view = fitGraphViewport(overview.nodes, 1200, 700, (group, zoom) =>
    getNodeDisplayBounds(group, ctx, settings, zoom, true)
  )!
  expect(view.zoom).toBeGreaterThan(2)
  expect(4.5 * 1.2 * view.zoom).toBeGreaterThan(12)
})

it('keeps synthetic dot labels visible below the detail cutoff', () => {
  const { ctx, text } = canvas()
  const group = node('group')
  const settings = { dotStyle: { value: true }, nodeSize: { value: 1 } } as GraphForceSettings
  const rc = createRenderContext(1, new Set(), new Set(), [], 'dark')
  renderNode({
    node: group,
    ctx,
    globalScale: 1,
    forceSettings: settings,
    showLabels: false,
    showIcons: false,
    isCurrent: () => false,
    isSelected: () => false,
    theme: 'dark',
    highlightNodes: new Set(),
    highlightLinks: new Set(),
    hoverNode: null,
    rc
  })
  expect(text).toHaveBeenCalledWith(group.nodeLabel, expect.any(Number), expect.any(Number))
  text.mockClear()
  renderNode({
    node: { ...group, nodeProperties: {} },
    ctx,
    globalScale: 1,
    forceSettings: settings,
    showLabels: true,
    showIcons: false,
    isCurrent: () => false,
    isSelected: () => false,
    theme: 'dark',
    highlightNodes: new Set(),
    highlightLinks: new Set(),
    hoverNode: null,
    rc
  })
  expect(text).not.toHaveBeenCalled()
})
