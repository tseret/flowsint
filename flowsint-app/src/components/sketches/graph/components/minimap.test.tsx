import { afterEach, expect, it, vi } from 'vitest'
import MinimapCanvas from './minimap'
import type { GraphNode, GraphViewerRef } from '@/types'

const mocks = vi.hoisted(() => ({
  context: {
    clearRect: vi.fn(),
    beginPath: vi.fn(),
    arc: vi.fn(),
    fill: vi.fn(),
    roundRect: vi.fn(),
    stroke: vi.fn()
  },
  cleanup: undefined as (() => void) | undefined
}))
vi.mock('react', () => ({
  useRef: () => ({ current: { getContext: () => mocks.context } }),
  useMemo: <T,>(factory: () => T) => factory(),
  useEffect: (effect: () => (() => void) | undefined) => {
    mocks.cleanup = effect()
  }
}))
afterEach(() => {
  mocks.cleanup?.()
  vi.unstubAllGlobals()
})
it('draws zero coordinates correctly and schedules no idle redraw loop', () => {
  const frames: FrameRequestCallback[] = []
  vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => {
    frames.push(callback)
    return frames.length
  })
  vi.stubGlobal('cancelAnimationFrame', vi.fn())
  const graphRef = {
    current: {
      graph2ScreenCoords: vi.fn(),
      zoom: () => 1,
      centerAt: () => ({ x: 0, y: 0 })
    } as unknown as GraphViewerRef
  }
  MinimapCanvas({
    nodes: [{ id: 'a', x: 0, y: 0 }] as GraphNode[],
    graphRef,
    canvasWidth: 800,
    canvasHeight: 600,
    viewportRevision: 0,
    positionRevision: 0
  })
  expect(frames).toHaveLength(1)
  frames[0](0)
  expect(mocks.context.arc).toHaveBeenCalledWith(80, 60, 0.75, 0, 2 * Math.PI)
  expect(frames).toHaveLength(1)
})
