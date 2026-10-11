import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { useLayout } from './use-layout'
import type { GraphNode } from '@/types'
import type { GraphForceSettings } from '@/stores/graph-settings-store'

const lifecycle = vi.hoisted(() => ({ cleanup: undefined as (() => void) | undefined }))
vi.mock('react', () => ({
  useRef: <T>(value: T) => ({ current: value }),
  useCallback: <T>(callback: T) => callback,
  useEffect: (effect: () => () => void) => {
    lifecycle.cleanup = effect()
  }
}))
class FakeWorker {
  static instances: FakeWorker[] = []
  onmessage: ((event: { data: unknown }) => void) | null = null
  onerror: ((event: Error) => void) | null = null
  terminate = vi.fn()
  postMessage = vi.fn()
  constructor() {
    FakeWorker.instances.push(this)
  }
  complete(nodes: unknown[]) {
    this.onmessage?.({ data: { type: 'complete', result: { nodes } } })
  }
}
beforeEach(() => {
  FakeWorker.instances = []
  vi.stubGlobal('Worker', FakeWorker)
})
afterEach(() => {
  lifecycle.cleanup?.()
  vi.unstubAllGlobals()
})
const makeNode = (id: string) => ({ id, x: 1, y: 2, fx: 1, fy: 2 }) as GraphNode
const setup = () => {
  const save = vi.fn()
  return {
    save,
    // eslint-disable-next-line react-hooks/rules-of-hooks -- Hooks are mocked by this lifecycle harness.
    ...useLayout({
      forceSettings: {} as GraphForceSettings,
      containerSize: { width: 800, height: 600 },
      saveAllNodePositions: save
    })
  }
}
it('cancels superseded layout, ignores late results and saves only the current positions', async () => {
  const { applyLayout, save } = setup()
  const old = makeNode('old'),
    current = makeNode('current')
  const first = applyLayout({ nodes: [old], edges: [], layoutType: 'force' })
  const rejected = expect(first).rejects.toMatchObject({ name: 'AbortError' })
  const second = applyLayout({ nodes: [current], edges: [], layoutType: 'hierarchy' })
  await rejected
  expect(FakeWorker.instances[0].terminate).toHaveBeenCalledOnce()
  FakeWorker.instances[0].complete([{ id: 'old', x: 100, y: 100 }])
  expect(old).toMatchObject({ x: 1, y: 2, fx: 1, fy: 2 })
  FakeWorker.instances[1].complete([{ id: 'current', x: 0, y: 40 }])
  await second
  expect(current).toMatchObject({ x: 0, y: 40, fx: 0, fy: 40 })
  expect(save).toHaveBeenCalledOnce()
  expect(save).toHaveBeenCalledWith([current], true)
})
it('preserves pinning on failed layout and rejects an unmounted request', async () => {
  const { applyLayout, save } = setup()
  const node = makeNode('a')
  const request = applyLayout({ nodes: [node], edges: [], layoutType: 'force' })
  const rejected = expect(request).rejects.toMatchObject({ name: 'AbortError' })
  lifecycle.cleanup?.()
  await rejected
  expect(node).toMatchObject({ fx: 1, fy: 2 })
  expect(save).not.toHaveBeenCalled()
})
