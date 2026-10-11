import { beforeEach, expect, it, vi } from 'vitest'
import { useSaveNodePositions } from './use-save-node-positions'
import type { GraphNode } from '@/types'

// Tiny hook lifecycle harness: node environment, no browser or extra test dependency.
const harness = vi.hoisted(() => ({
  cursor: 0,
  slots: [] as unknown[],
  dirty: false,
  effects: [] as (() => void)[]
}))
vi.mock('react', () => ({
  useState: <T>(initial: T) => {
    const index = harness.cursor++
    if (!(index in harness.slots)) harness.slots[index] = initial
    return [
      harness.slots[index],
      (value: T) => {
        harness.slots[index] = value
        harness.dirty = true
      }
    ]
  },
  useRef: <T>(initial: T) => {
    const index = harness.cursor++
    if (!(index in harness.slots)) harness.slots[index] = { current: initial }
    return harness.slots[index]
  },
  useCallback: <T>(callback: T, deps: unknown[]) => {
    const index = harness.cursor++
    const old = harness.slots[index] as { callback: T; deps: unknown[] } | undefined
    if (!old || deps.some((value, i) => value !== old.deps[i]))
      harness.slots[index] = { callback, deps }
    return (harness.slots[index] as { callback: T }).callback
  },
  useEffect: (effect: () => void | (() => void), deps: unknown[]) => {
    const index = harness.cursor++
    const old = harness.slots[index] as { cleanup?: () => void; deps: unknown[] } | undefined
    if (!old || deps.some((value, i) => value !== old.deps[i])) {
      harness.effects.push(() => {
        old?.cleanup?.()
        harness.slots[index] = { deps, cleanup: effect() }
      })
    }
  }
}))
vi.mock('./use-debounce', () => ({ useDebounce: <T>(value: T) => value }))
const mocks = vi.hoisted(() => ({
  write: vi.fn(),
  status: vi.fn(),
  setNodes: vi.fn(),
  nodes: [] as GraphNode[]
}))
vi.mock('@/api/sketch-service', () => ({ sketchService: { updateNodePositions: mocks.write } }))
vi.mock('@/stores/graph-save-status-store', () => ({
  useGraphSaveStatus: (selector: (value: { setSaveStatus: typeof mocks.status }) => unknown) =>
    selector({ setSaveStatus: mocks.status })
}))
vi.mock('@/stores/graph-store', () => ({
  useGraphStore: Object.assign(
    (selector: (value: { setNodes: typeof mocks.setNodes }) => unknown) =>
      selector({ setNodes: mocks.setNodes }),
    { getState: () => ({ nodes: mocks.nodes }) }
  )
}))
const render = (sketchId = 'one') => {
  let result: ReturnType<typeof useSaveNodePositions>
  do {
    harness.cursor = 0
    harness.dirty = false
    harness.effects = []
    // eslint-disable-next-line react-hooks/rules-of-hooks -- Each loop iteration simulates a separate render with mocked hooks.
    result = useSaveNodePositions(sketchId)
    harness.effects.forEach((effect) => effect())
  } while (harness.dirty)
  return result!
}
const flush = async () => {
  for (let i = 0; i < 8; i++) await Promise.resolve()
}
beforeEach(() => {
  harness.slots = []
  harness.cursor = 0
  mocks.write.mockReset()
  mocks.status.mockClear()
  mocks.setNodes.mockClear()
  mocks.nodes = []
})
it('serializes writes and retains newer drags when an earlier write finishes', async () => {
  let resolveFirst!: () => void
  mocks.write
    .mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          resolveFirst = resolve
        })
    )
    .mockResolvedValue(undefined)
  let hook = render()
  const node = { id: 'a', x: 1, y: 2 } as GraphNode
  hook.saveAllNodePositions([node])
  hook = render()
  await flush()
  expect(mocks.write).toHaveBeenCalledTimes(1)
  hook.saveAllNodePositions([{ ...node, x: 99 }])
  hook = render()
  await flush()
  expect(mocks.write).toHaveBeenCalledTimes(1)
  expect(hook.hasPendingChanges).toBe(true)
  resolveFirst()
  await flush()
  expect(mocks.write.mock.calls[1]).toEqual(['one', [{ nodeId: 'a', x: 99, y: 2 }]])
  hook = render()
  expect(hook.hasPendingChanges).toBe(false)
})
it('does not send an old batch to a newly opened sketch or overwrite its status', async () => {
  let resolveFirst!: () => void
  mocks.write.mockImplementationOnce(
    () =>
      new Promise<void>((resolve) => {
        resolveFirst = resolve
      })
  )
  let hook = render()
  hook.saveAllNodePositions([{ id: 'a', x: 1, y: 2 } as GraphNode])
  render()
  await flush()
  hook = render('two')
  resolveFirst()
  await flush()
  expect(mocks.write).toHaveBeenCalledTimes(1)
  expect(mocks.write.mock.calls[0][0]).toBe('one')
  expect(hook.hasPendingChanges).toBe(false)
  expect(mocks.status).toHaveBeenLastCalledWith('idle')
})
