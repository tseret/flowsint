import { useCallback, useRef, useEffect } from 'react'
import { GraphEdge, GraphNode } from '@/types'
import type { GraphForceSettings } from '@/stores/graph-settings-store'

interface UseLayoutProps {
  forceSettings: GraphForceSettings
  containerSize: { width: number; height: number }
  saveAllNodePositions: (nodes: GraphNode[], force?: boolean) => void
  onProgress?: (progress: number) => void
}

interface LayoutOptions {
  layoutType: 'force' | 'hierarchy'
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export function applyLayoutPositions(
  nodes: GraphNode[],
  positions: { id: string; x: number; y: number }[]
) {
  const byId = new Map(nodes.map((node) => [node.id, node]))
  for (const position of positions) {
    const node = byId.get(position.id)
    if (node && Number.isFinite(position.x) && Number.isFinite(position.y)) {
      Object.assign(node, { x: position.x, y: position.y, fx: position.x, fy: position.y })
    }
  }
}

export function useLayout({
  forceSettings,
  containerSize,
  saveAllNodePositions,
  onProgress
}: UseLayoutProps) {
  const cancelRef = useRef<(() => void) | null>(null)
  useEffect(() => () => cancelRef.current?.(), [])

  const applyLayout = useCallback(
    ({ nodes, edges, layoutType }: LayoutOptions) => {
      // A superseded worker must never apply or persist positions from an older request.
      cancelRef.current?.()
      return new Promise<GraphNode[]>((resolve, reject) => {
        const worker = new Worker(new URL('../workers/layout.worker.ts', import.meta.url), {
          type: 'module'
        })
        const finish = () => {
          worker.terminate()
          if (cancelRef.current === cancel) cancelRef.current = null
        }
        const cancel = () => {
          finish()
          reject(new DOMException('Layout superseded', 'AbortError'))
        }
        cancelRef.current = cancel
        worker.onmessage = (event: MessageEvent) => {
          if (cancelRef.current !== cancel) return
          if (event.data.type === 'progress') {
            onProgress?.(event.data.progress)
          } else if (event.data.type === 'complete') {
            applyLayoutPositions(nodes, event.data.result.nodes)
            finish()
            saveAllNodePositions(nodes, true)
            resolve(nodes)
          } else if (event.data.type === 'error') {
            finish()
            reject(new Error(event.data.error))
          }
        }
        worker.onerror = (error) => {
          finish()
          reject(error)
        }
        try {
          worker.postMessage({
            type: layoutType === 'hierarchy' ? 'dagre' : 'force',
            nodes: nodes.map((node) => ({ ...node, fx: undefined, fy: undefined })),
            edges: edges.map((edge) => ({ ...edge })),
            options: {
              dagLevelDistance: forceSettings.dagLevelDistance?.value ?? 50,
              width: containerSize.width || 800,
              height: containerSize.height || 600,
              chargeStrength: forceSettings.d3ForceChargeStrength?.value ?? -150,
              linkDistance: forceSettings.d3ForceLinkDistance?.value ?? 35,
              linkStrength: forceSettings.d3ForceLinkStrength?.value ?? 1,
              alphaDecay: forceSettings.d3AlphaDecay?.value ?? 0.06,
              alphaMin: forceSettings.d3AlphaMin?.value ?? 0.001,
              velocityDecay: forceSettings.d3VelocityDecay?.value ?? 0.75,
              iterations: forceSettings.cooldownTicks?.value ?? 300,
              collisionRadius: forceSettings.collisionRadius?.value ?? 22,
              collisionStrength: forceSettings.collisionStrength?.value ?? 0.95,
              centerGravity: forceSettings.centerGravity?.value ?? 0.15
            }
          })
        } catch (error) {
          finish()
          reject(error)
        }
      })
    },
    [forceSettings, containerSize, saveAllNodePositions, onProgress]
  )
  const cancelLayout = useCallback(() => cancelRef.current?.(), [])
  return { applyLayout, cancelLayout }
}
