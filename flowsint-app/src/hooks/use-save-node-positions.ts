import { useCallback, useEffect, useRef, useState } from 'react'
import { useDebounce } from './use-debounce'
import { sketchService } from '@/api/sketch-service'
import { useGraphSaveStatus } from '@/stores/graph-save-status-store'
import { useGraphStore } from '@/stores/graph-store'
import type { GraphNode } from '@/types'

interface NodePosition {
  x: number
  y: number
}
export type SaveStatus = 'idle' | 'pending' | 'saving' | 'saved' | 'error'
type Batch = { sketchId?: string; positions: Map<string, NodePosition> }

export function useSaveNodePositions(sketchId?: string) {
  const [batch, setBatch] = useState<Batch>({ sketchId, positions: new Map() })
  const latest = useRef(batch)
  const writes = useRef(Promise.resolve())
  const isStabilizingRef = useRef(false)
  const setNodes = useGraphStore((s) => s.setNodes)
  const setSaveStatus = useGraphSaveStatus((state) => state.setSaveStatus)
  const debouncedBatch = useDebounce(batch, 1200)

  const clearPendingChanges = useCallback(() => {
    const empty = { sketchId, positions: new Map<string, NodePosition>() }
    latest.current = empty
    setBatch(empty)
    setSaveStatus('idle')
  }, [sketchId, setSaveStatus])

  useEffect(() => {
    latest.current = { sketchId, positions: new Map() }
    setSaveStatus('idle')
    return () => {
      latest.current = { positions: new Map() }
    }
  }, [sketchId, setSaveStatus])

  const markAsStabilized = useCallback(() => {
    isStabilizingRef.current = false
  }, [])
  const markAsStabilizing = useCallback(() => {
    isStabilizingRef.current = true
  }, [])
  const saveAllNodePositions = useCallback(
    (nodes: GraphNode[], force = false) => {
      if (!sketchId || (!force && isStabilizingRef.current)) return
      const positions = new Map(
        latest.current.sketchId === sketchId ? latest.current.positions : []
      )
      for (const node of nodes) {
        if (Number.isFinite(node.x) && Number.isFinite(node.y)) {
          node.fx = node.x
          node.fy = node.y
          positions.set(node.id, { x: node.x, y: node.y })
        }
      }
      if (!positions.size) return
      const next = { sketchId, positions }
      latest.current = next
      setBatch(next)
      setNodes(
        useGraphStore.getState().nodes.map((node) => {
          const position = positions.get(node.id)
          return position ? { ...node, ...position, fx: position.x, fy: position.y } : node
        })
      )
      setSaveStatus('pending')
    },
    [sketchId, setNodes, setSaveStatus]
  )

  useEffect(() => {
    if (!sketchId || debouncedBatch.sketchId !== sketchId || !debouncedBatch.positions.size) return
    let cancelled = false
    // Serialize writes so an older response cannot overwrite a newer drag on the server.
    writes.current = writes.current.then(async () => {
      if (cancelled) return
      const positions = Array.from(debouncedBatch.positions, ([nodeId, pos]) => ({
        nodeId,
        ...pos
      }))
      if (latest.current === debouncedBatch) setSaveStatus('saving')
      try {
        await sketchService.updateNodePositions(sketchId, positions)
        // A completed write only acknowledges its own batch, never a newer drag.
        if (latest.current === debouncedBatch) {
          const empty = { sketchId, positions: new Map<string, NodePosition>() }
          latest.current = empty
          setBatch(empty)
          setSaveStatus('saved')
        }
      } catch (error) {
        console.error('[useSaveNodePositions] Failed to save:', error)
        if (latest.current === debouncedBatch) setSaveStatus('error')
      }
    })
    return () => {
      cancelled = true
    }
  }, [debouncedBatch, sketchId, setSaveStatus])

  return {
    saveAllNodePositions,
    markAsStabilized,
    markAsStabilizing,
    clearPendingChanges,
    hasPendingChanges: batch.sketchId === sketchId && batch.positions.size > 0
  }
}
