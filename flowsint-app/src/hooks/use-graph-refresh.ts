import { useEffect, useRef } from 'react'
import { useGraphControls } from '@/stores/graph-controls-store'
import { useAuthStore } from '@/stores/auth-store'
import { EventLevel } from '@/types'
import { connectSSE } from '@/api/sse'
import { useGraphStore } from '@/stores/graph-store'
import { useQueryClient } from '@tanstack/react-query'

const API_URL = import.meta.env.VITE_API_URL ?? ''

export function useGraphRefresh(sketch_id: string | undefined) {
  const refetchGraph = useGraphControls((s) => s.refetchGraph)
  const token = useAuthStore((s) => s.token)
  const queryClient = useQueryClient()

  // Use refs to avoid reconnecting SSE when functions change
  const refetchGraphRef = useRef(refetchGraph)

  // Keep refs updated
  useEffect(() => {
    refetchGraphRef.current = refetchGraph
  }, [refetchGraph])

  useEffect(() => {
    if (!sketch_id || !token) return

    const dispose = connectSSE({
      url: `${API_URL}/api/events/sketch/${sketch_id}/status/stream`,
      onMessage: (raw) => {
        // Only process status events
        if (raw.event !== 'status') return
        try {
          const event = JSON.parse(raw.data as string) as any
          // Only handle COMPLETED events
          if (
            event.type === EventLevel.COMPLETED ||
            event.type === EventLevel.FAILED ||
            event.payload?.summary
          ) {
            void queryClient.invalidateQueries({ queryKey: ['scans', 'list', sketch_id] })
            void queryClient.invalidateQueries({ queryKey: ['enrichers', 'readiness'] })
            const refetch = refetchGraphRef.current

            if (typeof refetch !== 'function') return

            useGraphStore.getState().setPendingRefresh(true)
            refetch(() => {
              const state = useGraphStore.getState()
              // React Query can retain identical data references after an empty run.
              if (state.pendingRefresh)
                state.setChanges({
                  addedNodes: [],
                  updatedNodes: [],
                  addedEdges: [],
                  updatedEdges: []
                })
            })
          }
        } catch (error) {
          console.error('[useGraphRefresh] Failed to parse status payload:', error, raw.data)
        }
      }
    })

    return dispose
  }, [sketch_id, token, queryClient])
}
