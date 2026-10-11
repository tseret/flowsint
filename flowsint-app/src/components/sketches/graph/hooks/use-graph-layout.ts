import { useState, useCallback, useRef, useEffect } from 'react'
import { useLayout } from '@/hooks/use-layout'
import type { GraphNode, GraphViewerRef } from '@/types'
import type { GraphForceSettings } from '@/stores/graph-settings-store'
import type { GraphData } from '../utils/types'

interface UseGraphLayoutParams {
  forceSettings: GraphForceSettings
  containerSize: { width: number; height: number }
  saveAllNodePositions: (nodes: GraphNode[]) => void
  graphRef: React.RefObject<GraphViewerRef>
  graphData: GraphData
  fitToView: () => void
}

export const useGraphLayout = ({
  forceSettings,
  containerSize,
  saveAllNodePositions,
  graphRef,
  graphData,
  fitToView
}: UseGraphLayoutParams) => {
  const [isRegeneratingLayout, setIsRegeneratingLayout] = useState(false)
  const requestRef = useRef(0)

  const { applyLayout, cancelLayout } = useLayout({
    forceSettings,
    containerSize,
    saveAllNodePositions,
    onProgress: (progress) => {
      // Keep loading state active while worker is running
      if (progress < 100) {
        setIsRegeneratingLayout(true)
      }
    }
  })
  useEffect(() => () => cancelLayout(), [graphData, cancelLayout])

  const regenerateLayout = useCallback(
    async (layoutType: 'force' | 'hierarchy') => {
      if (!graphRef.current || !graphData?.nodes) {
        console.warn('Cannot regenerate layout: graph not ready')
        return
      }

      setIsRegeneratingLayout(true)
      const request = ++requestRef.current

      try {
        await applyLayout({
          layoutType,
          nodes: graphData.nodes,
          edges: graphData.links
        })

        // Wait a bit for positions to be applied, then zoom to fit
        setTimeout(() => {
          if (request === requestRef.current && graphRef.current?.zoomToFit) {
            fitToView()
          }
        }, 100)
      } catch (error) {
        if (!(error instanceof DOMException && error.name === 'AbortError'))
          console.error('Layout calculation failed:', error)
      } finally {
        // Keep overlay visible for smooth transition
        setTimeout(() => {
          if (request === requestRef.current) setIsRegeneratingLayout(false)
        }, 600)
      }
    },
    [applyLayout, graphRef, graphData, fitToView]
  )

  return {
    isRegeneratingLayout,
    regenerateLayout
  }
}
