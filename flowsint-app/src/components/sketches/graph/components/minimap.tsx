import { useEffect, useRef, useMemo } from 'react'
import { GraphNode, type GraphViewerRef } from '@/types'

interface MinimapCanvasProps {
  nodes: GraphNode[]
  width?: number
  height?: number
  graphRef: React.RefObject<GraphViewerRef>
  canvasWidth: number
  canvasHeight: number
  viewportRevision: number
  positionRevision: number
}

const MinimapCanvas = ({
  nodes,
  width = 160,
  height = 120,
  graphRef,
  canvasWidth,
  canvasHeight,
  viewportRevision,
  positionRevision
}: MinimapCanvasProps) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  const bounds = useMemo(() => {
    // The renderer mutates coordinates in place when a layout settles.
    void positionRevision
    let minX = Infinity,
      minY = Infinity,
      maxX = -Infinity,
      maxY = -Infinity
    for (const node of nodes) {
      if (!Number.isFinite(node.x) || !Number.isFinite(node.y)) continue
      minX = Math.min(minX, node.x)
      minY = Math.min(minY, node.y)
      maxX = Math.max(maxX, node.x)
      maxY = Math.max(maxY, node.y)
    }
    return Number.isFinite(minX) ? { minX, minY, maxX, maxY } : null
  }, [nodes, positionRevision])

  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return
    const renderMinimap = () => {
      if (!graphRef.current) return

      if (!bounds) return

      const { minX, minY, maxX, maxY } = bounds

      try {
        // Check if required methods exist
        if (
          typeof graphRef.current.graph2ScreenCoords !== 'function' ||
          typeof graphRef.current.zoom !== 'function'
        ) {
          return
        }

        // Get the current zoom state from the graph
        const k = graphRef.current.zoom() || 1

        // Calculate viewport bounds in world coordinates
        const invScale = 1 / k
        const viewportWidth = canvasWidth * invScale
        const viewportHeight = canvasHeight * invScale

        // Get center position - use centerAt if available, otherwise default to origin
        let centerX = 0
        let centerY = 0

        if (typeof graphRef.current.centerAt === 'function') {
          const center = graphRef.current.centerAt()
          centerX = center?.x ?? 0
          centerY = center?.y ?? 0
        }

        const viewportX1 = centerX - viewportWidth / 2
        const viewportY1 = centerY - viewportHeight / 2
        const viewportX2 = centerX + viewportWidth / 2
        const viewportY2 = centerY + viewportHeight / 2

        // Expand bounds to include viewport
        const worldMinX = Math.min(minX, viewportX1)
        const worldMinY = Math.min(minY, viewportY1)
        const worldMaxX = Math.max(maxX, viewportX2)
        const worldMaxY = Math.max(maxY, viewportY2)

        const worldWidth = worldMaxX - worldMinX || 1
        const worldHeight = worldMaxY - worldMinY || 1

        // Scale to fit in minimap
        const scaleX = width / worldWidth
        const scaleY = height / worldHeight
        const scale = Math.min(scaleX, scaleY) * 0.9 // 0.9 for padding

        // Center content
        const offsetX = (width - worldWidth * scale) / 2
        const offsetY = (height - worldHeight * scale) / 2

        // Project function
        const project = (x: number, y: number): [number, number] => [
          (x - worldMinX) * scale + offsetX,
          (y - worldMinY) * scale + offsetY
        ]

        // Clear canvas
        ctx.clearRect(0, 0, width, height)

        // Draw nodes
        const nodeRadius = 0.75
        for (const node of nodes) {
          if (typeof node.x !== 'number' || typeof node.y !== 'number') continue

          const [cx, cy] = project(node.x, node.y)

          ctx.beginPath()
          ctx.arc(cx, cy, nodeRadius, 0, 2 * Math.PI)
          ctx.fillStyle = node.nodeColor || '#888'
          ctx.fill()
        }

        // Draw viewport rectangle
        const [vx1, vy1] = project(viewportX1, viewportY1)
        const [vx2, vy2] = project(viewportX2, viewportY2)

        const rectWidth = Math.abs(vx2 - vx1)
        const rectHeight = Math.abs(vy2 - vy1)
        const rectX = Math.min(vx1, vx2)
        const rectY = Math.min(vy1, vy2)

        ctx.strokeStyle = 'rgba(255, 115, 0, 0.8)'
        ctx.fillStyle = 'rgba(255, 115, 0, 0.1)'
        ctx.lineWidth = 1.4
        ctx.beginPath()
        ctx.roundRect(rectX, rectY, rectWidth, rectHeight, 2)
        ctx.fill()
        ctx.stroke()
      } catch {
        // Silent fail if graph not ready
        return
      }
    }

    const frame = requestAnimationFrame(renderMinimap)
    return () => cancelAnimationFrame(frame)
  }, [nodes, bounds, width, height, graphRef, canvasWidth, canvasHeight, viewportRevision])

  return (
    <div
      style={{ width, height }}
      className="absolute bottom-3 right-3 bg-background/90 backdrop-blur-sm overflow-hidden border border-border rounded-lg"
    >
      <canvas ref={canvasRef} width={width} height={height} className="bg-transparent" />
    </div>
  )
}

export default MinimapCanvas
