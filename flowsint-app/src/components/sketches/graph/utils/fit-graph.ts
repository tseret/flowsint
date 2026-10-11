import type { GraphNode } from '@/types'

type Bounds = { left: number; right: number; top: number; bottom: number }

export function fitGraphViewport(
  nodes: GraphNode[],
  width: number,
  height: number,
  measure: (node: GraphNode, zoom: number) => Bounds
) {
  const positioned = nodes.filter((node) => Number.isFinite(node.x) && Number.isFinite(node.y))
  if (!positioned.length || width <= 0 || height <= 0) return null
  let zoom = 4
  let bounds: Bounds = { left: 0, right: 0, top: 0, bottom: 0 }
  // Dot labels keep a screen-space font size; recompute their world extents as zoom changes.
  for (let pass = 0; pass < 16; pass++) {
    bounds = { left: Infinity, right: -Infinity, top: Infinity, bottom: -Infinity }
    for (const node of positioned) {
      const box = measure(node, zoom)
      bounds.left = Math.min(bounds.left, box.left)
      bounds.right = Math.max(bounds.right, box.right)
      bounds.top = Math.min(bounds.top, box.top)
      bounds.bottom = Math.max(bounds.bottom, box.bottom)
    }
    const next =
      Math.min(
        4,
        Math.max(1, width - 120) / Math.max(1, bounds.right - bounds.left),
        Math.max(1, height - 180) / Math.max(1, bounds.bottom - bounds.top)
      ) * 0.95
    if (Math.abs(next - zoom) < 0.00001) break
    zoom = Math.max(0.001, Math.min(zoom, next))
  }
  return {
    x: (bounds.left + bounds.right) / 2,
    y: (bounds.top + bounds.bottom) / 2 - 35 / zoom,
    zoom
  }
}
