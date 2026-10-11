import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { Filters } from '@/types/filter'

export type GraphView = {
  name: string
  filters: Filters
  positions: Record<string, { x: number; y: number }>
  view: 'graph' | 'table' | 'map' | 'relationships'
}

export const useGraphViews = create<{
  views: Record<string, GraphView[]>
  save: (scope: string, view: GraphView) => void
  remove: (scope: string, name: string) => void
}>()(
  persist(
    (set) => ({
      views: {},
      save: (scope, view) =>
        set((state) => ({
          views: {
            ...state.views,
            [scope]: [...(state.views[scope] || []).filter((item) => item.name !== view.name), view]
          }
        })),
      remove: (scope, name) =>
        set((state) => ({
          views: {
            ...state.views,
            [scope]: (state.views[scope] || []).filter((item) => item.name !== name)
          }
        }))
    }),
    { name: 'graph-named-views' }
  )
)
