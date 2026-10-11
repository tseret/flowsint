import { useGraphStore } from '@/stores/graph-store'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { Separator } from '@/components//ui/separator'
import TypeFilters from './type-filters'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { useParams } from '@tanstack/react-router'
import { useAuthStore } from '@/stores/auth-store'
import { useGraphViews } from '@/stores/graph-views-store'
import { useGraphControls } from '@/stores/graph-controls-store'
import { useState } from 'react'

const Filters = ({ children }: { children: React.ReactNode }) => {
  const filters = useGraphStore((s) => s.filters)
  const toggleTypeFilter = useGraphStore((s) => s.toggleTypeFilter)
  const setFilters = useGraphStore((s) => s.setFilters)
  const nodes = useGraphStore((s) => s.nodes)
  const edges = useGraphStore((s) => s.edges)
  const userId = useAuthStore((s) => s.user?.id)
  const { id: sketchId } = useParams({ strict: false })
  const scope = `${userId}:${sketchId}`
  const views = useGraphViews((s) => s.views[scope]) || []
  const [viewName, setViewName] = useState('')
  const providers = [
    ...new Set(
      edges.flatMap(
        (edge) =>
          edge.observations
            ?.map((item) => item.provider)
            .filter((item): item is string => !!item) || []
      )
    )
  ].sort()
  const relationships = [...new Set(edges.map((edge) => edge.type || edge.label))].sort()
  const infrastructure = [
    ...new Set(
      nodes
        .filter((node) => ['cidr', 'ip', 'port'].includes(node.nodeType.toLowerCase()))
        .map((node) => node.nodeType)
    )
  ].sort()

  return (
    <Popover>
      <PopoverTrigger asChild>
        <div>{children}</div>
      </PopoverTrigger>
      <PopoverContent className="w-112 bg-background max-h-[60vh] overflow-auto">
        <div className="grid gap-2">
          <div className="space-y-1">
            <h5 className="leading-none font-medium text-sm">Filters</h5>
          </div>
          <Separator />
          <TypeFilters filters={filters} toggleTypeFilter={toggleTypeFilter} />
          <Separator />
          <label className="text-xs">
            Provider
            <select
              className="w-full border rounded p-2 bg-background"
              value={filters.provider || ''}
              onChange={(e) => setFilters({ ...filters, provider: e.target.value })}
            >
              <option value="">All providers</option>
              {providers.map((provider) => (
                <option key={provider}>{provider}</option>
              ))}
            </select>
          </label>
          <label className="text-xs">
            Relationship type
            <select
              className="w-full border rounded p-2 bg-background"
              value={filters.relationship || ''}
              onChange={(e) => setFilters({ ...filters, relationship: e.target.value })}
            >
              <option value="">All relationships</option>
              {relationships.map((relationship) => (
                <option key={relationship}>{relationship}</option>
              ))}
            </select>
          </label>
          <div className="flex gap-2">
            <label className="text-xs flex-1">
              Observed from
              <Input
                type="date"
                value={filters.observedAfter || ''}
                onChange={(e) => setFilters({ ...filters, observedAfter: e.target.value })}
              />
            </label>
            <label className="text-xs flex-1">
              Observed through
              <Input
                type="date"
                value={filters.observedBefore || ''}
                onChange={(e) => setFilters({ ...filters, observedBefore: e.target.value })}
              />
            </label>
          </div>
          <p className="text-xs text-muted-foreground">
            Evidence filters hide relationships without a matching observation. Entities stay
            visible.
          </p>
          {infrastructure.map((type) => {
            const collapsed = filters.collapsedTypes?.includes(type)
            return (
              <Button
                key={type}
                variant="outline"
                size="sm"
                aria-expanded={!collapsed}
                onClick={() =>
                  setFilters({
                    ...filters,
                    collapsedTypes: collapsed
                      ? filters.collapsedTypes?.filter((item) => item !== type)
                      : [...(filters.collapsedTypes || []), type]
                  })
                }
              >
                {collapsed ? 'Expand' : 'Collapse'} {type} infrastructure (
                {nodes.filter((node) => node.nodeType === type).length})
              </Button>
            )
          })}
          <Separator />
          <p className="text-xs font-medium">Named views · saved in this browser</p>
          {userId && sketchId && (
            <>
              <div className="flex gap-2">
                <Input
                  aria-label="View name"
                  placeholder="View name"
                  maxLength={80}
                  value={viewName}
                  onChange={(e) => setViewName(e.target.value)}
                />
                <Button
                  size="sm"
                  disabled={!viewName.trim()}
                  onClick={() => {
                    useGraphViews.getState().save(scope, {
                      name: viewName.trim(),
                      filters,
                      positions: Object.fromEntries(
                        nodes
                          .filter((node) => Number.isFinite(node.x) && Number.isFinite(node.y))
                          .map((node) => [node.id, { x: node.x, y: node.y }])
                      ),
                      view: useGraphControls.getState().view
                    })
                    setViewName('')
                  }}
                >
                  Save
                </Button>
              </div>
              {views.map((saved) => (
                <div key={saved.name} className="flex gap-2">
                  <Button
                    variant="outline"
                    className="flex-1"
                    size="sm"
                    onClick={() => {
                      const state = useGraphStore.getState()
                      state.updateGraphData(
                        state.nodes.map((node) =>
                          saved.positions[node.id]
                            ? {
                                ...node,
                                ...saved.positions[node.id],
                                fx: saved.positions[node.id].x,
                                fy: saved.positions[node.id].y
                              }
                            : node
                        ),
                        state.edges
                      )
                      setFilters(saved.filters)
                      useGraphControls.getState().setView(saved.view)
                    }}
                  >
                    {saved.name}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    aria-label={`Delete view ${saved.name}`}
                    onClick={() => useGraphViews.getState().remove(scope, saved.name)}
                  >
                    Delete
                  </Button>
                </div>
              ))}
            </>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() =>
              setFilters({
                types: filters.types.map((type) => ({ ...type, checked: true })),
                rules: []
              })
            }
          >
            Clear filters
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  )
}

export default Filters
