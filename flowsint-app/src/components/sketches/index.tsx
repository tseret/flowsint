import { useLoaderData } from '@tanstack/react-router'
import { useEffect, useRef, memo, useState, lazy, Suspense } from 'react'
import { useGraphStore } from '@/stores/graph-store'
import { Toolbar } from './toolbar'
import { cn } from '@/lib/utils'
import { ArrowDownToLineIcon } from 'lucide-react'
import { CreateRelationDialog } from './create-relation'
import GraphLoader from './graph/components/graph-loader'
import Loader from '../loader'
import { useGraphControls } from '@/stores/graph-controls-store'
import NodesTable from '../table'
import { findActionItemByKey } from '@/lib/action-items'
import { useActionItems } from '@/hooks/use-action-items'
import { toast } from 'sonner'
import MapPanel from '../map/map-panel'
import NewActions from './add-item-dialog'
import GraphMain from './graph/components/graph-main'
import Settings, { KeyboardShortcuts } from './settings/settings'
import { type GraphNode, type GraphEdge } from '@/types'
import { MergeDialog } from './graph/actions/merge-nodes'
import { useGraphRefresh } from '@/hooks/use-graph-refresh'
import { usePermissions } from '@/hooks/use-can'
import { preserveGraphPositions, graphChanges } from '@/lib/graph-presentation'
import { Button } from '@/components/ui/button'
import { RunSummaries } from './run-summary'
const RelationshipsTable = lazy(() => import('@/components/table/relationships-view'))

// Separate component for the drag overlay
const DragOverlay = memo(({ isDragging }: { isDragging: boolean }) => (
  <div
    className={cn(
      'absolute flex items-center justify-center inset-0 bg-background/80 backdrop-blur-sm gap-1',
      'opacity-0 pointer-events-none transition-opacity duration-200',
      isDragging && 'opacity-100 pointer-events-auto'
    )}
  >
    <p className="font-medium">Drop here to add node</p>
    <ArrowDownToLineIcon className="opacity-60" />
  </div>
))
DragOverlay.displayName = 'DragOverlay'

interface GraphPanelProps {
  graphData: { nds: GraphNode[]; rls: GraphEdge[] } | null
  isLoading: boolean
  isRefetching: boolean
}

const GraphPanel = ({ graphData, isLoading }: GraphPanelProps) => {
  const { canCreate } = usePermissions()
  const handleOpenFormModal = useGraphStore((s) => s.handleOpenFormModal)
  const view = useGraphControls((s) => s.view)
  const updateGraphData = useGraphStore((s) => s.updateGraphData)
  const setFilters = useGraphStore((s) => s.setFilters)
  const { actionItems, isLoading: isLoadingActionItems } = useActionItems()

  const { params, sketch } = useLoaderData({
    from: '/_auth/dashboard/investigations/$investigationId/$type/$id'
  })
  const [isDraggingOver, setIsDraggingOver] = useState(false)
  const loadedSketch = useRef<string | undefined>(undefined)
  const changes = useGraphStore((s) => s.changes)
  const collapsedTypes = useGraphStore((s) => s.filters.collapsedTypes)
  const nodes = useGraphStore((s) => s.nodes)

  // Dedicated hook for graph refresh on transform completion
  useGraphRefresh(params.id)

  useEffect(() => {
    if (graphData?.nds && graphData?.rls) {
      const state = useGraphStore.getState()
      const sameSketch = loadedSketch.current === params.id
      if (sameSketch && state.pendingRefresh) {
        state.setChanges(graphChanges(graphData.nds, graphData.rls, state.nodes, state.edges))
      } else if (!sameSketch) {
        state.setChanges(null)
        state.reset()
      }
      updateGraphData(
        sameSketch
          ? preserveGraphPositions(graphData.nds, state.nodes, graphData.rls)
          : graphData.nds,
        graphData.rls
      )
      loadedSketch.current = params.id
      const types = new Set(graphData.nds.map((n) => n.nodeType))
      // Read current filters via getState() rather than subscribing — this
      // effect shouldn't re-run just because filters changed.
      const previousFilters = sameSketch ? state.filters : { types: [], rules: [] }
      setFilters({
        ...previousFilters,
        types: Array.from(types).map((t) => ({
          type: t,
          checked: previousFilters.types.find((filter) => filter.type === t)?.checked ?? true
        }))
      })
    }
  }, [params.id, graphData?.nds, graphData?.rls, setFilters, updateGraphData])

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDraggingOver(true)
  }

  const handleDragEnter = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDraggingOver(true)
  }

  const handleDragLeave = () => {
    setIsDraggingOver(false)
  }

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDraggingOver(false)
    if (isLoadingActionItems || !actionItems) {
      toast.error('Sorry, an error occured. Please try again.')
      return
    }
    const data = e.dataTransfer.getData('text/plain')
    if (data) {
      try {
        const parsedData = JSON.parse(data)
        handleOpenFormModal(findActionItemByKey(parsedData.itemKey, actionItems))
      } catch {
        return
      }
    }
  }
  if (isLoading) {
    return <GraphLoader />
  }

  if (!sketch || !graphData) {
    return (
      <div className="h-full w-full flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-lg font-semibold text-destructive mb-2">Error loading graph</h2>
          <p className="text-muted-foreground">Could not load graph data. Please try again.</p>
        </div>
      </div>
    )
  }

  return (
    <div
      onDragOver={canCreate ? handleDragOver : undefined}
      onDragEnter={canCreate ? handleDragEnter : undefined}
      onDragLeave={canCreate ? handleDragLeave : undefined}
      onDrop={canCreate ? handleDrop : undefined}
      className="h-full w-full flex flex-col relative outline-2 outline-transparent bg-background"
    >
      <Toolbar isLoading={isLoading} />
      <RunSummaries sketchId={params.id} />
      {!!collapsedTypes?.length && (
        <div className="flex flex-wrap gap-2 px-3 py-1 border-b">
          {collapsedTypes.map((type) => (
            <Button
              key={type}
              size="sm"
              variant="outline"
              className="h-6 text-xs"
              aria-expanded={false}
              onClick={() =>
                setFilters({
                  ...useGraphStore.getState().filters,
                  collapsedTypes: collapsedTypes.filter((item) => item !== type)
                })
              }
            >
              Expand {nodes.filter((node) => node.nodeType === type).length} {type} entities
            </Button>
          ))}
        </div>
      )}
      {changes && (
        <div
          role="status"
          className="flex items-center gap-2 px-3 py-1 border-b text-xs bg-primary/5"
        >
          <span>
            Run changes: {changes.addedNodes.length} new entities, {changes.updatedNodes.length}{' '}
            updated entities, {changes.addedEdges.length} new relationships,{' '}
            {changes.updatedEdges.length} updated relationships.
          </span>
          <Button
            size="sm"
            variant="ghost"
            className="ml-auto h-6"
            onClick={() => useGraphStore.getState().setChanges(null)}
          >
            Dismiss
          </Button>
        </div>
      )}
      <Suspense
        fallback={
          <div className="h-full w-full flex items-center justify-center">
            <div className="text-center flex items-center gap-2">
              <Loader />
            </div>
          </div>
        }
      >
        <div className="flex-1 min-h-0">
          {view === 'graph' && <GraphMain />}
          {view === 'table' && <NodesTable />}
          {view === 'map' && <MapPanel />}
          {view === 'relationships' && <RelationshipsTable />}
        </div>
      </Suspense>
      <DragOverlay isDragging={isDraggingOver} />
      <NewActions />
      <CreateRelationDialog />
      <MergeDialog />
      <Settings />
      <KeyboardShortcuts />
    </div>
  )
}

export default memo(GraphPanel)
