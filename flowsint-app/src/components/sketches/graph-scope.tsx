import { useEffect, useRef, useState } from 'react'
import { sketchService } from '@/api/sketch-service'
import { useGraphStore } from '@/stores/graph-store'
import { preserveGraphPositions } from '@/lib/graph-presentation'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import type { SketchGraphData } from '@/types'
import { toast } from 'sonner'

export function GraphScope({ sketchId, graph }: { sketchId: string; graph: SketchGraphData }) {
  const nodes = useGraphStore((s) => s.nodes)
  const edges = useGraphStore((s) => s.edges)
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<SketchGraphData | null>(null)
  const [busy, setBusy] = useState(false)
  const active = useRef(true)
  useEffect(() => {
    active.current = true
    return () => {
      active.current = false
    }
  }, [])
  const merge = (slice: SketchGraphData) => {
    const state = useGraphStore.getState()
    const mergedNodes = [...new Map([...state.nodes, ...slice.nds].map((n) => [n.id, n])).values()]
    const mergedEdges = [...new Map([...state.edges, ...slice.rls].map((e) => [e.id, e])).values()]
    state.updateGraphData(
      preserveGraphPositions(mergedNodes, state.nodes, mergedEdges),
      mergedEdges
    )
  }
  const search = async () => {
    setBusy(true)
    try {
      const slice = await sketchService.getGraphSlice(sketchId, { search: query, limit: 50 })
      if (active.current) setResults(slice)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Search failed')
    } finally {
      setBusy(false)
    }
  }
  const expand = async (id: string) => {
    setBusy(true)
    try {
      const slice = await sketchService.getGraphSlice(sketchId, { center_ids: [id], limit: 500 })
      if (!active.current) return
      merge(slice)
      useGraphStore.getState().setCurrentNodeId(id)
      setResults(null)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Expansion failed')
    } finally {
      setBusy(false)
    }
  }
  return (
    <details className="border-b px-3 py-1 text-xs">
      <summary className="w-fit cursor-pointer">
        Loaded {nodes.length} of {graph.total_nodes ?? nodes.length} entities · {edges.length} of{' '}
        {graph.total_edges ?? edges.length} relationships
        {graph.truncated && ' · Partial graph — search to explore'}
      </summary>
      <form
        className="flex gap-2 py-2"
        onSubmit={(event) => {
          event.preventDefault()
          void search()
        }}
      >
        <Input
          aria-label="Search entire investigation graph"
          placeholder="Find an entity in the entire sketch…"
          value={query}
          maxLength={200}
          onChange={(e) => setQuery(e.target.value)}
        />
        <Button size="sm" disabled={busy || !query.trim()}>
          Search
        </Button>
      </form>
      {results && (
        <div className="max-h-48 overflow-auto">
          <p>
            {results.nds.length} matches shown (up to 50). Expand loads up to 500 neighboring
            entities.
          </p>
          {results.nds.map((node) => (
            <Button
              key={node.id}
              variant="ghost"
              size="sm"
              disabled={busy}
              onClick={() => void expand(node.id)}
            >
              {node.nodeLabel} · {node.nodeType}
            </Button>
          ))}
        </div>
      )}
    </details>
  )
}
