import { useMemo, useState } from 'react'
import type { GraphNode, GraphEdge, EvidenceObservation } from '@/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@/components/ui/select'
import {
  compareHosts,
  compareObservationDates,
  parseObservationDate,
  isHost,
  type InfrastructureGrouping,
  infrastructureOverview
} from '@/lib/infrastructure-analysis'

export type InfrastructureMode = 'graph' | 'overview' | 'focus'
interface Props {
  nodes: GraphNode[]
  edges: GraphEdge[]
  selectedIds: string[]
  mode: InfrastructureMode
  onMode: (mode: InfrastructureMode) => void
  grouping: InfrastructureGrouping
  onGrouping: (grouping: InfrastructureGrouping) => void
  groups: ReturnType<typeof infrastructureOverview>['groups']
  expanded: Set<string>
  onToggleGroup: (id: string) => void
  onFocus: () => void
  onExpand: () => void
  loading: boolean
  status: string
  onInspect: (id: string) => void
}

export function InfrastructureTools({
  nodes,
  edges,
  selectedIds,
  mode,
  onMode,
  grouping,
  onGrouping,
  groups,
  expanded,
  onToggleGroup,
  onFocus,
  onExpand,
  loading,
  status,
  onInspect
}: Props) {
  const [dialog, setDialog] = useState<'hosts' | 'changes' | null>(null)
  const [showGroups, setShowGroups] = useState(false)
  const dates = useMemo(
    () =>
      [
        ...new Set(
          edges.flatMap((edge) =>
            (edge.observations ?? []).flatMap((o) => {
              const observed = parseObservationDate(o.observed_at)
              return observed ? [observed.day] : []
            })
          )
        )
      ].sort(),
    [edges]
  )
  const [before, setBefore] = useState('')
  const [after, setAfter] = useState('')
  const from = before || dates[0] || '',
    to = after || dates[dates.length - 1] || ''
  const loadedHostIds = useMemo(() => new Set(nodes.filter(isHost).map((node) => node.id)), [nodes])
  const hostIds = selectedIds.filter((id) => loadedHostIds.has(id))
  const comparisons = useMemo(
    () => (dialog === 'hosts' ? compareHosts(nodes, edges, selectedIds) : []),
    [dialog, nodes, edges, selectedIds]
  )
  const changes = useMemo(
    () => (dialog === 'changes' ? compareObservationDates(edges, from, to) : null),
    [dialog, edges, from, to]
  )
  const labels = useMemo(() => new Map(nodes.map((node) => [node.id, node.nodeLabel])), [nodes])
  const inspect = (id: string) => {
    setDialog(null)
    onInspect(id)
  }
  return (
    <>
      <div
        className="absolute left-3 top-3 z-10 max-w-[calc(100%-1.5rem)] rounded-md border bg-background/95 p-2 shadow-sm"
        aria-label="Infrastructure investigation tools"
      >
        <div className="flex flex-wrap items-center gap-2">
          <Select value={mode} onValueChange={(value) => onMode(value as InfrastructureMode)}>
            <SelectTrigger className="w-40" aria-label="Graph view">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="graph">Entity graph</SelectItem>
              <SelectItem value="overview">Infrastructure</SelectItem>
              <SelectItem value="focus" disabled={!selectedIds.length}>
                Focused neighborhood
              </SelectItem>
            </SelectContent>
          </Select>
          {mode === 'overview' && (
            <>
              <Select
                value={grouping}
                onValueChange={(value) => onGrouping(value as InfrastructureGrouping)}
              >
                <SelectTrigger className="w-32" aria-label="Group infrastructure by">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="asn">ASN</SelectItem>
                  <SelectItem value="prefix">Prefix</SelectItem>
                  <SelectItem value="domain">Domain</SelectItem>
                </SelectContent>
              </Select>
              <Button size="sm" variant="outline" onClick={() => setShowGroups(!showGroups)}>
                Groups ({groups.length})
              </Button>
            </>
          )}
          <Button size="sm" variant="outline" disabled={!selectedIds.length} onClick={onFocus}>
            Focus selection
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={!selectedIds.length || loading}
            onClick={onExpand}
          >
            {loading ? 'Loading…' : 'Load neighbors'}
          </Button>
          <Button size="sm" variant="outline" onClick={() => setDialog('hosts')}>
            Compare hosts
          </Button>
          <Button size="sm" variant="outline" onClick={() => setDialog('changes')}>
            Compare dates
          </Button>
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          Loaded scope: {nodes.length.toLocaleString()} entities · {edges.length.toLocaleString()}{' '}
          relationships.{' '}
          {mode === 'overview'
            ? 'Click a group to expand; grouping does not establish common ownership.'
            : ''}
        </p>
        {status && (
          <p role="status" className="mt-1 max-w-2xl text-xs">
            {status}
          </p>
        )}
        {showGroups && mode === 'overview' && (
          <div className="mt-2 max-h-48 overflow-auto border-t pt-1">
            {groups.map((group) => (
              <Button
                key={group.id}
                className="flex h-auto w-full justify-between gap-4 text-left"
                size="sm"
                variant="ghost"
                onClick={() => onToggleGroup(group.id)}
              >
                <span className="truncate">{group.label}</span>
                <span className="shrink-0">
                  {group.hosts} hosts · {group.members.length} entities · {group.flagged} flagged ·{' '}
                  {expanded.has(group.id) ? 'Collapse' : 'Expand'}
                </span>
              </Button>
            ))}
          </div>
        )}
      </div>
      <Dialog open={dialog !== null} onOpenChange={(open) => !open && setDialog(null)}>
        <DialogContent className="max-h-[85vh] overflow-auto sm:max-w-4xl">
          <DialogHeader>
            <DialogTitle>
              {dialog === 'hosts'
                ? 'Compare observed host infrastructure'
                : 'Compare recorded observations by date'}
            </DialogTitle>
            <DialogDescription>
              Uses the loaded, filtered graph. Similarity does not establish common control; missing
              observations do not establish absence.
            </DialogDescription>
          </DialogHeader>
          {dialog === 'hosts' && (
            <>
              <p className="text-sm">
                Select 2–12 IP or domain entities using the entity-list checkboxes or Shift/Ctrl on
                the graph, then open this comparison. Pairs are ranked by matching fingerprints,
                then matching ports and transports. Current service properties can differ in
                observation time.
              </p>
              {hostIds.length < 2 && (
                <p role="status">
                  Select at least two hosts to compare ({hostIds.length} selected).
                </p>
              )}
              {hostIds.length > 12 && (
                <p role="status">
                  Showing the first 12 selected hosts. Narrow the selection for the remaining hosts.
                </p>
              )}
              {comparisons.map((pair) => (
                <section
                  className="space-y-2 rounded border p-3 text-sm"
                  key={`${pair.left.id}-${pair.right.id}`}
                >
                  <h3 className="font-medium">
                    {pair.left.nodeLabel} ↔ {pair.right.nodeLabel}
                  </h3>
                  <p>
                    Shared ports/transports: {pair.sharedServices.join(', ') || 'None recorded'}
                  </p>
                  <p>Matching fingerprints: {pair.fingerprints.join('; ') || 'None recorded'}</p>
                  <details>
                    <summary className="cursor-pointer">
                      Differences to review ({pair.differences.length})
                    </summary>
                    <ul className="mt-2 max-h-60 space-y-2 overflow-auto">
                      {pair.differences.map((difference, index) => (
                        <li key={index} className="break-all">
                          {difference}
                        </li>
                      ))}
                    </ul>
                    {!pair.differences.length && <p>None in the comparable stored fields</p>}
                  </details>
                  <details>
                    <summary className="cursor-pointer">
                      Inspect service evidence and observation times ({pair.evidence.length})
                    </summary>
                    <ul className="mt-2 space-y-2">
                      {pair.evidence.map((entry) => (
                        <li key={`${entry.host}-${entry.nodeId}`}>
                          <Button size="sm" variant="link" onClick={() => inspect(entry.nodeId)}>
                            {entry.host}: {entry.service}
                          </Button>
                          {entry.observations.map((observation, index) => (
                            <div key={index} className="pl-3 text-xs text-muted-foreground">
                              {observation.provider || 'Provider unknown'} · observed{' '}
                              {observation.observed_at || 'unknown'} · retrieved{' '}
                              {observation.retrieved_at || 'unknown'}
                            </div>
                          ))}
                        </li>
                      ))}
                    </ul>
                  </details>
                </section>
              ))}
            </>
          )}
          {dialog === 'changes' && (
            <>
              <div className="flex gap-4">
                <label className="space-y-1 text-sm">
                  Earlier observed date
                  <Input
                    type="date"
                    value={from}
                    onChange={(event) => setBefore(event.target.value)}
                  />
                </label>
                <label className="space-y-1 text-sm">
                  Later observed date
                  <Input
                    type="date"
                    value={to}
                    onChange={(event) => setAfter(event.target.value)}
                  />
                </label>
              </div>
              <p className="text-xs text-muted-foreground">
                Available dates: {dates.join(', ') || 'No dated observations'}. Compares the latest
                observation per relationship/provider/enricher on each exact UTC date. Historical
                entity properties are not reconstructed.
              </p>
              {!from || !to || from >= to ? (
                <p role="status">Choose two different dates with the earlier date first.</p>
              ) : (
                changes && (
                  <>
                    <p className="text-sm">
                      {changes.beforeCount} observations on {from}; {changes.afterCount} on {to}.{' '}
                      {changes.undated} records excluded (missing or invalid date/timezone).
                    </p>
                    {[
                      ['Newly observed on later date', changes.added],
                      ['Previously observed; not re-observed on later date', changes.notReobserved],
                      ['Changed evidence payload', changes.changed],
                      ['Different provider evidence on later date — review', changes.disagreements]
                    ].map(([title, rows]) => {
                      const items = rows as ((typeof changes.added)[number] & {
                        previous?: EvidenceObservation
                      })[]
                      return (
                        <section key={String(title)} className="rounded border p-3">
                          <h3 className="text-sm font-medium">
                            {String(title)} ({items.length})
                          </h3>
                          <ul className="mt-2 space-y-2 text-sm">
                            {items.slice(0, 200).map(({ edge, observation, previous }, index) => (
                              <li key={`${edge.id}-${index}`}>
                                <button
                                  className="text-primary underline"
                                  onClick={() => inspect(edge.source)}
                                >
                                  {labels.get(edge.source) || edge.source}
                                </button>{' '}
                                → {edge.caption || edge.label} →{' '}
                                <button
                                  className="text-primary underline"
                                  onClick={() => inspect(edge.target)}
                                >
                                  {labels.get(edge.target) || edge.target}
                                </button>
                                <span className="block text-xs text-muted-foreground">
                                  {observation.provider || 'Provider unknown'} ·{' '}
                                  {observation.observed_at}
                                </span>
                                {observation.evidence != null && (
                                  <details>
                                    <summary className="cursor-pointer text-xs">
                                      Recorded evidence
                                    </summary>
                                    <pre className="overflow-auto whitespace-pre-wrap break-all text-xs">
                                      {JSON.stringify(
                                        previous
                                          ? {
                                              earlier: previous.evidence,
                                              later: observation.evidence
                                            }
                                          : observation.evidence,
                                        null,
                                        2
                                      )}
                                    </pre>
                                  </details>
                                )}
                              </li>
                            ))}
                          </ul>
                          {items.length > 200 && (
                            <p className="text-xs">
                              Showing 200 of {items.length}; narrow the graph filters.
                            </p>
                          )}
                        </section>
                      )
                    })}
                  </>
                )
              )}
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}
