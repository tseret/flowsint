import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { Sparkles, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { copilotService } from '@/api/copilot-service'
import { useConfirm } from '@/components/use-confirm-dialog'
import { chatGPTSubscriptionService } from '@/api/chatgpt-subscription-service'
import { useGraphStore } from '@/stores/graph-store'
import { useGraphControls } from '@/stores/graph-controls-store'
import { usePermissions } from '@/hooks/use-can'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Input } from '@/components/ui/input'
import { MemoizedMarkdown } from '@/components/chat/memoized-markdown'
import { Badge } from '@/components/ui/badge'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription
} from '@/components/ui/sheet'
import { ToolbarButton } from './toolbar'
import { CopilotCandidates } from './copilot-candidates'

const ACTIVE = ['running', 'publishing']
const UNDOABLE = ['completed', 'failed', 'cancelled']

export function InvestigationCopilot({ sketchId }: { sketchId: string }) {
  const { canEdit } = usePermissions()
  const selected = useGraphStore((s) => s.selectedNodes)
  const queryClient = useQueryClient()
  const { confirm } = useConfirm()
  const refetchGraph = useGraphControls((s) => s.refetchGraph)
  const [open, setOpen] = useState(false)
  const [objective, setObjective] = useState('')
  const [maxSteps, setMaxSteps] = useState(20)
  const nodes = useGraphStore((s) => s.nodesMapping)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const connection = useQuery({
    queryKey: ['chatgpt-subscription', 'status'],
    queryFn: chatGPTSubscriptionService.status,
    enabled: open
  })
  const latestKey = ['copilot', 'agent', 'latest', sketchId]
  const latest = useQuery({
    queryKey: latestKey,
    queryFn: () => copilotService.latestAgentRun(sketchId),
    enabled: open
  })
  const runId = latest.data?.id ?? null
  const runQuery = useQuery({
    queryKey: ['copilot', 'agent', runId],
    queryFn: () => copilotService.getAgentRun(runId!),
    enabled: open && !!runId,
    initialData: latest.data ?? undefined,
    refetchInterval: (query) => (ACTIVE.includes(query.state.data?.status ?? '') ? 2000 : false)
  })
  const run = runQuery.data
  const active = !!run && ACTIVE.includes(run.status)
  const ids = selected.map((node) => String(node.id))
  const ipsOnly =
    selected.length > 0 &&
    selected.length <= 10 &&
    selected.every((node) => node.nodeType.toLowerCase() === 'ip')
  const subscribed = connection.data?.mode === 'subscription' && connection.data.connected

  useEffect(() => {
    if (run?.status === 'completed' && run.finding_ids.length) {
      void queryClient.invalidateQueries({ queryKey: ['case-workspace'] })
    }
  }, [run?.status, run?.finding_ids.length, queryClient])

  // Each finished step may add entities; show them on the canvas and in step labels.
  // Steps are saved as 'running' before their scan ends; refresh once each finishes.
  const finishedSteps = run?.steps.filter((step) => step.outcome !== 'running').length ?? 0
  useEffect(() => {
    if (finishedSteps) refetchGraph()
  }, [run?.id, finishedSteps, refetchGraph])

  async function start() {
    setBusy(true)
    setError(null)
    try {
      const created = await copilotService.startAgent({
        sketch_id: sketchId,
        node_ids: ids,
        objective: objective.trim(),
        max_steps: maxSteps
      })
      queryClient.setQueryData(['copilot', 'agent', created.id], created)
      queryClient.setQueryData(latestKey, created)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to start the agent')
    } finally {
      setBusy(false)
    }
  }

  async function cancel() {
    if (!run) return
    setBusy(true)
    try {
      queryClient.setQueryData(
        ['copilot', 'agent', run.id],
        await copilotService.cancelAgent(run.id)
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to cancel the agent')
    } finally {
      setBusy(false)
    }
  }

  async function undo() {
    if (!run) return
    if (
      !(await confirm({
        title: 'Undo this agent run?',
        message:
          'Removes the entities and relationships its enrichments created, and its draft findings nobody has edited or reviewed.'
      }))
    )
      return
    setBusy(true)
    setError(null)
    try {
      const { removed, ...undone } = await copilotService.undoAgent(run.id)
      queryClient.setQueryData(['copilot', 'agent', run.id], undone)
      void queryClient.invalidateQueries({ queryKey: ['case-workspace'] })
      refetchGraph()
      toast.success(
        `Removed ${removed.nodes} entities, ${removed.relationships} relationships and ${removed.findings} draft findings.`
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to undo the agent run')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <ToolbarButton
        icon={<Sparkles className="h-4 w-4 opacity-70" />}
        tooltip="Investigate selected entities"
        onClick={() => setOpen(true)}
      />
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent className="w-full sm:max-w-xl overflow-y-auto">
          <SheetHeader>
            <SheetTitle>Investigation agent</SheetTitle>
            <SheetDescription>
              The agent chooses passive enrichments step by step to answer your objective, then
              writes a cited report and draft findings for your review. It never contacts target
              infrastructure directly.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-6 space-y-4">
            {!active && (
              <>
                <p className="text-sm">{selected.length} entities selected (1 to 10).</p>
                <ul className="text-sm list-disc pl-4 break-all">
                  {selected.map((node) => (
                    <li key={node.id}>{node.nodeLabel}</li>
                  ))}
                </ul>
                <label className="block text-sm space-y-2">
                  Objective
                  <Textarea
                    value={objective}
                    maxLength={2000}
                    disabled={busy}
                    placeholder="Map the infrastructure and exposure of this domain"
                    onChange={(e) => setObjective(e.target.value)}
                  />
                </label>
                <label className="block text-sm space-y-2">
                  Maximum steps
                  <Input
                    type="number"
                    min={1}
                    max={50}
                    value={maxSteps}
                    disabled={busy}
                    onChange={(e) => setMaxSteps(Math.min(50, Math.max(1, Number(e.target.value))))}
                  />
                </label>
                <Button
                  onClick={start}
                  disabled={
                    !canEdit ||
                    busy ||
                    !subscribed ||
                    !objective.trim() ||
                    selected.length < 1 ||
                    selected.length > 10
                  }
                >
                  {busy && <Loader2 className="h-4 w-4 animate-spin" />} Run agent
                </Button>
              </>
            )}
            <p className="text-sm text-muted-foreground">
              {connection.data?.mode === 'subscription'
                ? `ChatGPT subscription · ${connection.data.model} · ${connection.data.reasoning_effort} effort${connection.data.connected ? '' : ' · connection required'}`
                : connection.data
                  ? 'The agent requires ChatGPT subscription mode.'
                  : 'Loading connection…'}{' '}
              <Link to="/dashboard/profile" className="underline">
                Manage connection
              </Link>
            </p>
            {[error, connection.error?.message, latest.error?.message, runQuery.error?.message]
              .filter(Boolean)
              .map((message) => (
                <p key={message} role="alert" className="text-sm text-destructive">
                  {message}
                </p>
              ))}
            {!active && ipsOnly && (
              <CopilotCandidates
                key={JSON.stringify([sketchId, [...ids].sort()])}
                sketchId={sketchId}
                nodeIds={ids}
                question={objective}
              />
            )}
            {run && (
              <section className="space-y-3 border-t pt-4" aria-live="polite">
                <h3 className="font-medium">Objective</h3>
                <p className="text-sm whitespace-pre-wrap">{run.objective}</p>
                <p className="text-sm">
                  {run.status === 'running' && !run.started_at
                    ? 'Waiting for an agent worker. The run starts when one is available.'
                    : run.status === 'running'
                      ? `Running · step ${run.steps.length} of ${run.max_steps}`
                      : run.status === 'publishing'
                        ? 'Writing the report and draft findings…'
                        : `Agent ${run.status} after ${run.steps.length} steps`}
                </p>
                {run.status === 'running' && (
                  <Button variant="outline" size="sm" onClick={cancel} disabled={!canEdit || busy}>
                    Cancel
                  </Button>
                )}
                {UNDOABLE.includes(run.status) && (
                  <Button variant="outline" size="sm" onClick={undo} disabled={!canEdit || busy}>
                    Undo run
                  </Button>
                )}
                {run.error && (
                  <p role="alert" className="text-sm text-destructive">
                    {run.error}
                  </p>
                )}
                {run.steps.map((step) => (
                  <div key={step.step} className="rounded border p-3 space-y-1 text-sm">
                    <p className="font-medium break-all">
                      {step.step}. {step.enricher} <Badge variant="outline">{step.outcome}</Badge>
                      {step.output_count !== undefined && ` ${step.output_count} results`}
                    </p>
                    <p>{step.reason}</p>
                    <ul className="list-disc pl-4 break-all text-muted-foreground">
                      {step.node_ids.map((id) => (
                        <li key={id}>{nodes.get(id)?.nodeLabel ?? id}</li>
                      ))}
                    </ul>
                    {step.errors?.map((issue, index) => (
                      <p key={index} className="text-destructive break-all">
                        {issue.message}
                      </p>
                    ))}
                  </div>
                ))}
                {run.report && (
                  <div className="text-sm prose prose-sm dark:prose-invert max-w-none">
                    <MemoizedMarkdown content={run.report} id={run.id} />
                  </div>
                )}
                {run.status === 'completed' && (
                  <p className="text-sm">
                    {run.finding_ids.length} draft findings added to the case for review.
                  </p>
                )}
              </section>
            )}
          </div>
        </SheetContent>
      </Sheet>
    </>
  )
}
