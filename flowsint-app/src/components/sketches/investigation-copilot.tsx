import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { Sparkles, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import {
  copilotService,
  matchesPlan,
  isRunComplete,
  pollCopilotRun,
  externalCallCount,
  providerName,
  type CopilotStep,
  type CopilotPlan,
  type CopilotRun,
  type CopilotSummary
} from '@/api/copilot-service'
import { sketchService } from '@/api/sketch-service'
import { chatGPTSubscriptionService } from '@/api/chatgpt-subscription-service'
import { collaborationService } from '@/api/collaboration-service'
import { queryKeys } from '@/api/query-keys'
import { useGraphStore } from '@/stores/graph-store'
import { useGraphControls } from '@/stores/graph-controls-store'
import { usePermissions } from '@/hooks/use-can'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Input } from '@/components/ui/input'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription
} from '@/components/ui/sheet'
import { ToolbarButton } from './toolbar'
import { CopilotCandidates } from './copilot-candidates'

export function InvestigationCopilot({ sketchId }: { sketchId: string }) {
  const { canEdit } = usePermissions()
  const selected = useGraphStore((s) => s.selectedNodes)
  const refetchGraph = useGraphControls((s) => s.refetchGraph)
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const connection = useQuery({
    queryKey: ['chatgpt-subscription', 'status'],
    queryFn: chatGPTSubscriptionService.status,
    enabled: open
  })
  const [question, setQuestion] = useState('')
  const [plan, setPlan] = useState<CopilotPlan | null>(null)
  const [runs, setRuns] = useState<CopilotRun[]>([])
  const [summary, setSummary] = useState<CopilotSummary | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [flowName, setFlowName] = useState('')
  const [flowId, setFlowId] = useState<string | null>(null)
  const [findingSaved, setFindingSaved] = useState(false)
  const [labels, setLabels] = useState<Record<string, string>>({})
  const [skipped, setSkipped] = useState<CopilotStep[]>([])
  const [planIPs, setPlanIPs] = useState(false)
  const [pollUntil, setPollUntil] = useState(0)
  const summaryRequested = useRef(false)
  const ids = selected.map((node) => String(node.id))
  const ipsOnly =
    selected.length > 0 &&
    selected.length <= 10 &&
    selected.every((node) => node.nodeType.toLowerCase() === 'ip')
  const valid = !!plan && matchesPlan(plan, sketchId, ids, question)
  const scans = useQuery({
    queryKey: ['copilot', 'runs', runs.map((run) => run.id)],
    queryFn: () => Promise.all(runs.map((run) => pollCopilotRun(run.id))),
    enabled: runs.length > 0,
    retry: false,
    refetchInterval: (query) =>
      Date.now() < pollUntil &&
      !query.state.error &&
      !query.state.data?.every((scan) => isRunComplete(scan.status))
        ? 2000
        : false
  })
  const complete = runs.length > 0 && !!scans.data?.every((scan) => isRunComplete(scan.status))

  async function summarize() {
    if (!plan) return
    setBusy('summary')
    setError(null)
    try {
      setSummary(
        await copilotService.summary({
          sketch_id: plan.sketch_id,
          run_ids: runs.map((run) => run.id),
          question: plan.question
        })
      )
      refetchGraph()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to summarize results')
    } finally {
      setBusy(null)
    }
  }

  useEffect(() => {
    if (complete && !summaryRequested.current) {
      summaryRequested.current = true
      void summarize()
    }
    // Summarize each reviewed execution once; retries are explicit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [complete])

  async function propose() {
    setBusy('plan')
    setError(null)
    setPlan(null)
    setRuns([])
    setSummary(null)
    setFlowId(null)
    setFindingSaved(false)
    setSkipped([])
    setPlanIPs(ipsOnly)
    setLabels(Object.fromEntries(selected.map((node) => [String(node.id), node.nodeLabel])))
    summaryRequested.current = false
    try {
      setPlan(
        await copilotService.plan({ sketch_id: sketchId, node_ids: ids, question: question.trim() })
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to suggest a plan')
    } finally {
      setBusy(null)
    }
  }

  async function collect() {
    if (!canEdit || !ipsOnly || busy || runs.length > 0) return
    const collectionQuestion =
      question.trim() || 'Gather passive IP intelligence and summarize the supporting evidence.'
    setQuestion(collectionQuestion)
    setBusy('collect')
    setError(null)
    setPlan(null)
    setRuns([])
    setSummary(null)
    setFlowId(null)
    setFindingSaved(false)
    setSkipped([])
    setPlanIPs(true)
    setLabels(Object.fromEntries(selected.map((node) => [String(node.id), node.nodeLabel])))
    summaryRequested.current = false
    try {
      const response = await copilotService.collect({
        sketch_id: sketchId,
        node_ids: ids,
        question: collectionQuestion
      })
      setPlan(response.plan)
      setRuns(response.runs)
      setSkipped(response.skipped)
      if (response.error) setError(response.error)
      setPollUntil(Date.now() + 10 * 60 * 1000)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to gather IP intelligence')
    } finally {
      setBusy(null)
    }
  }

  async function run() {
    if (!plan || !valid || !canEdit) return
    setBusy('run')
    setError(null)
    try {
      const response = await copilotService.run(plan)
      setRuns(response.runs)
      if (response.error) setError(response.error)
      setPollUntil(Date.now() + 10 * 60 * 1000)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to run the reviewed plan')
    } finally {
      setBusy(null)
    }
  }

  async function save() {
    if (!plan || (!valid && runs.length === 0) || !canEdit) return
    setBusy('save')
    setError(null)
    try {
      const flow = await copilotService.save({ ...plan, name: flowName.trim() })
      setFlowId(flow.id)
      await queryClient.invalidateQueries({ queryKey: queryKeys.flows.list })
      toast.success('Reviewed plan saved as a flow')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to save flow')
    } finally {
      setBusy(null)
    }
  }

  async function saveFinding() {
    if (!plan || !summary || !canEdit) return
    setBusy('finding')
    setError(null)
    try {
      const sketch = await sketchService.getById(plan.sketch_id)
      await collaborationService.create(sketch.investigation_id, {
        kind: 'finding',
        body: [
          summary.summary,
          ...skipped.map(
            (step) =>
              `Collection gap: ${providerName(step.enricher)} ${step.enricher} skipped; missing ${step.missing_keys.join(', ')}.`
          )
        ].join('\n'),
        sketch_id: plan.sketch_id,
        evidence: summary.evidence.map((item) => `Run ${item.run_id}: ${item.status}`).join('\n'),
        assessment: 'Copilot draft. Review the cited run evidence before accepting.',
        status: 'open',
        decision: 'pending'
      })
      setFindingSaved(true)
      toast.success('Draft finding added to the case for review')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to save draft finding')
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      <ToolbarButton
        icon={<Sparkles className="h-4 w-4 opacity-70" />}
        tooltip="Investigate selected entities"
        disabled={runs.length === 0 && (selected.length < 1 || selected.length > 10)}
        onClick={() => setOpen(true)}
      />
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent className="w-full sm:max-w-xl overflow-y-auto">
          <SheetHeader>
            <SheetTitle>Investigate selected entities</SheetTitle>
            <SheetDescription>
              Gather passive intelligence on selected IPs for final review, or review an enrichment
              plan before running it.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-6 space-y-4">
            <p className="text-sm">
              {runs.length > 0 ? plan?.node_ids.length : selected.length} entities{' '}
              {runs.length > 0 ? 'in reviewed scope' : 'selected'} (maximum 10).
            </p>
            <ul className="text-sm list-disc pl-4 break-all">
              {(runs.length > 0 && plan
                ? plan.node_ids.map((id) => ({ id, label: labels[id] ?? id }))
                : selected.map((node) => ({ id: String(node.id), label: node.nodeLabel }))
              ).map((node) => (
                <li key={node.id}>{node.label}</li>
              ))}
            </ul>
            <label className="block text-sm space-y-2">
              Investigation question
              <Textarea
                value={question}
                maxLength={2000}
                disabled={!!busy || runs.length > 0}
                placeholder="What evidence can we gather about these entities?"
                onChange={(e) => {
                  setQuestion(e.target.value)
                  setFlowId(null)
                }}
              />
            </label>
            {runs.length === 0 && (
              <div className="space-y-2">
                <Button onClick={collect} disabled={!canEdit || !!busy || !ipsOnly}>
                  {busy === 'collect' && <Loader2 className="h-4 w-4 animate-spin" />} Gather IP
                  intelligence
                </Button>
                <p className="text-sm text-muted-foreground">
                  Runs configured passive lookups on up to 10 selected IPs, then summarizes evidence
                  for your review. Up to {ipsOnly ? selected.length * 6 : 60} external calls across
                  Shodan, Modat, VirusTotal and ThreatFox. Missing credentials are skipped; newly
                  discovered entities are never followed automatically.
                </p>
                <Button
                  variant="outline"
                  onClick={propose}
                  disabled={
                    !!busy || !question.trim() || selected.length < 1 || selected.length > 10
                  }
                >
                  {busy === 'plan' && <Loader2 className="h-4 w-4 animate-spin" />} Suggest a plan
                  to review first
                </Button>
              </div>
            )}
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <p className="text-sm text-muted-foreground">
              {connection.data?.mode === 'subscription'
                ? `ChatGPT subscription · ${connection.data.model} · ${connection.data.reasoning_effort} effort${connection.data.connected ? '' : ' · connection required'}`
                : connection.data
                  ? 'API key · separate API billing'
                  : 'Loading connection…'}{' '}
              <Link to="/dashboard/profile" className="underline">
                Manage connection
              </Link>
            </p>
            {connection.error && (
              <p role="alert" className="text-sm text-destructive">
                {connection.error.message}
              </p>
            )}
            {(ipsOnly || (runs.length > 0 && plan && planIPs)) && (
              <CopilotCandidates
                key={JSON.stringify([
                  sketchId,
                  [...(runs.length > 0 && plan && planIPs ? plan.node_ids : ids)].sort()
                ])}
                sketchId={sketchId}
                nodeIds={runs.length > 0 && plan && planIPs ? plan.node_ids : ids}
                question={question}
              />
            )}
            {plan && (
              <>
                {!valid && runs.length === 0 && (
                  <p role="alert" className="text-sm text-amber-600">
                    Selection or question changed. Suggest a new plan before running or saving.
                  </p>
                )}
                <p className="text-sm whitespace-pre-wrap">{plan.analysis}</p>
                {plan.context_truncated && (
                  <p className="text-sm text-amber-600">
                    Context was limited. These suggestions may omit relevant evidence.
                  </p>
                )}
                <h3 className="font-medium">Review enrichment steps</h3>
                <p className="text-sm">
                  Maximum external lookup calls: {externalCallCount(plan.steps)}. VirusTotal domain
                  history is limited to two pages per IP; other provider lookups use one call per
                  entity. Root domain extraction runs locally. No automatic pivots or follow-up
                  enrichment.
                </p>
                {skipped.length > 0 && (
                  <section className="rounded border p-3 text-sm space-y-2">
                    <h3 className="font-medium">Skipped providers</h3>
                    {skipped.map((step, index) => (
                      <p key={`${step.enricher}-${index}`}>
                        {providerName(step.enricher)} · {step.enricher}:{' '}
                        {step.missing_keys.length
                          ? `Missing credentials: ${step.missing_keys.join(', ')}`
                          : step.reason}
                      </p>
                    ))}
                  </section>
                )}
                {plan.steps.length === 0 && (
                  <p className="text-sm">No compatible passive steps were suggested.</p>
                )}
                {plan.steps.map((step, index) => (
                  <div
                    key={`${step.enricher}-${index}`}
                    className="rounded border p-3 space-y-2 text-sm"
                  >
                    <p className="font-medium break-all">{step.enricher}</p>
                    <p>{step.reason}</p>
                    <p>{step.node_ids.length} selected entities · one run</p>
                    <p>Provider: {providerName(step.enricher)}</p>
                    <ul className="list-disc pl-4 break-all">
                      {step.node_ids.map((id) => (
                        <li key={id}>{labels[id] ?? id}</li>
                      ))}
                    </ul>
                    {step.missing_keys.length > 0 && (
                      <p className="text-amber-600">
                        Configure credentials before running: {step.missing_keys.join(', ')}
                      </p>
                    )}
                    {runs.length === 0 && (
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={!!busy}
                        onClick={() => {
                          setPlan({ ...plan, steps: plan.steps.filter((_, i) => i !== index) })
                          setFlowId(null)
                        }}
                      >
                        Remove step
                      </Button>
                    )}
                  </div>
                ))}
                {runs.length === 0 && (
                  <Button
                    onClick={run}
                    disabled={
                      !canEdit ||
                      !!busy ||
                      !valid ||
                      !plan.steps.length ||
                      plan.steps.some((step) => step.missing_keys.length > 0)
                    }
                  >
                    {busy === 'run' && <Loader2 className="h-4 w-4 animate-spin" />} Run reviewed
                    plan
                  </Button>
                )}
                {runs.length > 0 && (
                  <div className="space-y-2 text-sm" aria-live="polite">
                    <h3 className="font-medium">Enrichment runs</h3>
                    {runs.map((run) => (
                      <p key={run.id} className="break-all">
                        {run.enricher}:{' '}
                        {scans.data?.find((scan) => scan.id === run.id)?.status ??
                          'Queued; waiting for worker'}{' '}
                        <span className="text-muted-foreground">({run.id})</span>
                      </p>
                    ))}
                    {!complete && (
                      <p>
                        Queued runs may wait for a worker. Status is checked for up to 10 minutes;
                        refresh to continue checking.
                      </p>
                    )}
                    {scans.error && (
                      <p role="alert" className="text-destructive">
                        Could not check run status: {scans.error.message}
                      </p>
                    )}
                    {!complete && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setPollUntil(Date.now() + 10 * 60 * 1000)
                          void scans.refetch()
                        }}
                      >
                        Refresh run status
                      </Button>
                    )}
                    {complete && !summary && (
                      <Button onClick={summarize} disabled={!!busy}>
                        {busy === 'summary' ? 'Summarizing…' : 'Summarize results'}
                      </Button>
                    )}
                  </div>
                )}
                {summary && (
                  <section className="space-y-2">
                    <h3 className="font-medium">Results and evidence</h3>
                    <p className="text-sm whitespace-pre-wrap">{summary.summary}</p>
                    {summary.context_truncated && (
                      <p className="text-sm text-amber-600">
                        Summary context was limited; inspect individual run evidence.
                      </p>
                    )}
                    {summary.evidence.map((item) => (
                      <details key={item.run_id} className="text-sm rounded border p-2">
                        <summary className="cursor-pointer break-all">
                          Run {item.run_id} · {item.status}
                        </summary>
                        <pre className="whitespace-pre-wrap break-all mt-2">
                          {JSON.stringify(
                            {
                              summary: item.summary,
                              details: item.details,
                              relationships: item.relationships,
                              relationships_truncated: item.relationships_truncated
                            },
                            null,
                            2
                          )}
                        </pre>
                      </details>
                    ))}
                    <Button
                      variant="outline"
                      onClick={() => {
                        refetchGraph()
                        setOpen(false)
                      }}
                    >
                      Review updated graph
                    </Button>
                    <Button
                      variant="outline"
                      onClick={saveFinding}
                      disabled={!canEdit || !!busy || findingSaved}
                    >
                      {findingSaved ? 'Draft finding saved' : 'Save summary as draft finding'}
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => {
                        setPlan(null)
                        setRuns([])
                        setSummary(null)
                        setError(null)
                        setFindingSaved(false)
                        setSkipped([])
                        summaryRequested.current = false
                      }}
                    >
                      Start another investigation
                    </Button>
                  </section>
                )}
                <div className="space-y-2 border-t pt-4">
                  <label className="block text-sm">
                    Flow name
                    <Input
                      value={flowName}
                      maxLength={120}
                      onChange={(e) => setFlowName(e.target.value)}
                      placeholder="Reusable passive investigation"
                    />
                  </label>
                  <Button
                    variant="outline"
                    onClick={save}
                    disabled={
                      !canEdit ||
                      !!busy ||
                      (!valid && runs.length === 0) ||
                      !plan.steps.length ||
                      !flowName.trim()
                    }
                  >
                    Save reviewed plan as flow
                  </Button>
                  {flowId && (
                    <p className="text-sm">
                      <Link to="/dashboard/flows/$flowId" params={{ flowId }} className="underline">
                        Open saved flow
                      </Link>
                    </p>
                  )}
                </div>
              </>
            )}
          </div>
        </SheetContent>
      </Sheet>
    </>
  )
}
