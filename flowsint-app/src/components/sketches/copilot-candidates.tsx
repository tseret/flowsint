import { useState } from 'react'
import {
  copilotService,
  type CopilotCandidate,
  type CopilotServiceEvidence
} from '@/api/copilot-service'
import { collaborationService, type CaseItem } from '@/api/collaboration-service'
import { sketchService } from '@/api/sketch-service'
import { Button } from '@/components/ui/button'
import { usePermissions } from '@/hooks/use-can'
import { ServiceInvestigation } from './service-investigation'

export function candidateFinding(sketchId: string, candidate: CopilotCandidate): Partial<CaseItem> {
  return {
    kind: 'finding',
    sketch_id: sketchId,
    target_kind: 'entity',
    target_id: candidate.node_id,
    body: `Related IP evidence review: ${candidate.label}. Association is supported by the cited existing graph paths and requires analyst review.`,
    evidence: JSON.stringify({ candidate_id: candidate.node_id, paths: candidate.evidence }),
    assessment:
      'Review of existing or imported graph evidence. No new provider queries or enrichment performed.'
  }
}

export function matchingCandidateFinding(
  items: CaseItem[],
  sketchId: string,
  candidate: CopilotCandidate
) {
  const evidence = candidateFinding(sketchId, candidate).evidence
  return items.find(
    (item) =>
      item.kind === 'finding' &&
      item.sketch_id === sketchId &&
      item.target_kind === 'entity' &&
      item.target_id === candidate.node_id &&
      item.evidence === evidence
  )
}

export function CopilotCandidates({
  sketchId,
  nodeIds,
  question
}: {
  sketchId: string
  nodeIds: string[]
  question: string
}) {
  const { canEdit } = usePermissions()
  const [result, setResult] = useState<{
    candidates: CopilotCandidate[]
    truncated: boolean
    services: CopilotServiceEvidence[]
    services_truncated: boolean
  } | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState<Record<string, CaseItem>>({})

  async function load() {
    setBusy('load')
    setError(null)
    setSaved({})
    setResult(null)
    try {
      const response = await copilotService.candidates({
        sketch_id: sketchId,
        node_ids: nodeIds,
        question: question.trim() || 'Review related IP evidence already in this graph.'
      })
      const sketch = await sketchService.getById(sketchId)
      const existing = await Promise.all(
        response.candidates.map(async (candidate) => {
          let offset = 0
          while (true) {
            const items = await collaborationService.items(sketch.investigation_id, offset, {
              sketch_id: sketchId,
              target_kind: 'entity',
              target_id: candidate.node_id
            })
            const match = matchingCandidateFinding(items, sketchId, candidate)
            if (match || items.length < 100) return match
            offset += items.length
          }
        })
      )
      setSaved(
        Object.fromEntries(
          existing.filter((item): item is CaseItem => !!item).map((item) => [item.target_id!, item])
        )
      )
      setResult(response)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to review related IP evidence')
    } finally {
      setBusy(null)
    }
  }

  async function record(candidate: CopilotCandidate, decision: CaseItem['decision']) {
    if (!canEdit || busy) return
    setBusy(candidate.node_id)
    setError(null)
    try {
      const sketch = await sketchService.getById(sketchId)
      const existing = saved[candidate.node_id]
      const item =
        existing ??
        (await collaborationService.create(
          sketch.investigation_id,
          candidateFinding(sketchId, candidate)
        ))
      if (!existing) {
        setSaved((previous) => ({ ...previous, [candidate.node_id]: item }))
      }
      if (item.decision !== decision) {
        const updated = await collaborationService.update(sketch.investigation_id, item, {
          decision
        })
        setSaved((previous) => ({ ...previous, [candidate.node_id]: updated }))
      }
    } catch (e) {
      setError(
        e instanceof Error && 'status' in e && e.status === 409
          ? 'This review changed. Reload related IP evidence to retrieve its current decision and version.'
          : e instanceof Error
            ? e.message
            : 'Unable to record review decision'
      )
    } finally {
      setBusy(null)
    }
  }

  return (
    <section className="space-y-3 border-t pt-4">
      <Button variant="outline" onClick={load} disabled={!!busy}>
        {' '}
        {busy === 'load' ? 'Loading existing evidence…' : 'Review related IP evidence'}{' '}
      </Button>
      <p className="text-sm text-muted-foreground">
        Loading this review reads existing graph evidence. Service searches below query Modat only
        when you click Search Modat index. Shared evidence requires review before accepting.
      </p>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      {result?.truncated && (
        <p className="text-sm text-amber-600">
          Evidence was limited to 20 candidate IPs and 5 paths per IP; observation details may have
          been shortened or omitted. Other associations may exist.
        </p>
      )}
      {result && result.candidates.length === 0 && (
        <p className="text-sm">
          No existing related-IP paths found. This does not rule out unqueried fingerprint leads.
        </p>
      )}
      {result && result.services.length === 0 && (
        <p className="text-sm text-muted-foreground">
          No stored service fingerprints were found. Older Modat port records omitted them;
          refreshing the selected IP’s passive service enrichment can retain them now.
        </p>
      )}
      {result && result.services.length > 0 && (
        <div className="space-y-3">
          <h3 className="font-medium">Recorded service fingerprint leads</h3>
          <p className="text-sm text-muted-foreground">
            Choose a recorded fingerprint below to search the provider index. Matching fingerprints
            can reflect common software or configuration and do not establish common control.
          </p>
          {result.services.map((service) => (
            <ServiceInvestigation
              key={`${service.source_id}-${service.service_id}-${service.service_version}`}
              sketchId={sketchId}
              service={service}
            />
          ))}
        </div>
      )}
      {result?.services_truncated && (
        <p className="text-sm text-amber-600">
          Service evidence was truncated; other fingerprint leads may exist.
        </p>
      )}
      {result?.candidates.map((candidate) => (
        <article key={candidate.node_id} className="rounded border p-3 text-sm space-y-3">
          <h3 className="font-medium break-all">{candidate.label}</h3>
          <p className="text-muted-foreground break-all">Entity: {candidate.node_id}</p>
          {candidate.evidence.map((path, index) => (
            <div
              key={`${path.source_id}-${path.evidence_id}-${index}`}
              className="space-y-2 rounded bg-muted/40 p-2"
            >
              <p className="break-all">
                {path.source_label} → {path.evidence_label} → {candidate.label}
              </p>
              <p className="break-all">Relationships: {path.relationships.join(' · ')}</p>
              <p className="text-muted-foreground break-all">
                Source entity: {path.source_id} · Evidence entity: {path.evidence_id}
              </p>
              {path.observations.length === 0 && (
                <p className="text-muted-foreground">
                  No dated observations recorded for this path.
                </p>
              )}
              {path.observations.map((observation, observationIndex) => (
                <pre key={observationIndex} className="whitespace-pre-wrap break-all text-xs">
                  {JSON.stringify(observation, null, 2)}
                </pre>
              ))}
            </div>
          ))}
          <p aria-live="polite">
            {saved[candidate.node_id]
              ? `Saved review: ${saved[candidate.node_id].decision}`
              : 'Review not yet recorded'}
          </p>
          {canEdit && (
            <div className="flex flex-wrap gap-2">
              {(['pending', 'accepted', 'rejected'] as const).map((decision) => (
                <Button
                  key={decision}
                  variant="outline"
                  size="sm"
                  disabled={!!busy || saved[candidate.node_id]?.decision === decision}
                  onClick={() => record(candidate, decision)}
                >
                  {decision === 'pending'
                    ? 'Pending review'
                    : decision === 'accepted'
                      ? 'Accept association'
                      : 'Reject association'}
                </Button>
              ))}
            </div>
          )}
        </article>
      ))}
    </section>
  )
}
