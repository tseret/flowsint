import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  copilotService,
  type CopilotServiceEvidence,
  type FingerprintMatch,
  type FingerprintResult
} from '@/api/copilot-service'
import { collaborationService, type CaseItem } from '@/api/collaboration-service'
import { sketchService } from '@/api/sketch-service'
import { usePermissions } from '@/hooks/use-can'
import { Button } from '@/components/ui/button'

export function fingerprintFinding(
  sketchId: string,
  result: FingerprintResult,
  candidate: FingerprintMatch
): Partial<CaseItem> {
  const service = result.service
  const sourceFingerprints = Object.fromEntries(
    Object.keys(candidate.fingerprints)
      .filter((name) => typeof service.fingerprints[name] === 'string')
      .map((name) => [name, service.fingerprints[name]])
  )
  let detailLimit = 2048
  let evidence: string
  do {
    let truncated =
      result.truncated ||
      Object.keys(service.fingerprints).length !== Object.keys(sourceFingerprints).length
    const detail = (value: string, limit: number) => {
      const cap = Math.min(limit, detailLimit)
      if (value.length > cap) truncated = true
      return value.slice(0, cap)
    }
    const source = {
      source_id: service.source_id,
      service_id: service.service_id,
      service_version: service.service_version,
      host: service.host,
      port: service.port,
      transport: service.transport,
      service: service.service,
      source_label: detail(service.source_label, 256),
      provider: detail(service.provider, 128),
      observed_at: detail(service.observed_at, 128),
      retrieved_at: detail(service.retrieved_at, 128),
      source_ref: detail(service.source_ref, 1024),
      banner: detail(service.banner, 2048),
      fingerprints: sourceFingerprints
    }
    const candidateEvidence = {
      ...candidate,
      observed_at: detail(candidate.observed_at, 128),
      source_ref: detail(candidate.source_ref, 1024),
      banner: detail(candidate.banner, 2048)
    }
    evidence = JSON.stringify({
      query: result.query,
      source,
      candidate: candidateEvidence,
      matching_fingerprints: candidate.matching_fingerprints,
      retrieved_at: result.retrieved_at,
      evidence_truncated: truncated
    })
    if (evidence.length <= 20000) break
    // Reduce descriptive details; exact query, endpoint IDs and hash comparisons stay intact.
    if (detailLimit === 0)
      throw new Error(
        'Fingerprint support exceeds the finding evidence limit. Review the source records before saving.'
      )
    detailLimit = Math.floor(detailLimit / 2)
  } while (evidence.length > 20000)
  return {
    kind: 'finding',
    sketch_id: sketchId,
    target_kind: 'entity',
    target_id: result.service.service_id,
    body: `Unverified indexed fingerprint candidate: ${candidate.ip}:${candidate.port ?? '?'} (${candidate.transport}). Review the recorded hash comparison and provider evidence before drawing an association.`,
    evidence,
    assessment:
      'Human-triggered passive Modat indexed lookup. Fingerprint similarity can reflect common software or configuration and does not establish common control. No candidate probing, enrichment or graph insertion performed.'
  }
}

export function matchingFingerprintFinding(items: CaseItem[], finding: Partial<CaseItem>) {
  return items.find(
    (item) =>
      item.kind === 'finding' &&
      item.sketch_id === finding.sketch_id &&
      item.target_kind === 'entity' &&
      item.target_id === finding.target_id &&
      item.evidence === finding.evidence
  )
}

export function ServiceInvestigation({
  sketchId,
  service
}: {
  sketchId: string
  service: CopilotServiceEvidence
}) {
  const { canEdit } = usePermissions()
  const keys = Object.keys(service.modat_queries ?? {})
  const [fingerprint, setFingerprint] = useState('')
  const chosen = keys.includes(fingerprint)
    ? fingerprint
    : (keys.find((key) => /hassh/i.test(key)) ?? keys[0] ?? '')
  const [result, setResult] = useState<FingerprintResult | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState<Record<string, CaseItem>>({})

  async function lookup() {
    if (!canEdit || busy || !chosen || !service.modat_queries[chosen]) return
    setBusy('lookup')
    setError(null)
    setResult(null)
    setSaved({})
    try {
      setResult(
        await copilotService.fingerprint({
          sketch_id: sketchId,
          service_id: service.service_id,
          service_version: service.service_version,
          fingerprint: chosen
        })
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to run indexed fingerprint lookup')
    } finally {
      setBusy(null)
    }
  }

  async function save(candidate: FingerprintMatch) {
    if (!canEdit || busy || !result) return
    const finding = fingerprintFinding(sketchId, result, candidate)
    const evidence = finding.evidence!
    if (saved[evidence]) return
    setBusy(evidence)
    setError(null)
    try {
      const sketch = await sketchService.getById(sketchId)
      let offset = 0
      let existing: CaseItem | undefined
      while (true) {
        const items = await collaborationService.items(sketch.investigation_id, offset, {
          sketch_id: sketchId,
          target_kind: 'entity',
          target_id: result.service.service_id
        })
        existing = matchingFingerprintFinding(items, finding)
        if (existing || items.length < 100) break
        offset += items.length
      }
      const item = existing ?? (await collaborationService.create(sketch.investigation_id, finding))
      setSaved((previous) => ({ ...previous, [evidence]: item }))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to save pending candidate finding')
    } finally {
      setBusy(null)
    }
  }

  return (
    <section className="rounded border p-3 text-sm space-y-3">
      <h3 className="font-medium break-all">
        {service.host || service.source_label}:{service.port ?? '?'} / {service.transport || '?'} ·{' '}
        {service.service || 'Protocol not recorded'}
      </h3>
      <p>
        Provider: {service.provider || 'Not recorded'} · Observed:{' '}
        {service.observed_at || 'Not recorded'} · Retrieved:{' '}
        {service.retrieved_at || 'Not recorded'}
      </p>
      <p className="break-all">Source: {service.source_ref || 'Not recorded'}</p>
      <p className="text-muted-foreground break-all">Service entity: {service.service_id}</p>
      <details>
        <summary className="cursor-pointer">Recorded banner</summary>
        <pre className="whitespace-pre-wrap break-all mt-2">
          {service.banner || 'No banner recorded'}
        </pre>
      </details>
      <dl className="space-y-1">
        {Object.entries(service.fingerprints).map(([name, hash]) => (
          <div key={name} className="break-all">
            <dt className="font-medium">{name}</dt>
            <dd>{typeof hash === 'string' ? hash : JSON.stringify(hash)}</dd>
          </div>
        ))}
      </dl>
      {keys.length === 0 ? (
        <p className="text-muted-foreground">
          No supported Modat indexed fingerprint query is available for this recorded service.
        </p>
      ) : (
        <>
          <label className="block space-y-1">
            Fingerprint for indexed lookup
            <select
              className="block w-full rounded border bg-background p-2"
              value={chosen}
              disabled={!!busy}
              onChange={(e) => setFingerprint(e.target.value)}
            >
              {keys.map((key) => (
                <option key={key} value={key}>
                  {key}
                </option>
              ))}
            </select>
          </label>
          <p className="font-medium">Exact Modat query</p>
          <pre className="whitespace-pre-wrap break-all rounded bg-muted/40 p-2">
            {service.modat_queries[chosen]}
          </pre>
          <p className="text-muted-foreground">
            One passive indexed lookup, only when you click. No LLM, network probing, follow-up
            candidate queries or automatic new graph nodes.
          </p>
          <Button variant="outline" onClick={lookup} disabled={!canEdit || !!busy}>
            {busy === 'lookup' ? 'Searching Modat index…' : 'Search Modat index'}
          </Button>
        </>
      )}
      {error && (
        <p role="alert" className="text-destructive">
          {error}
        </p>
      )}
      {result && (
        <div className="space-y-3">
          <h4 className="font-medium">Unverified indexed candidates</h4>
          <p className="break-all">
            Query: {result.query} · Retrieved: {result.retrieved_at} · Records reported:{' '}
            {result.total_records ?? 'Unknown'}
          </p>
          <p className="text-muted-foreground">
            Matching fingerprints may reflect common software or configuration. They do not
            establish common control.
          </p>
          {result.truncated && (
            <p className="text-amber-600">
              Results or observation details were shortened. Other indexed records may exist.
            </p>
          )}
          {result.matches.length === 0 && <p>No indexed matching records returned.</p>}
          {result.matches.map((candidate, index) => {
            const evidence = fingerprintFinding(sketchId, result, candidate).evidence!
            return (
              <article
                key={`${candidate.ip}-${candidate.port}-${index}`}
                className="rounded border p-2 space-y-2"
              >
                <h5 className="font-medium break-all">
                  {candidate.ip}:{candidate.port ?? '?'} / {candidate.transport} ·{' '}
                  {candidate.protocol}
                </h5>
                <p>Observed: {candidate.observed_at || 'Not recorded'}</p>
                <p className="break-all">Source: {candidate.source_ref || 'Not recorded'}</p>
                <p>
                  Matching fingerprints:{' '}
                  {candidate.matching_fingerprints.join(', ') || 'None verified'}
                </p>
                <dl>
                  {Object.entries(candidate.fingerprints).map(([name, value]) => (
                    <div key={name} className="break-all">
                      <dt>{name}</dt>
                      <dd>
                        Recorded source:{' '}
                        {String(result.service.fingerprints[name] ?? 'Not recorded')}
                        <br />
                        Candidate: {value}
                      </dd>
                    </div>
                  ))}
                </dl>
                <details>
                  <summary className="cursor-pointer">Candidate banner</summary>
                  <pre className="whitespace-pre-wrap break-all mt-2">
                    {candidate.banner || 'No banner recorded'}
                  </pre>
                </details>
                {saved[evidence] && (
                  <p aria-live="polite">Saved finding: {saved[evidence].decision}</p>
                )}
                {canEdit && (
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={!!busy || !!saved[evidence]}
                    onClick={() => save(candidate)}
                  >
                    {saved[evidence] ? 'Finding recorded' : 'Save candidate as pending finding'}
                  </Button>
                )}
              </article>
            )
          })}
        </div>
      )}
    </section>
  )
}

export function PortInvestigation({
  sketchId,
  serviceId
}: {
  sketchId: string
  serviceId: string
}) {
  const context = useQuery({
    queryKey: ['copilot', 'service-context', sketchId, serviceId],
    queryFn: () => copilotService.serviceContext({ sketch_id: sketchId, service_id: serviceId }),
    retry: false
  })
  if (context.isPending) return <p className="p-3 text-sm">Loading recorded service evidence…</p>
  if (context.error)
    return (
      <div className="p-3 space-y-2">
        <p role="alert" className="text-sm text-destructive">
          {context.error.message}
        </p>
        <Button variant="outline" size="sm" onClick={() => void context.refetch()}>
          Reload service evidence
        </Button>
      </div>
    )
  return (
    <div className="space-y-2 p-3">
      <Button
        variant="outline"
        size="sm"
        disabled={context.isFetching}
        onClick={() => void context.refetch()}
      >
        Reload recorded service evidence
      </Button>
      <ServiceInvestigation
        key={`${sketchId}:${context.data.service_id}:${context.data.service_version}`}
        sketchId={sketchId}
        service={context.data}
      />
    </div>
  )
}
