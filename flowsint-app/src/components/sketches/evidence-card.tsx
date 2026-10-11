import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { scanService } from '@/api/scan-service'
import { sketchService } from '@/api/sketch-service'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { evidenceUrl, formatEvidenceValue, parseEvidence } from '@/lib/evidence-display'
import { outcomeLabels } from '@/types/scan'

function ScanEvidence({ id }: { id: string }) {
  const scan = useQuery({ queryKey: ['scan-evidence', id], queryFn: () => scanService.getById(id) })
  if (scan.isPending) return <p>Loading recorded run…</p>
  if (scan.isError) return <p role="alert">This run could not be loaded.</p>
  return (
    <div className="space-y-2">
      <p>
        {scan.data.summary?.provider || scan.data.summary?.enricher || 'Enrichment'} ·{' '}
        {scan.data.summary
          ? outcomeLabels[scan.data.summary.outcome] || scan.data.summary.outcome
          : scan.data.status}
      </p>
      <p>
        Started {scan.data.started_at} · Completed {scan.data.completed_at || 'Not recorded'}
      </p>
      <pre className="overflow-auto whitespace-pre-wrap text-xs">
        {JSON.stringify(scan.data.summary, null, 2)}
      </pre>
    </div>
  )
}

export function EvidenceCard({
  evidence,
  targetId,
  sketchId,
  investigationId
}: {
  evidence: string
  targetId?: string | null
  sketchId?: string | null
  investigationId?: string
}) {
  const [scanId, setScanId] = useState<string | null>(null)
  const [inspectTarget, setInspectTarget] = useState(false)
  const parsed = parseEvidence(evidence)
  const source =
    parsed?.source && typeof parsed.source === 'object'
      ? (parsed.source as Record<string, unknown>)
      : parsed
  const scanIds = Array.isArray(parsed?.scan_ids)
    ? parsed.scan_ids.filter((v): v is string => typeof v === 'string')
    : []
  const target = useQuery({
    queryKey: ['evidence-target', sketchId, targetId],
    queryFn: () => sketchService.getGraphSlice(sketchId!, { center_ids: [targetId!], limit: 1 }),
    enabled: Boolean(inspectTarget && targetId && sketchId),
    staleTime: 60000
  })
  const label = target.data?.nds.find((n) => n.id === targetId)?.nodeLabel
  const url = evidenceUrl(source?.source_ref)
  return (
    <div className="space-y-2 rounded border bg-muted/20 p-3 text-sm">
      <p className="font-medium">Supporting evidence</p>
      {sketchId && investigationId && (
        <a
          className="text-primary underline"
          href={`/dashboard/investigations/${investigationId}/graph/${sketchId}`}
        >
          {label ? `Open sketch · ${label}` : 'Open investigation sketch'}
        </a>
      )}
      {targetId && sketchId && (
        <Button size="sm" variant="outline" onClick={() => setInspectTarget(true)}>
          View linked entity
        </Button>
      )}
      {source && (
        <dl className="grid grid-cols-2 gap-1 text-xs">
          <dt>Provider</dt>
          <dd>{formatEvidenceValue(source.provider)}</dd>
          <dt>Observed</dt>
          <dd>{formatEvidenceValue(source.observed_at)}</dd>
          <dt>Retrieved</dt>
          <dd>{formatEvidenceValue(source.retrieved_at || parsed?.retrieved_at)}</dd>
        </dl>
      )}
      {url && (
        <a className="text-primary underline" href={url} target="_blank" rel="noreferrer">
          Open source record
        </a>
      )}
      <div className="flex flex-wrap gap-2">
        {scanIds.map((id, index) => (
          <Button key={id} size="sm" variant="outline" onClick={() => setScanId(id)}>
            Evidence {index + 1} · view recorded run
          </Button>
        ))}
      </div>
      {!parsed && <p className="whitespace-pre-wrap">{evidence}</p>}
      {parsed && (
        <details>
          <summary className="cursor-pointer">Raw evidence</summary>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">
            {JSON.stringify(parsed, null, 2)}
          </pre>
        </details>
      )}
      <Dialog
        open={Boolean(scanId) || inspectTarget}
        onOpenChange={(open) => {
          if (!open) {
            setScanId(null)
            setInspectTarget(false)
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Recorded enrichment evidence</DialogTitle>
          </DialogHeader>
          {scanId && <ScanEvidence id={scanId} />}
          {inspectTarget &&
            (target.isPending ? (
              <p>Loading entity…</p>
            ) : target.isError ? (
              <p role="alert">Entity could not load.</p>
            ) : (
              <div>
                <p>{label || 'Entity no longer available'}</p>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs">
                  {JSON.stringify(target.data?.nds[0]?.nodeProperties, null, 2)}
                </pre>
              </div>
            ))}
        </DialogContent>
      </Dialog>
    </div>
  )
}
