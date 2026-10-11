import { useQuery } from '@tanstack/react-query'
import { scanService } from '@/api/scan-service'
import { outcomeLabels } from '@/types/scan'

export function RunSummaries({ sketchId }: { sketchId: string }) {
  const scans = useQuery({
    queryKey: ['scans', 'list', sketchId],
    queryFn: () => scanService.getSketchScans(sketchId),
    refetchInterval: 5000
  })
  const recent = [...(scans.data || [])]
    .sort((a, b) => (b.started_at || '').localeCompare(a.started_at || ''))
    .slice(0, 10)
  if (scans.isError)
    return (
      <p role="alert" className="px-3 py-1 text-xs">
        Run history could not load.
      </p>
    )
  if (!recent.length) return null
  return (
    <details className="border-b px-3 py-1 text-xs">
      <summary className="cursor-pointer">
        Recent enrichment runs ·{' '}
        {recent[0].summary
          ? outcomeLabels[recent[0].summary.outcome] || recent[0].summary.outcome
          : recent[0].status}
      </summary>
      <div className="max-h-52 overflow-y-auto py-2 space-y-2">
        {recent.map((scan) => (
          <article key={scan.id} className="border rounded p-2">
            <p className="font-medium">
              {scan.summary?.enricher || scan.summary?.provider || 'Enrichment'} ·{' '}
              {scan.summary
                ? outcomeLabels[scan.summary.outcome] || scan.summary.outcome
                : scan.status}
            </p>
            {scan.summary && (
              <p>
                {scan.summary.input_count} inputs · {scan.summary.output_count} results ·{' '}
                {(scan.summary.duration_ms / 1000).toFixed(1)}s
              </p>
            )}
            <p className="text-muted-foreground">
              {scan.completed_at || scan.started_at} · Run {scan.id}
            </p>
            {scan.summary?.errors.map((error, index) => (
              <p key={index} className="text-destructive whitespace-pre-wrap">
                {typeof error === 'string' ? error : error.message}
              </p>
            ))}
            {scan.error && !scan.summary?.errors.length && (
              <p className="text-destructive">{scan.error}</p>
            )}
          </article>
        ))}
      </div>
    </details>
  )
}
