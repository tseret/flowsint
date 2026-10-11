import type { Enricher } from '@/types/enricher'

export function EnricherMetadata({ enricher }: { enricher: Enricher }) {
  return (
    <div className="space-y-1 text-xs text-muted-foreground">
      <p>
        {enricher.provider || 'Provider not specified'} ·{' '}
        {enricher.passive === true
          ? 'Passive lookup'
          : enricher.passive === false
            ? 'Contacts target infrastructure'
            : 'Behavior not reviewed'}
      </p>
      <p>
        {enricher.freshness || 'Freshness depends on provider observations'}
        {enricher.max_results ? ` · Up to ${enricher.max_results} results` : ''}
      </p>
    </div>
  )
}
