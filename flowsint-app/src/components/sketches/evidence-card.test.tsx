import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { ScanPersistenceEvidence } from './evidence-card'
import type { RunSummary } from '@/types/scan'

const summary: RunSummary = {
  outcome: 'partial',
  input_count: 1,
  output_count: 0,
  duration_ms: 1,
  errors: [],
  scan_id: 'current'
}

describe('recorded run persistence evidence', () => {
  it('shows confirmed zero separately from uncertain or interrupted graph writes', () => {
    const html = renderToStaticMarkup(
      <ScanPersistenceEvidence
        summary={{
          ...summary,
          committed_graph_operations: 0,
          provider_request_count: 0,
          interrupted: true,
          graph_commit_uncertain: true
        }}
      />
    )
    expect(html).toContain('Confirmed committed graph operations: 0')
    expect(html).toContain('Provider requests: 0')
    expect(html).toContain('Run interrupted')
    expect(html).toContain('Graph commit could not be confirmed')
  })
  it('retains the original fetch date and source scan when a response was reused', () => {
    const html = renderToStaticMarkup(
      <ScanPersistenceEvidence
        summary={{
          ...summary,
          provider_evidence: [
            {
              provider: 'Shodan',
              request_id: 'lookup',
              fetched_at: '2026-10-01T12:00:00Z',
              source_scan_id: 'original',
              cache_hit: true
            }
          ]
        }}
      />
    )
    expect(html).toContain('Reused recorded response')
    expect(html).toContain('2026-10-01T12:00:00Z')
    expect(html).toContain('original')
    expect(html).not.toContain('Run interrupted')
  })
})
