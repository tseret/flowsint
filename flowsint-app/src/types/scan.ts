export type RunOutcome =
  | 'results'
  | 'no_matches'
  | 'partial'
  | 'missing_credentials'
  | 'quota_exceeded'
  | 'failed'
export type RunSummary = {
  outcome: RunOutcome
  input_count: number
  output_count: number
  duration_ms: number
  errors: (string | { outcome: string; message: string })[]
  provider?: string
  enricher?: string
  scan_id: string
  provider_evidence?: {
    provider: string
    request_id: string
    fetched_at: string
    source_scan_id: string
    cache_hit: boolean
  }[]
  provider_request_count?: number
  committed_graph_operations?: number
  interrupted?: boolean
  graph_commit_uncertain?: boolean
}
export type Scan = {
  id: string
  sketch_id?: string
  status: string
  summary?: RunSummary | null
  started_at?: string
  completed_at?: string
  error?: string
}
export const outcomeLabels: Record<RunOutcome, string> = {
  results: 'Results found',
  no_matches: 'No matches',
  partial: 'Partial results',
  missing_credentials: 'Missing credentials',
  quota_exceeded: 'Quota exceeded',
  failed: 'Failed'
}
