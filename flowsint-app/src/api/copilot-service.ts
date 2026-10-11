import { fetchWithAuth } from './api'

export type AgentStep = {
  step: number
  enricher: string
  node_ids: string[]
  reason: string
  thought?: string
  scan_id?: string
  provider_block_reason?: string | null
  outcome: string
  output_count?: number
  provider_request_count?: number
  new_entity_count?: number
  errors?: { message: string }[]
}
export type InvestigationPolicy = {
  permitted_domains: string[]
  permitted_cidrs: string[]
  excluded_entities: string[]
  max_pivot_depth: number
  max_provider_requests: number
  max_graph_growth: number
}
export type AgentRun = {
  id: string
  sketch_id: string
  objective: string
  seed_ids: string[]
  status:
    | 'running'
    | 'publishing'
    | 'reporting'
    | 'report_pending'
    | 'completed'
    | 'failed'
    | 'cancelled'
    | 'undone'
  max_steps: number
  policy?: InvestigationPolicy | null
  steps: AgentStep[]
  report: string | null
  finding_ids: string[]
  error: string | null
  created_at: string | null
  started_at: string | null
  finished_at: string | null
}
export type CopilotCandidate = {
  node_id: string
  label: string
  evidence: {
    source_id: string
    source_label: string
    evidence_id: string
    evidence_label: string
    relationships: string[]
    observations: unknown[]
  }[]
}
export type CopilotServiceEvidence = {
  source_id: string
  source_label: string
  service_id: string
  service_version: number
  host: string
  port: number | null
  transport: string
  service: string
  provider: string
  observed_at: string
  retrieved_at: string
  banner: string
  source_ref: string
  fingerprints: Record<string, unknown>
  modat_queries: Record<string, string>
}
export type FingerprintMatch = {
  ip: string
  port: number | null
  transport: string
  protocol: string
  observed_at: string
  banner: string
  fingerprints: Record<string, string>
  matching_fingerprints: string[]
  source_ref: string
}
export type FingerprintResult = {
  query: string
  service: CopilotServiceEvidence
  matches: FingerprintMatch[]
  truncated: boolean
  total_records: number | null
  retrieved_at: string
}

export const copilotService = {
  importFingerprint: (body: {
    sketch_id: string
    finding_id: string
    finding_version: number
  }): Promise<{
    ip_id: string
    service_id: string
    source_service_id: string
  }> =>
    fetchWithAuth('/api/copilot/fingerprint/import', {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  serviceContext: (body: {
    sketch_id: string
    service_id: string
  }): Promise<CopilotServiceEvidence> =>
    fetchWithAuth('/api/copilot/service-context', { method: 'POST', body: JSON.stringify(body) }),
  fingerprint: (body: {
    sketch_id: string
    service_id: string
    service_version: number
    fingerprint: string
  }): Promise<FingerprintResult> =>
    fetchWithAuth('/api/copilot/fingerprint', { method: 'POST', body: JSON.stringify(body) }),
  candidates: (body: {
    sketch_id: string
    node_ids: string[]
    question: string
  }): Promise<{
    candidates: CopilotCandidate[]
    truncated: boolean
    services: CopilotServiceEvidence[]
    services_truncated: boolean
  }> => fetchWithAuth('/api/copilot/candidates', { method: 'POST', body: JSON.stringify(body) }),
  startAgent: (body: {
    sketch_id: string
    node_ids: string[]
    objective: string
    max_steps: number
    policy?: InvestigationPolicy
  }): Promise<AgentRun> =>
    fetchWithAuth('/api/copilot/agent', { method: 'POST', body: JSON.stringify(body) }),
  latestAgentRun: (sketchId: string): Promise<AgentRun | null> =>
    fetchWithAuth(`/api/copilot/agent?sketch_id=${encodeURIComponent(sketchId)}`),
  getAgentRun: (id: string): Promise<AgentRun> => fetchWithAuth(`/api/copilot/agent/${id}`),
  retryReport: (id: string): Promise<AgentRun> =>
    fetchWithAuth(`/api/copilot/agent/${id}/retry-report`, { method: 'POST' }),
  resumeAgent: (id: string): Promise<AgentRun> =>
    fetchWithAuth(`/api/copilot/agent/${id}/resume`, { method: 'POST' }),
  cancelAgent: (id: string): Promise<AgentRun> =>
    fetchWithAuth(`/api/copilot/agent/${id}/cancel`, { method: 'POST' }),
  undoAgent: (
    id: string
  ): Promise<AgentRun & { removed: { nodes: number; relationships: number; findings: number } }> =>
    fetchWithAuth(`/api/copilot/agent/${id}/undo`, { method: 'POST' })
}
