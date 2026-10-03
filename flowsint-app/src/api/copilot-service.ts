import { fetchWithAuth } from './api'

export type AgentStep = {
  step: number
  enricher: string
  node_ids: string[]
  reason: string
  thought?: string
  scan_id?: string
  outcome: string
  output_count?: number
  errors?: { message: string }[]
}
export type AgentRun = {
  id: string
  sketch_id: string
  objective: string
  seed_ids: string[]
  status: 'running' | 'publishing' | 'completed' | 'failed' | 'cancelled'
  max_steps: number
  steps: AgentStep[]
  report: string | null
  finding_ids: string[]
  error: string | null
  created_at: string | null
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
  }): Promise<AgentRun> =>
    fetchWithAuth('/api/copilot/agent', { method: 'POST', body: JSON.stringify(body) }),
  latestAgentRun: (sketchId: string): Promise<AgentRun | null> =>
    fetchWithAuth(`/api/copilot/agent?sketch_id=${encodeURIComponent(sketchId)}`),
  getAgentRun: (id: string): Promise<AgentRun> => fetchWithAuth(`/api/copilot/agent/${id}`),
  cancelAgent: (id: string): Promise<AgentRun> =>
    fetchWithAuth(`/api/copilot/agent/${id}/cancel`, { method: 'POST' })
}
