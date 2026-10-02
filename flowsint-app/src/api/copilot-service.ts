import { fetchWithAuth } from './api'
import { scanService } from './scan-service'
import type { Scan } from '@/types/scan'

export type CopilotStep = {
  enricher: string
  node_ids: string[]
  reason: string
  missing_keys: string[]
}
export type CopilotPlan = {
  question: string
  sketch_id: string
  node_ids: string[]
  node_versions: Record<string, number>
  analysis: string
  steps: CopilotStep[]
  context_truncated: boolean
}
export type CopilotRun = { id: string; enricher: string; node_ids: string[] }
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
export type CopilotSummary = {
  summary: string
  evidence: {
    run_id: string
    status: string
    details: unknown
    summary?: unknown
    relationships?: unknown
    relationships_truncated?: boolean
  }[]
  context_truncated: boolean
}

export const copilotService = {
  candidates: (body: {
    sketch_id: string
    node_ids: string[]
    question: string
  }): Promise<{
    candidates: CopilotCandidate[]
    truncated: boolean
  }> => fetchWithAuth('/api/copilot/candidates', { method: 'POST', body: JSON.stringify(body) }),
  collect: (body: {
    sketch_id: string
    node_ids: string[]
    question: string
  }): Promise<{
    plan: CopilotPlan
    runs: CopilotRun[]
    skipped: CopilotStep[]
    error?: string
  }> => fetchWithAuth('/api/copilot/collect', { method: 'POST', body: JSON.stringify(body) }),
  plan: (body: { sketch_id: string; node_ids: string[]; question: string }): Promise<CopilotPlan> =>
    fetchWithAuth('/api/copilot/plan', { method: 'POST', body: JSON.stringify(body) }),
  run: (body: CopilotPlan): Promise<{ runs: CopilotRun[]; error?: string }> =>
    fetchWithAuth('/api/copilot/run', { method: 'POST', body: JSON.stringify(body) }),
  save: (body: CopilotPlan & { name: string }): Promise<{ id: string }> =>
    fetchWithAuth('/api/copilot/save', { method: 'POST', body: JSON.stringify(body) }),
  summary: (body: {
    sketch_id: string
    run_ids: string[]
    question: string
  }): Promise<CopilotSummary> =>
    fetchWithAuth('/api/copilot/summary', { method: 'POST', body: JSON.stringify(body) })
}

export async function pollCopilotRun(id: string): Promise<Scan> {
  try {
    return await scanService.getById(id)
  } catch (error) {
    // Workers insert scan rows after consuming queued tasks.
    if (error instanceof Error && 'status' in error && error.status === 404) {
      return { id, status: 'PENDING' }
    }
    throw error
  }
}

export function externalCallCount(steps: CopilotStep[]) {
  return steps.reduce(
    (total, step) => total + (passiveProviders[step.enricher]?.calls ?? 0) * step.node_ids.length,
    0
  )
}

const passiveProviders: Record<string, { name: string; calls: number }> = {
  domain_to_root_domain: { name: 'Local processing', calls: 0 },
  domain_to_threatfox: { name: 'ThreatFox', calls: 1 },
  ip_to_threatfox: { name: 'ThreatFox', calls: 1 },
  ip_to_ports_shodan: { name: 'Shodan', calls: 1 },
  ip_to_ports_modat: { name: 'Modat', calls: 1 },
  ip_to_reputation_virustotal: { name: 'VirusTotal', calls: 1 },
  ip_to_domains_virustotal: { name: 'VirusTotal', calls: 2 }
}

export function providerName(enricher: string) {
  return passiveProviders[enricher]?.name ?? 'Unknown provider'
}

export function matchesPlan(plan: CopilotPlan, sketchId: string, ids: string[], question: string) {
  return (
    plan.sketch_id === sketchId &&
    plan.question === question.trim() &&
    JSON.stringify([...plan.node_ids].sort()) === JSON.stringify([...ids].sort())
  )
}

export function isRunComplete(status: string) {
  return ['COMPLETED', 'FAILED'].includes(status.toUpperCase())
}
