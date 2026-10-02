import { describe, expect, it, vi } from 'vitest'
import {
  copilotService,
  isRunComplete,
  matchesPlan,
  pollCopilotRun,
  externalCallCount,
  providerName,
  type CopilotPlan
} from './copilot-service'
import { fetchWithAuth } from './api'
import { scanService } from './scan-service'

vi.mock('./api', () => ({ fetchWithAuth: vi.fn().mockResolvedValue({ runs: [] }) }))
vi.mock('./scan-service', () => ({ scanService: { getById: vi.fn() } }))

const plan: CopilotPlan = {
  sketch_id: 'sketch',
  question: 'Check ownership',
  node_ids: ['a', 'b'],
  node_versions: { a: 1, b: 2 },
  analysis: '',
  steps: [],
  context_truncated: false
}

describe('reviewed copilot plan', () => {
  it('loads stored service context separately from an explicit versioned fingerprint lookup', async () => {
    await copilotService.serviceContext({ sketch_id: 'sketch', service_id: 'port' })
    expect(fetchWithAuth).toHaveBeenLastCalledWith('/api/copilot/service-context', {
      method: 'POST',
      body: JSON.stringify({ sketch_id: 'sketch', service_id: 'port' })
    })
    const request = {
      sketch_id: 'sketch',
      service_id: 'port',
      service_version: 3,
      fingerprint: 'banner_hash'
    }
    await copilotService.fingerprint(request)
    expect(fetchWithAuth).toHaveBeenLastCalledWith('/api/copilot/fingerprint', {
      method: 'POST',
      body: JSON.stringify(request)
    })
  })
  it('requests existing candidates only for the specified sketch and entities', async () => {
    const request = {
      sketch_id: 'sketch',
      node_ids: ['ip-1'],
      question: 'Review existing evidence'
    }
    await copilotService.candidates(request)
    expect(fetchWithAuth).toHaveBeenLastCalledWith('/api/copilot/candidates', {
      method: 'POST',
      body: JSON.stringify(request)
    })
  })
  it('sends the exact selected IP scope and question to collection', async () => {
    const request = {
      sketch_id: 'sketch',
      node_ids: ['ip-1', 'ip-2'],
      question: 'Check passive IP intelligence'
    }
    await copilotService.collect(request)
    expect(fetchWithAuth).toHaveBeenLastCalledWith('/api/copilot/collect', {
      method: 'POST',
      body: JSON.stringify(request)
    })
  })
  it('budgets all passive IP providers including bounded VirusTotal pagination', () => {
    const names = [
      'ip_to_ports_shodan',
      'ip_to_ports_modat',
      'ip_to_reputation_virustotal',
      'ip_to_domains_virustotal',
      'ip_to_threatfox'
    ]
    expect(
      externalCallCount(
        names.map((enricher) => ({ enricher, node_ids: ['a', 'b'], reason: '', missing_keys: [] }))
      )
    ).toBe(12)
    expect(providerName('ip_to_ports_shodan')).toBe('Shodan')
    expect(providerName('ip_to_ports_modat')).toBe('Modat')
    expect(providerName('ip_to_domains_virustotal')).toBe('VirusTotal')
    expect(providerName('domain_to_root_domain')).toBe('Local processing')
    expect(providerName('unknown')).toBe('Unknown provider')
  })
  it('keeps queued tasks pending until workers insert their scan rows', async () => {
    vi.mocked(scanService.getById).mockRejectedValueOnce(
      Object.assign(new Error('Not found'), { status: 404 })
    )
    expect(await pollCopilotRun('queued')).toEqual({ id: 'queued', status: 'PENDING' })
    vi.mocked(scanService.getById).mockResolvedValueOnce({ id: 'queued', status: 'COMPLETED' })
    expect(await pollCopilotRun('queued')).toEqual({ id: 'queued', status: 'COMPLETED' })
  })
  it('surfaces real status errors instead of concealing them as queued tasks', async () => {
    vi.mocked(scanService.getById).mockRejectedValueOnce(
      Object.assign(new Error('Forbidden'), { status: 403 })
    )
    await expect(pollCopilotRun('forbidden')).rejects.toThrow('Forbidden')
  })
  it('counts external lookups only for provider-backed steps', () => {
    expect(
      externalCallCount([
        { enricher: 'domain_to_root_domain', node_ids: ['a', 'b'], reason: '', missing_keys: [] },
        { enricher: 'domain_to_threatfox', node_ids: ['a', 'b'], reason: '', missing_keys: [] },
        { enricher: 'ip_to_threatfox', node_ids: ['c'], reason: '', missing_keys: [] }
      ])
    ).toBe(3)
  })
  it('sends the reviewed selection and entity versions unchanged when running', async () => {
    await copilotService.run(plan)
    expect(fetchWithAuth).toHaveBeenLastCalledWith('/api/copilot/run', {
      method: 'POST',
      body: JSON.stringify(plan)
    })
  })
  it('accepts reordered selection and trimmed question', () => {
    expect(matchesPlan(plan, 'sketch', ['b', 'a'], ' Check ownership ')).toBe(true)
  })
  it('invalidates a plan when scope or question changes', () => {
    expect(matchesPlan(plan, 'other', ['a', 'b'], plan.question)).toBe(false)
    expect(matchesPlan(plan, 'sketch', ['a', 'c'], plan.question)).toBe(false)
    expect(matchesPlan(plan, 'sketch', ['a'], plan.question)).toBe(false)
    expect(matchesPlan(plan, 'sketch', ['a', 'b'], 'Check addresses')).toBe(false)
  })
  it('summarizes failed runs as well as completed runs, but waits for pending work', () => {
    expect(isRunComplete('COMPLETED')).toBe(true)
    expect(isRunComplete('failed')).toBe(true)
    expect(isRunComplete('PENDING')).toBe(false)
    expect(isRunComplete('RUNNING')).toBe(false)
    expect(isRunComplete('SUCCESS')).toBe(false)
  })
})
