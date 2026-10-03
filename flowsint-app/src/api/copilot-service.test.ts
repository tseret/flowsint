import { describe, expect, it, vi } from 'vitest'
import { copilotService } from './copilot-service'
import { fetchWithAuth } from './api'

vi.mock('./api', () => ({ fetchWithAuth: vi.fn().mockResolvedValue({}) }))

describe('copilot evidence requests', () => {
  it('imports only a saved finding ID and exact version without sending a provider query', async () => {
    const request = { sketch_id: 'sketch', finding_id: 'finding', finding_version: 4 }
    await copilotService.importFingerprint(request)
    expect(fetchWithAuth).toHaveBeenLastCalledWith('/api/copilot/fingerprint/import', {
      method: 'POST',
      body: JSON.stringify(request)
    })
  })
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
})
