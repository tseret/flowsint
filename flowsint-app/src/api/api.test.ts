import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/stores/auth-store', () => ({
  useAuthStore: { getState: () => ({ token: null, logout: vi.fn() }) }
}))
import { fetchWithAuth } from './api'

afterEach(() => vi.unstubAllGlobals())

describe('API errors for concurrent edits', () => {
  it('exposes a conflict status so callers retain drafts instead of treating it as success', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: 'Entity changed since it was loaded' }), {
          status: 409
        })
      )
    )
    await expect(
      fetchWithAuth('/api/sketches/sketch/nodes/edit', { method: 'PUT', body: '{}' })
    ).rejects.toMatchObject({ status: 409, message: 'Entity changed since it was loaded' })
  })
  it('preserves a useful error and status if the server returns a non-JSON response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response('Gateway unavailable', { status: 502 }))
    )
    await expect(fetchWithAuth('/api/sketches/sketch/graph')).rejects.toMatchObject({
      status: 502,
      message: 'Erreur 502'
    })
  })
})
