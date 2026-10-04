import { fetchWithAuth } from './api'

export type CopilotBillingMode = 'subscription' | 'api'
export type ChatGPTSubscriptionStatus = {
  mode: CopilotBillingMode
  connected: boolean
  account_label: string | null
  model: string
  reasoning_effort: string
  accounts: { id: string; label: string; connected: boolean }[]
  active_account_id: string | null
  error?: string
}

export const chatGPTSubscriptionService = {
  status: (): Promise<ChatGPTSubscriptionStatus> =>
    fetchWithAuth('/api/chatgpt-subscription/status'),
  connect: (body: {
    account_id?: string
    new_account?: boolean
  }): Promise<{ authorization_url: string }> =>
    fetchWithAuth('/api/chatgpt-subscription/connect', {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  models: (): Promise<{ models: { slug: string; display_name: string }[] }> =>
    fetchWithAuth('/api/chatgpt-subscription/models'),
  settings: (settings: {
    mode: CopilotBillingMode
    model?: string
    reasoning_effort?: string
  }): Promise<ChatGPTSubscriptionStatus> =>
    fetchWithAuth('/api/chatgpt-subscription/settings', {
      method: 'PUT',
      body: JSON.stringify(settings)
    }),
  disconnect: (): Promise<void> =>
    fetchWithAuth('/api/chatgpt-subscription/connection', { method: 'DELETE' })
}
