import { fetchWithAuth } from './api'

export interface CaseItem {
  id: string
  kind: 'comment' | 'question' | 'finding'
  body: string
  evidence: string
  assessment: string
  status: 'open' | 'resolved'
  decision: 'pending' | 'accepted' | 'rejected'
  version: number
  author_id: string | null
  assignee_id: string | null
  reviewer_id: string | null
  sketch_id: string | null
  target_kind: 'entity' | 'relationship' | null
  target_id: string | null
  created_at: string
}
export interface CaseActivity {
  id: string
  actor_name: string
  action: string
  item_id: string | null
  details: Record<string, unknown>
  created_at: string
}
export const collaborationService = {
  items: (
    id: string,
    offset = 0,
    target?: { sketch_id: string; target_kind: string; target_id: string }
  ): Promise<CaseItem[]> => {
    const params = new URLSearchParams({ offset: String(offset), ...target })
    return fetchWithAuth(`/api/investigations/${id}/items?${params}`)
  },
  activity: (id: string, offset = 0): Promise<CaseActivity[]> =>
    fetchWithAuth(`/api/investigations/${id}/activity?offset=${offset}`),
  create: (id: string, body: Partial<CaseItem>): Promise<CaseItem> =>
    fetchWithAuth(`/api/investigations/${id}/items`, {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  update: (id: string, item: CaseItem, body: Partial<CaseItem>): Promise<CaseItem> =>
    fetchWithAuth(`/api/investigations/${id}/items/${item.id}`, {
      method: 'PUT',
      body: JSON.stringify({ ...body, version: item.version })
    })
}
