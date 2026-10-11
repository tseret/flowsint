import { fetchWithAuth } from './api'
import type { Scan } from '@/types/scan'

export const scanService = {
  getById: (scan_id: string): Promise<Scan> =>
    fetchWithAuth(`/api/scans/${scan_id}`, { method: 'GET' }),
  delete: (scan_id: string) => fetchWithAuth(`/api/scans/${scan_id}`, { method: 'DELETE' }),
  getSketchScans: (sketch_id: string): Promise<Scan[]> =>
    fetchWithAuth(`/api/scans/sketch/${sketch_id}`, { method: 'GET' }),
  deleteAll: () => fetchWithAuth('/api/scans/all', { method: 'DELETE' })
}
