import { describe, expect, it, vi } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import {
  ServiceInvestigation,
  fingerprintFinding,
  matchingFingerprintFinding,
  isFingerprintFinding,
  FingerprintImportButton
} from './service-investigation'
import {
  copilotService,
  type CopilotServiceEvidence,
  type FingerprintResult
} from '@/api/copilot-service'
import { usePermissions } from '@/hooks/use-can'
import type { CaseItem } from '@/api/collaboration-service'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('@/hooks/use-can', () => ({ usePermissions: vi.fn(() => ({ canEdit: false })) }))

const service: CopilotServiceEvidence = {
  source_id: 'source-ip',
  source_label: '192.0.2.1',
  service_id: 'source-port',
  service_version: 3,
  host: '192.0.2.1',
  port: 443,
  transport: 'tcp',
  service: 'https',
  provider: 'Modat',
  observed_at: '2026-10-01',
  retrieved_at: '2026-10-02',
  banner: 'Recorded server banner',
  source_ref: 'indexed-source',
  fingerprints: { banner_hash: 'abc123' },
  modat_queries: { banner_hash: 'banner_hash=abc123' }
}
const result: FingerprintResult = {
  service,
  query: service.modat_queries.banner_hash,
  retrieved_at: '2026-10-03',
  truncated: false,
  total_records: 1,
  matches: [
    {
      ip: '192.0.2.2',
      port: 443,
      transport: 'tcp',
      protocol: 'https',
      observed_at: '2026-10-01',
      banner: 'Candidate banner',
      fingerprints: { banner_hash: 'abc123' },
      matching_fingerprints: ['banner_hash'],
      source_ref: 'candidate-source'
    }
  ]
}

describe('passive indexed service review', () => {
  it('does not offer graph import for a rejected finding', () => {
    vi.mocked(usePermissions).mockReturnValueOnce({ canEdit: true } as ReturnType<
      typeof usePermissions
    >)
    const item = {
      ...fingerprintFinding('sketch', result, result.matches[0]),
      id: 'saved',
      version: 4,
      decision: 'rejected'
    } as CaseItem
    const html = renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <FingerprintImportButton finding={item} />
      </QueryClientProvider>
    )
    expect(html).not.toContain('Add candidate to graph')
  })
  it('renders an explicit saved-finding import action without importing or querying providers', () => {
    vi.mocked(usePermissions).mockReturnValueOnce({ canEdit: true } as ReturnType<
      typeof usePermissions
    >)
    const item = {
      ...fingerprintFinding('sketch', result, result.matches[0]),
      id: 'saved',
      version: 3,
      decision: 'pending'
    } as CaseItem
    const importer = vi.spyOn(copilotService, 'importFingerprint')
    const lookup = vi.spyOn(copilotService, 'fingerprint')
    const html = renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <FingerprintImportButton finding={item} />
      </QueryClientProvider>
    )
    expect(html).toContain('Add candidate to graph')
    expect(importer).not.toHaveBeenCalled()
    expect(lookup).not.toHaveBeenCalled()
    expect(item.decision).toBe('pending')
    importer.mockRestore()
    lookup.mockRestore()
  })
  it('offers saved-evidence imports only for fingerprint findings on their source service', () => {
    const finding = {
      ...fingerprintFinding('sketch', result, result.matches[0]),
      id: 'saved',
      version: 3,
      decision: 'pending'
    } as CaseItem
    expect(isFingerprintFinding(finding)).toBe(true)
    expect(isFingerprintFinding({ ...finding, kind: 'comment' })).toBe(false)
    expect(isFingerprintFinding({ ...finding, target_id: 'unrelated-ip' })).toBe(false)
    expect(isFingerprintFinding({ ...finding, evidence: 'not JSON' })).toBe(false)
    expect(
      isFingerprintFinding({
        ...finding,
        evidence: JSON.stringify({
          query: 'query',
          source: { service_id: finding.target_id },
          candidate: {}
        })
      })
    ).toBe(false)
  })
  it('shows exact query, recorded context and disabled lookup for readers without running a search', () => {
    const lookup = vi.spyOn(copilotService, 'fingerprint')
    const html = renderToStaticMarkup(<ServiceInvestigation sketchId="sketch" service={service} />)
    expect(html).toContain('banner_hash=abc123')
    expect(html).toContain('Recorded server banner')
    expect(html).toContain('192.0.2.1:443')
    expect(html).toContain('2026-10-01')
    expect(html).toMatch(/disabled=""[^>]*>Search Modat index/)
    expect(lookup).not.toHaveBeenCalled()
    lookup.mockRestore()
  })
  it('still requires an explicit lookup action for editors', () => {
    vi.mocked(usePermissions).mockReturnValueOnce({ canEdit: true } as ReturnType<
      typeof usePermissions
    >)
    const lookup = vi.spyOn(copilotService, 'fingerprint')
    const html = renderToStaticMarkup(<ServiceInvestigation sketchId="sketch" service={service} />)
    expect(html).toContain('Search Modat index')
    expect(html).not.toMatch(/disabled=""[^>]*>Search Modat index/)
    expect(lookup).not.toHaveBeenCalled()
    lookup.mockRestore()
  })
  it('saves an unverified pending finding on the source service with exact query and dated evidence', () => {
    const finding = fingerprintFinding('sketch', result, result.matches[0])
    expect(finding).toMatchObject({
      kind: 'finding',
      sketch_id: 'sketch',
      target_kind: 'entity',
      target_id: 'source-port'
    })
    expect(finding).not.toHaveProperty('decision')
    const { modat_queries: _queries, ...recordedSource } = service
    expect(JSON.parse(finding.evidence!)).toEqual({
      query: result.query,
      source: recordedSource,
      candidate: result.matches[0],
      matching_fingerprints: ['banner_hash'],
      retrieved_at: result.retrieved_at,
      evidence_truncated: false
    })
    const item = { ...finding, id: 'recorded', version: 2, decision: 'pending' } as CaseItem
    expect(matchingFingerprintFinding([item], finding)).toBe(item)
    expect(
      matchingFingerprintFinding([{ ...item, evidence: 'different evidence' }], finding)
    ).toBeUndefined()
    expect(
      matchingFingerprintFinding([{ ...item, target_id: 'candidate-ip' }], finding)
    ).toBeUndefined()
  })
  it('bounds oversized descriptions and arbitrary stored metadata while preserving hash support', () => {
    const huge = '\u0000'.repeat(100000)
    const source = {
      ...service,
      banner: huge,
      source_ref: huge,
      provider: huge,
      fingerprints: { ...service.fingerprints, arbitrary_metadata: { huge } },
      modat_queries: { banner_hash: huge }
    }
    const candidate = { ...result.matches[0], banner: huge, source_ref: huge }
    const finding = fingerprintFinding('sketch', { ...result, service: source }, candidate)
    expect(finding.evidence!.length).toBeLessThanOrEqual(20000)
    const evidence = JSON.parse(finding.evidence!)
    expect(evidence.evidence_truncated).toBe(true)
    expect(evidence.query).toBe(result.query)
    expect(evidence.source.source_id).toBe(service.source_id)
    expect(evidence.source.service_id).toBe(service.service_id)
    expect(evidence.source.fingerprints).toEqual({ banner_hash: 'abc123' })
    expect(evidence.source).not.toHaveProperty('modat_queries')
    expect(evidence.candidate.fingerprints).toEqual(candidate.fingerprints)
    expect(evidence.matching_fingerprints).toEqual(['banner_hash'])
  })
  it('defaults to recorded HASSH when available while keeping query selection explicit', () => {
    const html = renderToStaticMarkup(
      <ServiceInvestigation
        sketchId="sketch"
        service={{
          ...service,
          modat_queries: {
            banner_hash: 'banner_hash=abc123',
            ssh_hassh: 'port=22 ssh.hassh=recorded'
          }
        }}
      />
    )
    expect(html).toMatch(/value="ssh_hassh" selected=""/)
    expect(html).toContain('port=22 ssh.hassh=recorded')
  })
})
