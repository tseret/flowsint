import { describe, expect, it } from 'vitest'
import { candidateFinding, matchingCandidateFinding } from './copilot-candidates'
import type { CaseItem } from '@/api/collaboration-service'

describe('related IP evidence finding', () => {
  it('restores only a finding for the same entity, sketch and exact current evidence', () => {
    const candidate = { node_id: 'candidate-ip', label: '192.0.2.2', evidence: [] }
    const item = {
      ...candidateFinding('sketch', candidate),
      id: 'saved',
      decision: 'accepted',
      version: 3
    } as CaseItem
    const oldEvidence = { ...item, id: 'old', evidence: '{"old":true}' }
    const wrongSketch = { ...item, sketch_id: 'other' }
    const wrongTarget = { ...item, target_id: 'other' }
    const comment = { ...item, kind: 'comment' as const }
    expect(
      matchingCandidateFinding(
        [oldEvidence, wrongSketch, wrongTarget, comment, item],
        'sketch',
        candidate
      )
    ).toBe(item)
    expect(
      matchingCandidateFinding(
        [oldEvidence, wrongSketch, wrongTarget, comment],
        'sketch',
        candidate
      )
    ).toBeUndefined()
    expect(
      matchingCandidateFinding([item], 'sketch', {
        ...candidate,
        evidence: [
          {
            source_id: 'source',
            source_label: 'Source',
            evidence_id: 'new',
            evidence_label: 'New evidence',
            relationships: ['USES'],
            observations: []
          }
        ]
      })
    ).toBeUndefined()
  })
  it('targets the existing candidate and preserves source paths and dated observations', () => {
    const candidate = {
      node_id: 'candidate-ip',
      label: '192.0.2.2',
      evidence: [
        {
          source_id: 'selected-ip',
          source_label: '192.0.2.1',
          evidence_id: 'certificate',
          evidence_label: 'Shared certificate',
          relationships: ['USES_CERTIFICATE', 'USES_CERTIFICATE'],
          observations: [{ provider: 'Modat', observed_at: '2026-10-02', source_ref: 'import-42' }]
        }
      ]
    }
    const finding = candidateFinding('sketch', candidate)
    expect(finding).toMatchObject({
      kind: 'finding',
      sketch_id: 'sketch',
      target_kind: 'entity',
      target_id: 'candidate-ip'
    })
    expect(JSON.parse(finding.evidence!)).toEqual({
      candidate_id: 'candidate-ip',
      paths: candidate.evidence
    })
    expect(finding.body).toContain('requires analyst review')
    expect(finding.assessment).toContain('No new provider queries')
    expect(finding).not.toHaveProperty('decision')
  })
})
