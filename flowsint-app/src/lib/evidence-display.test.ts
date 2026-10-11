import { describe, expect, it } from 'vitest'
import { formatEvidenceValue, parseEvidence, evidenceUrl } from './evidence-display'
describe('evidence display', () => {
  it('preserves false, zero and nested fingerprints', () => {
    expect(formatEvidenceValue(0)).toBe('0')
    expect(formatEvidenceValue(false)).toBe('false')
    expect(formatEvidenceValue({ sha256: 'abc' })).toBe('{"sha256":"abc"}')
  })
  it('handles legacy text and refuses executable evidence links', () => {
    expect(parseEvidence('legacy note')).toBeNull()
    expect(parseEvidence('[]')).toBeNull()
    expect(evidenceUrl('javascript:alert(1)')).toBeUndefined()
    expect(evidenceUrl('https://example.com/evidence')).toBe('https://example.com/evidence')
  })
})
