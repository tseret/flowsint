import { describe, it, expect } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { FingerprintPivotDetails } from './edge-details-panel'

describe('readable pivot evidence', () => {
  it('shows exact query, service endpoints, hashes, banners and dated provider evidence', () => {
    const html = renderToStaticMarkup(
      <FingerprintPivotDetails
        observation={{
          evidence: {
            query: 'port=22 ssh.hassh="hash"',
            retrieved_at: '2026-10-03',
            matching_fingerprints: ['ssh.hassh'],
            source: {
              service_id: 'source-port',
              host: '192.0.2.1',
              port: 22,
              transport: 'tcp',
              service: 'ssh',
              observed_at: '2026-10-01',
              banner: 'SSH source banner',
              fingerprints: { 'ssh.hassh': 'hash' }
            },
            candidate: {
              ip: '192.0.2.2',
              port: 22,
              transport: 'tcp',
              protocol: 'ssh',
              observed_at: '2026-10-02',
              banner: 'SSH candidate banner',
              fingerprints: { 'ssh.hassh': 'hash' }
            }
          }
        }}
      />
    )
    expect(html).toContain('Exact indexed query')
    expect(html).toContain('port=22 ssh.hassh=&quot;hash&quot;')
    expect(html).toContain('source-port')
    expect(html).toContain('SSH source banner')
    expect(html).toContain('SSH candidate banner')
    expect(html).toContain('2026-10-01')
    expect(html).toContain('2026-10-03')
    expect(html).toContain('does not establish common control')
  })
  it('ignores absent or malformed fingerprint snapshots', () => {
    expect(renderToStaticMarkup(<FingerprintPivotDetails observation={null} />)).toBe('')
    expect(renderToStaticMarkup(<FingerprintPivotDetails observation={{ evidence: {} }} />)).toBe(
      ''
    )
  })
})
