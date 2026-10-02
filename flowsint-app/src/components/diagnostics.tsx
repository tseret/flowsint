import { useQuery } from '@tanstack/react-query'
import { fetchWithAuth } from '@/api/api'
import { Button } from '@/components/ui/button'

interface DiagnosticReport {
  revision: string
  postgres: string
  redis: string
  neo4j: string
  migrations_current: boolean
  database_migrations: string[]
  expected_migrations: string[]
  connectors: string[]
  worker: { revision: string; connectors: string[] } | null
  worker_matches_api: boolean
}

export function Diagnostics() {
  const { data, isFetching, error, refetch } = useQuery<DiagnosticReport>({
    queryKey: ['diagnostics'],
    queryFn: () => fetchWithAuth('/api/diagnostics'),
    enabled: false
  })
  const frontendRevision = import.meta.env.VITE_BUILD_REVISION || 'development'

  return (
    <section className="space-y-3 border-t pt-6">
      <div className="flex items-center justify-between gap-3">
        <h2 className="font-medium">Setup diagnostics</h2>
        <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
          {isFetching ? 'Checking…' : 'Check setup'}
        </Button>
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          Could not check setup. Try again.
        </p>
      )}
      {data && (
        <dl className="grid grid-cols-2 gap-2 text-sm">
          <dt>Frontend build</dt>
          <dd className="break-all">{frontendRevision}</dd>
          <dt>API build</dt>
          <dd className="break-all">{data.revision}</dd>
          <dt>Worker build</dt>
          <dd className="break-all">{data.worker?.revision ?? 'Unavailable'}</dd>
          <dt>Builds and connectors match</dt>
          <dd>
            {data.worker_matches_api && frontendRevision === data.revision
              ? 'Yes'
              : 'No / development build'}
          </dd>
          <dt>PostgreSQL</dt>
          <dd>{data.postgres}</dd>
          <dt>Redis</dt>
          <dd>{data.redis}</dd>
          <dt>Neo4j</dt>
          <dd>{data.neo4j}</dd>
          <dt>Migrations</dt>
          <dd>{data.migrations_current ? 'Current' : 'Upgrade required'}</dd>
          <dt>Database revision</dt>
          <dd className="break-all">{data.database_migrations.join(', ') || 'Unknown'}</dd>
          <dt>Expected revision</dt>
          <dd className="break-all">{data.expected_migrations.join(', ')}</dd>
          <dt>API connectors</dt>
          <dd>{data.connectors.length}</dd>
          <dt>Worker connectors</dt>
          <dd>{data.worker?.connectors.length ?? 'Unknown'}</dd>
        </dl>
      )}
    </section>
  )
}
