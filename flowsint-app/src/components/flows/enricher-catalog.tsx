import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { enricherService } from '@/api/enricher-service'
import { Input } from '@/components/ui/input'
import { EnricherMetadata } from './enricher-metadata'

export function EnricherCatalog() {
  const catalog = useQuery({ queryKey: ['enricher-catalog'], queryFn: () => enricherService.get() })
  const readiness = useQuery({
    queryKey: ['enricher-readiness'],
    queryFn: enricherService.readiness
  })
  const [search, setSearch] = useState('')
  const [passive, setPassive] = useState(false)
  const [purpose, setPurpose] = useState('all')
  const purposes = [...new Set((catalog.data || []).map((e) => e.purpose || e.category))].sort()
  const matches = (catalog.data || []).filter(
    (e) =>
      (!passive || e.passive === true) &&
      (purpose === 'all' || (e.purpose || e.category) === purpose) &&
      [e.display_name, e.name, e.description, e.provider, e.purpose]
        .join(' ')
        .toLowerCase()
        .includes(search.toLowerCase())
  )
  return (
    <section className="space-y-4 mb-8">
      <h2 className="text-lg font-semibold">Investigation capabilities</h2>
      <p className="text-sm text-muted-foreground">
        Choose a capability from a selected entity or combine it in a flow. Provider credentials and
        recorded run status are shown below.
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <Input
          className="max-w-md"
          aria-label="Search capabilities"
          placeholder="What do you want to discover?"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          aria-label="Capability purpose"
          className="border rounded bg-background p-2"
          value={purpose}
          onChange={(e) => setPurpose(e.target.value)}
        >
          <option value="all">All purposes</option>
          {purposes.map((p) => (
            <option key={p}>{p}</option>
          ))}
        </select>
        <label className="text-sm">
          <input type="checkbox" checked={passive} onChange={(e) => setPassive(e.target.checked)} />{' '}
          Passive only
        </label>
      </div>
      {catalog.isPending && <p>Loading capabilities…</p>}
      {catalog.isError && <p role="alert">The capability catalog could not load.</p>}
      {readiness.isError && <p role="alert">Provider readiness could not load.</p>}
      <p className="text-sm">{matches.length} capabilities</p>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {matches.map((e) => (
          <details className="rounded border p-3" key={e.name}>
            <summary className="cursor-pointer font-medium">{e.display_name || e.name}</summary>
            <div className="space-y-2 pt-2">
              <p className="text-sm">{e.description}</p>
              <EnricherMetadata enricher={e} />
              <p className="text-xs">
                {e.inputs?.type} → {e.outputs?.type}
              </p>
              <p className="text-xs">
                {readiness.data?.[e.name]
                  ? readiness.data[e.name].credentials_configured
                    ? 'Credentials configured'
                    : `Missing: ${readiness.data[e.name].missing_required_keys.join(', ')}`
                  : 'Readiness not available'}
              </p>
              {readiness.data?.[e.name]?.last_run && (
                <p className="text-xs">
                  Last run: {readiness.data[e.name].last_run?.outcome} ·{' '}
                  {readiness.data[e.name].last_run_at}
                </p>
              )}
              {e.params_schema?.map((p) => (
                <p key={p.name} className="text-xs">
                  {p.name}: {p.description} {p.default !== undefined && `(default ${p.default})`}
                </p>
              ))}
            </div>
          </details>
        ))}
      </div>
    </section>
  )
}
