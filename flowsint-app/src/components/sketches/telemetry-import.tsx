import { useState } from 'react'
import { fetchWithAuth } from '@/api/api'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger
} from '@/components/ui/dialog'
import { useGraphControls } from '@/stores/graph-controls-store'
import { toast } from 'sonner'

type Preview = {
  observation_count: number
  executed: boolean
  preview: {
    source: { label: string }
    target: { label: string }
    relationship: string
    observed_at: string
  }[]
}
export function TelemetryImport({ sketchId }: { sketchId: string }) {
  const [open, setOpen] = useState(false)
  const [format, setFormat] = useState('normalized')
  const [content, setContent] = useState('')
  const [preview, setPreview] = useState<Preview | null>(null)
  const [busy, setBusy] = useState(false)
  const run = async (execute: boolean) => {
    setBusy(true)
    try {
      const result: Preview = await fetchWithAuth(`/api/sketches/${sketchId}/import/telemetry`, {
        method: 'POST',
        body: JSON.stringify({ format, content, execute })
      })
      if (execute) {
        toast.success(`Imported ${result.observation_count} observations`)
        setOpen(false)
        setPreview(null)
        setContent('')
        useGraphControls.getState().refetchGraph?.()
      } else setPreview(result)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Import failed')
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline">
          Import telemetry
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-3xl max-h-[85vh] overflow-auto">
        <DialogHeader>
          <DialogTitle>Import internal observations</DialogTitle>
        </DialogHeader>
        <p className="text-sm">
          Import JSON or newline-delimited JSON from existing telemetry. Up to 2 MiB, 1,000 records
          and 2,000 relationships per import. Nothing is sent to external providers.
        </p>
        <label>
          Source format{' '}
          <select
            aria-label="Telemetry format"
            disabled={busy}
            className="rounded border bg-background p-2"
            value={format}
            onChange={(e) => {
              setFormat(e.target.value)
              setPreview(null)
            }}
          >
            <option value="normalized">Normalized observations</option>
            <option value="dns">DNS</option>
            <option value="proxy">Proxy</option>
            <option value="zeek">Zeek JSON</option>
            <option value="suricata">Suricata EVE</option>
            <option value="cloudtrail">AWS CloudTrail</option>
          </select>
        </label>
        <p className="text-xs text-muted-foreground">
          Normalized example:{' '}
          {`{"source":"192.0.2.1","target":"example.org","timestamp":"2026-10-01T12:00:00Z"}`}
        </p>
        <input
          aria-label="Telemetry file"
          type="file"
          disabled={busy}
          accept=".json,.jsonl,.ndjson"
          onChange={async (event) => {
            const file = event.target.files?.[0]
            if (!file) return
            if (file.size > 2 * 1024 * 1024) {
              toast.error('File exceeds 2 MiB')
              return
            }
            setBusy(true)
            try {
              setContent(await file.text())
              setPreview(null)
            } catch {
              toast.error('Could not read file')
            } finally {
              setBusy(false)
            }
          }}
        />
        <Textarea
          aria-label="Telemetry records"
          disabled={busy}
          className="min-h-40 font-mono text-xs"
          value={content}
          onChange={(e) => {
            setContent(e.target.value)
            setPreview(null)
          }}
        />
        <Button disabled={busy || !content.trim()} onClick={() => void run(false)}>
          Preview observations
        </Button>
        {preview && (
          <div className="space-y-2">
            <p>
              {preview.observation_count} relationships ready. Showing first{' '}
              {preview.preview.length}.
            </p>
            <div className="max-h-52 overflow-auto text-xs">
              {preview.preview.map((row, i) => (
                <p key={i}>
                  {row.source.label} → {row.relationship} → {row.target.label} · {row.observed_at}
                </p>
              ))}
            </div>
            <Button disabled={busy} onClick={() => void run(true)}>
              Import {preview.observation_count} observations
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
