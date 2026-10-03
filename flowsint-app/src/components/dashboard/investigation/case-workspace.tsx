import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { collaborationService, type CaseItem } from '@/api/collaboration-service'
import { investigationService } from '@/api/investigation-service'
import { usePermissions } from '@/hooks/use-can'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { toast } from 'sonner'
import {
  FingerprintImportButton,
  isFingerprintFinding
} from '@/components/sketches/service-investigation'

export interface CaseTarget {
  sketch_id: string
  target_kind: 'entity' | 'relationship'
  target_id: string
}

export function CaseWorkspace({
  investigationId,
  target
}: {
  investigationId: string
  target?: CaseTarget
}) {
  const { canEdit, canManage } = usePermissions()
  const client = useQueryClient()
  const key = ['case-workspace', investigationId]
  const [page, setPage] = useState(0)
  const [activityPage, setActivityPage] = useState(0)
  const items = useQuery({
    queryKey: [...key, 'items', target, page],
    queryFn: () => collaborationService.items(investigationId, page * 100, target),
    refetchInterval: 15000
  })
  const activity = useQuery({
    queryKey: [...key, 'activity', activityPage],
    queryFn: () => collaborationService.activity(investigationId, activityPage * 100),
    refetchInterval: 15000
  })
  const collaborators = useQuery({
    queryKey: [...key, 'collaborators'],
    queryFn: () => investigationService.getCollaborators(investigationId)
  })
  const [kind, setKind] = useState<CaseItem['kind']>('question')
  const [body, setBody] = useState('')
  const [editing, setEditing] = useState<CaseItem | null>(null)
  const [busy, setBusy] = useState(false)
  const refresh = () => client.invalidateQueries({ queryKey: key })
  const create = async () => {
    setBusy(true)
    try {
      await collaborationService.create(investigationId, { kind, body, ...target })
      setBody('')
      setPage(0)
      await refresh()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Could not create item')
    } finally {
      setBusy(false)
    }
  }
  const save = async () => {
    if (!editing) return
    setBusy(true)
    try {
      await collaborationService.update(investigationId, editing, {
        body: editing.body,
        evidence: editing.evidence,
        assessment: editing.assessment,
        assignee_id: editing.assignee_id,
        status: editing.status,
        ...(canManage ? { decision: editing.decision } : {})
      })
      setEditing(null)
      await refresh()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Could not save item')
    } finally {
      setBusy(false)
    }
  }
  const visible = (items.data ?? []).filter(
    (item) =>
      !target ||
      (item.sketch_id === target.sketch_id &&
        item.target_kind === target.target_kind &&
        item.target_id === target.target_id)
  )
  return (
    <section className="space-y-4">
      <h2 className="text-lg font-semibold">
        {target ? 'Comments and findings' : 'Investigation workspace'}
      </h2>
      {items.isError && (
        <p role="alert">
          Could not load the workspace.{' '}
          <Button variant="outline" onClick={() => void refresh()}>
            Retry
          </Button>
        </p>
      )}
      {canEdit && (
        <div className="space-y-2 rounded border p-3">
          <label className="block">
            New item{' '}
            <select
              className="ml-2 rounded border bg-background p-1"
              aria-label="Item type"
              value={kind}
              onChange={(event) => setKind(event.target.value as CaseItem['kind'])}
            >
              <option value="question">Question</option>
              <option value="finding">Finding</option>
              <option value="comment">Comment</option>
            </select>
          </label>
          <Textarea
            aria-label="New item content"
            placeholder="Record a question, finding, or comment…"
            value={body}
            onChange={(event) => setBody(event.target.value)}
          />
          <Button disabled={busy || !body.trim()} onClick={() => void create()}>
            Add {kind}
          </Button>
        </div>
      )}
      {items.isLoading ? (
        <p>Loading workspace…</p>
      ) : (
        visible.length === 0 && <p className="text-muted-foreground">No items yet.</p>
      )}
      {visible.map((item) => (
        <article className="space-y-2 rounded border p-3" key={item.id}>
          <div className="text-xs text-muted-foreground">
            {item.kind} · {item.status} · review {item.decision}
            {item.assignee_id &&
              ` · assigned to ${collaborators.data?.find((c) => c.user_id === item.assignee_id)?.user?.email ?? item.assignee_id}`}
          </div>
          <p className="whitespace-pre-wrap">{item.body}</p>
          {item.target_id && (
            <p className="break-all text-xs">
              {item.target_kind}: {item.target_id}
            </p>
          )}
          {item.evidence && (
            <p className="whitespace-pre-wrap text-sm">
              <strong>Evidence:</strong> {item.evidence}
            </p>
          )}
          {item.assessment && (
            <p className="whitespace-pre-wrap text-sm">
              <strong>Assessment:</strong> {item.assessment}
            </p>
          )}
          {isFingerprintFinding(item) && <FingerprintImportButton finding={item} />}
          {canEdit && (
            <Button size="sm" variant="outline" onClick={() => setEditing({ ...item })}>
              Edit / review
            </Button>
          )}
          {editing?.id === item.id && (
            <div className="space-y-2 border-t pt-3">
              <label className="block">
                Content
                <Textarea
                  value={editing.body}
                  onChange={(event) => setEditing({ ...editing, body: event.target.value })}
                />
              </label>
              <label className="block">
                Supporting evidence (source references or observations)
                <Textarea
                  value={editing.evidence}
                  onChange={(event) => setEditing({ ...editing, evidence: event.target.value })}
                />
              </label>
              <label className="block">
                Analyst assessment
                <Textarea
                  value={editing.assessment}
                  onChange={(event) => setEditing({ ...editing, assessment: event.target.value })}
                />
              </label>
              <label className="block">
                Assignee{' '}
                <select
                  className="rounded border bg-background p-1"
                  value={editing.assignee_id ?? ''}
                  onChange={(event) =>
                    setEditing({ ...editing, assignee_id: event.target.value || null })
                  }
                >
                  <option value="">Unassigned</option>
                  {collaborators.data?.map((c) => (
                    <option key={c.user_id} value={c.user_id}>
                      {c.user?.email ?? c.user_id}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block">
                Status{' '}
                <select
                  className="rounded border bg-background p-1"
                  value={editing.status}
                  onChange={(event) =>
                    setEditing({ ...editing, status: event.target.value as CaseItem['status'] })
                  }
                >
                  <option value="open">Open</option>
                  <option value="resolved">Resolved</option>
                </select>
              </label>
              {canManage && (
                <label className="block">
                  Reviewer decision{' '}
                  <select
                    className="rounded border bg-background p-1"
                    value={editing.decision}
                    onChange={(event) =>
                      setEditing({
                        ...editing,
                        decision: event.target.value as CaseItem['decision']
                      })
                    }
                  >
                    <option value="pending">Pending</option>
                    <option value="accepted">Accepted</option>
                    <option value="rejected">Rejected</option>
                  </select>
                </label>
              )}
              <div className="flex gap-2">
                <Button disabled={busy || !editing.body.trim()} onClick={() => void save()}>
                  Save
                </Button>
                <Button variant="outline" onClick={() => setEditing(null)}>
                  Cancel
                </Button>
                <Button
                  variant="outline"
                  onClick={async () => {
                    await refresh()
                    setEditing(null)
                  }}
                >
                  Reload latest
                </Button>
              </div>
            </div>
          )}
        </article>
      ))}
      {(page > 0 || items.data?.length === 100) && (
        <div className="flex gap-2">
          <Button
            variant="outline"
            disabled={page === 0 || items.isFetching}
            onClick={() => {
              setPage(page - 1)
              setEditing(null)
            }}
          >
            Newer items
          </Button>
          <Button
            variant="outline"
            disabled={items.data?.length !== 100 || items.isFetching}
            onClick={() => {
              setPage(page + 1)
              setEditing(null)
            }}
          >
            Older items
          </Button>
        </div>
      )}
      {!target && (
        <div className="space-y-2">
          <h3 className="font-semibold">Activity</h3>
          {activity.isError && <p role="alert">Could not load activity.</p>}
          {activity.data?.length === 0 && (
            <p className="text-muted-foreground">No recorded activity yet.</p>
          )}
          {activity.data?.map((event) => (
            <details key={event.id} className="rounded border p-2 text-sm">
              <summary>
                {event.actor_name} · {event.action} · {new Date(event.created_at).toLocaleString()}
              </summary>
              <pre className="whitespace-pre-wrap break-all text-xs">
                {JSON.stringify(event.details, null, 2)}
              </pre>
            </details>
          ))}
          {(activityPage > 0 || activity.data?.length === 100) && (
            <div className="flex gap-2">
              <Button
                variant="outline"
                disabled={activityPage === 0 || activity.isFetching}
                onClick={() => setActivityPage(activityPage - 1)}
              >
                Newer activity
              </Button>
              <Button
                variant="outline"
                disabled={activity.data?.length !== 100 || activity.isFetching}
                onClick={() => setActivityPage(activityPage + 1)}
              >
                Older activity
              </Button>
            </div>
          )}
        </div>
      )}
    </section>
  )
}
