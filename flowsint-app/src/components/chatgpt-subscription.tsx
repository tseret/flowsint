import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import {
  chatGPTSubscriptionService,
  type CopilotBillingMode
} from '@/api/chatgpt-subscription-service'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'

const statusKey = ['chatgpt-subscription', 'status']
const modelsKey = ['chatgpt-subscription', 'models']
const selectClass =
  'w-full rounded-md border border-input bg-background px-3 py-2 text-sm disabled:opacity-50'

export function ChatGPTSubscription() {
  const queryClient = useQueryClient()
  const [selectedAccount, setSelectedAccount] = useState('')
  const status = useQuery({ queryKey: statusKey, queryFn: chatGPTSubscriptionService.status })
  const models = useQuery({
    queryKey: modelsKey,
    queryFn: chatGPTSubscriptionService.models,
    enabled: status.data?.connected === true && status.data.mode === 'subscription'
  })
  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: statusKey })
    await queryClient.invalidateQueries({ queryKey: modelsKey })
  }
  const connect = useMutation({
    mutationFn: chatGPTSubscriptionService.connect,
    onSuccess: ({ authorization_url }) => window.location.assign(authorization_url)
  })
  const settings = useMutation({
    mutationFn: chatGPTSubscriptionService.settings,
    onSuccess: refresh
  })
  const disconnect = useMutation({
    mutationFn: chatGPTSubscriptionService.disconnect,
    onSuccess: async () => {
      queryClient.removeQueries({ queryKey: modelsKey })
      await refresh()
    }
  })
  const busy = connect.isPending || settings.isPending || disconnect.isPending
  const error = status.error || connect.error || settings.error || disconnect.error
  const data = status.data
  const catalog = models.data?.models ?? []
  const account = selectedAccount || data?.active_account_id || 'new'

  return (
    <section className="space-y-4 border-t pt-6" aria-labelledby="copilot-connection-title">
      <div>
        <h2 id="copilot-connection-title" className="font-semibold">
          Copilot connection
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Connect your own ChatGPT account to use an eligible subscription. Plan limits and model
          access still apply. Selected investigation context is sent to OpenAI when you run the
          copilot.
        </p>
      </div>
      {status.isPending && (
        <p role="status" className="text-sm">
          Loading connection…
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error.message}
        </p>
      )}
      {data?.error && (
        <p role="alert" className="text-sm text-destructive">
          {data.error}
        </p>
      )}
      {data && (
        <>
          <div className="space-y-2">
            <Label htmlFor="copilot-billing-mode">Billing mode</Label>
            <select
              id="copilot-billing-mode"
              className={selectClass}
              value={data.mode}
              disabled={busy}
              onChange={(event) =>
                settings.mutate({ mode: event.target.value as CopilotBillingMode })
              }
            >
              <option value="subscription">ChatGPT subscription</option>
              <option value="api">API key — separate paid API billing</option>
            </select>
            <p className="text-sm text-muted-foreground">
              {data.mode === 'subscription'
                ? 'Subscription mode never falls back to paid API requests. Connect an eligible account to run the copilot.'
                : 'API mode uses your provider key in Vault and separate API credits. Your ChatGPT subscription does not cover these requests.'}
            </p>
          </div>
          <p className="text-sm">
            {data.connected
              ? `Connected: ${data.account_label || 'ChatGPT account'}`
              : 'No ChatGPT account connected.'}
          </p>
          <div className="space-y-2">
            <Label htmlFor="copilot-chatgpt-account">ChatGPT account</Label>
            <select
              id="copilot-chatgpt-account"
              className={selectClass}
              value={account}
              disabled={busy}
              onChange={(event) => setSelectedAccount(event.target.value)}
            >
              {data.accounts.map((saved) => (
                <option key={saved.id} value={saved.id}>
                  {saved.label}
                  {saved.connected ? '' : ' — disconnected'}
                </option>
              ))}
              <option value="new">Add another ChatGPT account</option>
            </select>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              onClick={() =>
                connect.mutate(account === 'new' ? { new_account: true } : { account_id: account })
              }
              disabled={busy}
            >
              {connect.isPending ? 'Connecting…' : 'Continue with ChatGPT'}
            </Button>
            {data.connected && (
              <Button variant="outline" disabled={busy} onClick={() => disconnect.mutate()}>
                {disconnect.isPending ? 'Disconnecting…' : 'Disconnect ChatGPT'}
              </Button>
            )}
          </div>
          <div className="space-y-2">
            <Label htmlFor="copilot-subscription-model">Subscription model</Label>
            {data.connected ? (
              <select
                id="copilot-subscription-model"
                className={selectClass}
                value={data.model}
                disabled={busy || models.isPending || models.isError || catalog.length === 0}
                onChange={(event) =>
                  settings.mutate({
                    mode: data.mode,
                    model: event.target.value,
                    reasoning_effort: 'medium'
                  })
                }
              >
                {!catalog.some((model) => model.slug === data.model) && (
                  <option value={data.model}>{data.model} — access not verified</option>
                )}
                {catalog.map((model) => (
                  <option key={model.slug} value={model.slug}>
                    {model.display_name}
                  </option>
                ))}
              </select>
            ) : (
              <p id="copilot-subscription-model" className="text-sm">
                {data.model} — access checked after connection
              </p>
            )}
            <p className="text-sm text-muted-foreground">
              Reasoning effort: {data.reasoning_effort}.
            </p>
            {models.error && (
              <p role="alert" className="text-sm text-destructive">
                {models.error.message}
              </p>
            )}
            {data.connected && models.isSuccess && catalog.length === 0 && (
              <p role="alert" className="text-sm text-destructive">
                No eligible subscription models are available for this account.
              </p>
            )}
          </div>
        </>
      )}
      <Button
        variant="outline"
        size="sm"
        onClick={refresh}
        disabled={busy || status.isFetching || models.isFetching}
      >
        Refresh connection
      </Button>
    </section>
  )
}
