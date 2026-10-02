import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { isValidElement, type ReactNode, type ReactElement } from 'react'
import { ChatGPTSubscription } from './chatgpt-subscription'
import { chatGPTSubscriptionService } from '@/api/chatgpt-subscription-service'

const mocks = vi.hoisted(() => ({
  query: vi.fn(),
  mutation: vi.fn(),
  invalidate: vi.fn().mockResolvedValue(undefined),
  remove: vi.fn(),
  assign: vi.fn(),
  mutations: [] as {
    mutate: ReturnType<typeof vi.fn>
    onSuccess: (result?: unknown) => unknown
  }[]
}))

vi.mock('react', async (original) => ({
  ...(await original<typeof import('react')>()),
  useState: () => ['', vi.fn()]
}))
vi.mock('@tanstack/react-query', () => ({
  useQuery: mocks.query,
  useMutation: mocks.mutation,
  useQueryClient: () => ({ invalidateQueries: mocks.invalidate, removeQueries: mocks.remove })
}))
vi.mock('@/api/chatgpt-subscription-service', () => ({
  chatGPTSubscriptionService: {
    status: vi.fn(),
    models: vi.fn(),
    connect: vi.fn(),
    settings: vi.fn(),
    disconnect: vi.fn()
  }
}))
vi.mock('@/components/ui/button', () => ({ Button: 'button' }))
vi.mock('@/components/ui/label', () => ({ Label: 'label' }))

const status = {
  mode: 'subscription',
  connected: true,
  account_label: 'Personal account',
  model: 'gpt-6.1-sol',
  reasoning_effort: 'medium',
  active_account_id: 'personal',
  accounts: [{ id: 'personal', label: 'Personal account', connected: true }]
}

type ElementProps = {
  children?: ReactNode
  id?: string
  role?: string
  disabled?: boolean
  onClick?: () => void
  onChange?: (event: { target: { value: string } }) => void
}

function elements(node: ReactNode): ReactElement<ElementProps>[] {
  if (Array.isArray(node)) return node.flatMap(elements)
  if (!isValidElement<ElementProps>(node)) return []
  return [node, ...elements(node.props.children)]
}

function text(node: ReactNode): string {
  if (Array.isArray(node)) return node.map(text).join('')
  if (isValidElement<ElementProps>(node)) return text(node.props.children)
  return typeof node === 'string' || typeof node === 'number' ? String(node) : ''
}

function control(tree: ReactNode, id: string) {
  const element = elements(tree).find((element) => element.props.id === id)
  expect(element, `Missing ${id} control`).toBeDefined()
  return element!.props
}

function button(tree: ReactNode, label: string) {
  const element = elements(tree).find(
    (element) => element.type === 'button' && text(element) === label
  )
  expect(element, `Missing ${label} button`).toBeDefined()
  return element!.props
}

function render(overrides = {}) {
  mocks.query.mockReturnValueOnce({ data: { ...status, ...overrides } })
  mocks.query.mockReturnValueOnce({
    data: { models: [{ slug: 'gpt-6.1-sol', display_name: 'GPT-6.1 Sol' }] },
    isSuccess: true
  })
  return ChatGPTSubscription()
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.mutations.length = 0
  mocks.mutation.mockImplementation((options) => {
    const mutation = { mutate: vi.fn(), onSuccess: options.onSuccess }
    mocks.mutations.push(mutation)
    return mutation
  })
  vi.stubGlobal('window', { location: { assign: mocks.assign } })
})

afterEach(() => vi.unstubAllGlobals())

describe('ChatGPT subscription controls', () => {
  it('makes separate paid API billing explicit and changes mode only on selection', () => {
    const tree = render()
    expect(text(tree)).toContain('API key — separate paid API billing')
    expect(text(tree)).toContain('never falls back to paid API requests')
    expect(text(tree)).toContain('Selected investigation context is sent to OpenAI')
    expect(mocks.mutations[1].mutate).not.toHaveBeenCalled()
    control(tree, 'copilot-billing-mode').onChange!({ target: { value: 'api' } })
    expect(mocks.mutations[1].mutate).toHaveBeenCalledWith({ mode: 'api' })
  })

  it('does not request the subscription model catalog in API mode or while disconnected', () => {
    const apiTree = render({ mode: 'api' })
    expect(mocks.query.mock.calls[1][0]).toMatchObject({
      queryFn: chatGPTSubscriptionService.models,
      enabled: false
    })
    expect(text(apiTree)).toContain('Your ChatGPT subscription does not cover these requests')
    render({ connected: false })
    expect(mocks.query.mock.calls[3][0]).toMatchObject({ enabled: false })
  })

  it('starts sign-in for the selected saved account and follows the authorization URL', () => {
    const tree = render()
    button(tree, 'Continue with ChatGPT').onClick!()
    expect(mocks.mutations[0].mutate).toHaveBeenCalledWith({ account_id: 'personal' })
    mocks.mutations[0].onSuccess({ authorization_url: 'https://auth.openai.com/authorize' })
    expect(mocks.assign).toHaveBeenCalledWith('https://auth.openai.com/authorize')
    expect(mocks.mutation.mock.calls[0][0].mutationFn).toBe(chatGPTSubscriptionService.connect)
  })

  it('starts a new account connection when no saved account is active', () => {
    const tree = render({ active_account_id: null, connected: false, accounts: [] })
    button(tree, 'Continue with ChatGPT').onClick!()
    expect(mocks.mutations[0].mutate).toHaveBeenCalledWith({ new_account: true })
  })

  it('clears the account model catalog and refreshes status after disconnecting', async () => {
    const tree = render()
    button(tree, 'Disconnect ChatGPT').onClick!()
    expect(mocks.mutations[2].mutate).toHaveBeenCalledOnce()
    expect(mocks.mutation.mock.calls[2][0].mutationFn).toBe(chatGPTSubscriptionService.disconnect)
    await mocks.mutations[2].onSuccess()
    expect(mocks.remove).toHaveBeenCalledWith({ queryKey: ['chatgpt-subscription', 'models'] })
    expect(mocks.invalidate).toHaveBeenCalledWith({ queryKey: ['chatgpt-subscription', 'status'] })
    expect(mocks.invalidate).toHaveBeenCalledWith({ queryKey: ['chatgpt-subscription', 'models'] })
  })

  it('keeps model selection at medium effort and surfaces connection errors', () => {
    mocks.mutation.mockImplementationOnce((options) => {
      const mutation = {
        mutate: vi.fn(),
        onSuccess: options.onSuccess,
        error: new Error('Sign-in failed')
      }
      mocks.mutations.push(mutation)
      return mutation
    })
    const tree = render({ error: 'Subscription eligibility could not be verified' })
    const alerts = elements(tree)
      .filter((element) => element.props.role === 'alert')
      .map(text)
    expect(alerts).toContain('Sign-in failed')
    expect(alerts).toContain('Subscription eligibility could not be verified')
    control(tree, 'copilot-subscription-model').onChange!({ target: { value: 'gpt-6.1-sol' } })
    expect(mocks.mutations[1].mutate).toHaveBeenCalledWith({
      mode: 'subscription',
      model: 'gpt-6.1-sol',
      reasoning_effort: 'medium'
    })
  })

  it('shows status loading failures and offers a retry instead of connection controls', async () => {
    mocks.query.mockReturnValueOnce({ error: new Error('Connection status unavailable') })
    mocks.query.mockReturnValueOnce({})
    const tree = ChatGPTSubscription()
    expect(text(tree)).toContain('Connection status unavailable')
    expect(text(tree)).not.toContain('Continue with ChatGPT')
    await button(tree, 'Refresh connection').onClick!()
    expect(mocks.invalidate).toHaveBeenCalledWith({ queryKey: ['chatgpt-subscription', 'status'] })
  })

  it('keeps disconnect failures visible and does not clear the catalog before success', () => {
    mocks.mutation.mockImplementation((options) => {
      const mutation = {
        mutate: vi.fn(),
        onSuccess: options.onSuccess,
        error:
          options.mutationFn === chatGPTSubscriptionService.disconnect
            ? new Error('Disconnect failed')
            : null
      }
      mocks.mutations.push(mutation)
      return mutation
    })
    const tree = render()
    expect(
      elements(tree)
        .filter((element) => element.props.role === 'alert')
        .map(text)
    ).toContain('Disconnect failed')
    expect(mocks.remove).not.toHaveBeenCalled()
    expect(mocks.invalidate).not.toHaveBeenCalled()
  })
})
