const environment = import.meta.env ?? {}
const configuredApiUrl = environment.VITE_API_URL || 'http://127.0.0.1:8000'
export const API_URL = configuredApiUrl.replace(/\/+$/, '')
export const DEMO_TARGET_URL = `${API_URL}/demo/laptop-selection`

export class ApiError extends Error {
  constructor(message, kind, status = null) {
    super(message)
    this.name = 'ApiError'
    this.kind = kind
    this.status = status
  }
}

function errorDetail(detail) {
  if (typeof detail === 'string') return detail
  if (typeof detail?.message === 'string') return detail.message
  if (!Array.isArray(detail)) return null
  return detail.map((issue) => {
    if (typeof issue?.msg !== 'string') return ''
    const field = Array.isArray(issue.loc) ? issue.loc.filter(part => part !== 'body').join('.') : ''
    return field ? `${field}: ${issue.msg}` : issue.msg
  }).filter(Boolean).join('; ')
}

async function request(path, options = {}) {
  const { timeoutMs = 30_000, signal, headers, ...init } = options
  const method = init.method || 'GET'
  const requestHeaders = new Headers(headers)
  if (init.body != null && !requestHeaders.has('Content-Type')) {
    requestHeaders.set('Content-Type', 'application/json')
  }

  const deadline = new AbortController()
  const onAbort = () => deadline.abort(signal.reason)
  if (signal?.aborted) onAbort()
  else signal?.addEventListener('abort', onAbort, { once: true })
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    deadline.abort()
  }, timeoutMs)

  try {
    const response = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: requestHeaders,
      signal: deadline.signal,
    })
    const body = await response.text()
    let data = null
    try {
      if (body) data = JSON.parse(body)
    } catch {
      if (response.ok) {
        throw new ApiError(`The API returned invalid JSON for ${method} ${path} (HTTP ${response.status}). Check the API endpoint.`, 'invalid-response', response.status)
      }
    }
    if (!response.ok) {
      const detail = errorDetail(data?.detail)
      const fallback = `HTTP ${response.status} for ${method} ${path}`
      throw new ApiError(detail ? `${detail} (${fallback})` : fallback, 'http', response.status)
    }
    if (data === null && response.status !== 204) {
      throw new ApiError(`The API returned no JSON for ${method} ${path} (HTTP ${response.status}).`, 'invalid-response', response.status)
    }
    return data
  } catch (error) {
    if (error instanceof ApiError) throw error
    if (timedOut) throw new ApiError(`The API timed out for ${method} ${path}.`, 'timeout')
    if (signal?.aborted) throw new ApiError('The request was cancelled.', 'cancelled')
    throw new ApiError(`Could not reach the ProofPilot API at ${API_URL || 'this site'} for ${method} ${path}. Check the API connection and allowed frontend origin.`, 'network')
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', onAbort)
  }
}

function hasStringFields(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && fields.every(field => typeof value[field] === 'string')
}

async function requireResponse(path, options, validate) {
  const value = await request(path, options)
  if (!validate(value)) {
    throw new ApiError(`The API returned an unexpected response for ${path}. Check that the frontend and backend versions match.`, 'invalid-response')
  }
  return value
}

const isTask = value => hasStringFields(value, ['id', 'task', 'status'])
const isAction = value => hasStringFields(value, ['action_id', 'task_id', 'status', 'approval_digest'])
const isReceipt = value => hasStringFields(value, ['receipt_id', 'action_id', 'task_id', 'verification_status'])
const taskRequest = (path, options) => requireResponse(path, options, isTask)
const actionRequest = (path, options) => requireResponse(path, options, isAction)
const receiptRequest = (path, options) => requireResponse(path, options, isReceipt)
const arrayOf = predicate => value => Array.isArray(value) && value.every(predicate)

export const createTask = (task, budget, clientRequestId = crypto.randomUUID()) =>
  taskRequest('/api/tasks', {
    method: 'POST',
    body: JSON.stringify({
      task,
      budget: budget || null,
      context: {},
      client_request_id: clientRequestId,
    }),
  })

export const createDemoScenario = () =>
  taskRequest('/api/demo/scenario', { method: 'POST' })

export const listTasks = options => requireResponse('/api/tasks', options, arrayOf(isTask))
export const getTask = (taskId, options) => taskRequest(`/api/tasks/${taskId}`, options)
export const retryTask = taskId => taskRequest(`/api/tasks/${taskId}/retry`, { method: 'POST' })
export const cancelTask = taskId => taskRequest(`/api/tasks/${taskId}/cancel`, { method: 'POST' })
export const pauseTask = taskId => taskRequest(`/api/tasks/${taskId}/pause`, { method: 'POST' })
export const resumeTask = taskId => taskRequest(`/api/tasks/${taskId}/resume`, { method: 'POST' })
export const deleteTask = (taskId) => request(`/api/tasks/${taskId}`, { method: 'DELETE' })
export const listExecutionEvents = (taskId, { afterEventId, signal } = {}) => {
  const query = new URLSearchParams({ task_id: taskId, limit: '500' })
  if (afterEventId) query.set('after_event_id', afterEventId)
  return requireResponse(`/api/events?${query}`, { signal },
    arrayOf(event => hasStringFields(event, ['event_id', 'task_id', 'event_type', 'timestamp', 'message'])))
}
export const refineTask = (taskId, instruction) =>
  taskRequest(`/api/tasks/${taskId}/refine`, {
    method: 'POST',
    body: JSON.stringify({ instruction }),
  })
export const getTaskContract = (taskId, options) => requireResponse(
  `/api/tasks/${taskId}/contract`, options,
  value => hasStringFields(value, ['task_id']) && Array.isArray(value.requirements),
)
export const getTaskActions = (taskId, options) => requireResponse(
  `/api/tasks/${taskId}/actions`, options, arrayOf(isAction),
)
export const createActionContract = (taskId, action) =>
  actionRequest(`/api/tasks/${taskId}/actions`, {
    method: 'POST',
    body: JSON.stringify(action),
  })
export const getActionContract = (actionId, options) => actionRequest(`/api/actions/${actionId}`, options)
export const getActionWarrant = (actionId, options) => requireResponse(
  `/api/actions/${actionId}/warrant`, options,
  value => hasStringFields(value, ['approval_status', 'signing_mode'])
    && typeof value.signature_valid === 'boolean'
    && hasStringFields(value.warrant, ['warrant_id', 'action_id', 'task_id', 'contract_hash']),
)
export const getActionPolicyDecisions = (actionId, options) => requireResponse(
  `/api/actions/${actionId}/policy-decisions`, options,
  value => Array.isArray(value) && value.every(item => hasStringFields(item, [
    'decision_id', 'task_id', 'action_id', 'action_type', 'target', 'phase', 'rule_id', 'decision', 'reason', 'timestamp',
  ]) && (item.source === undefined || typeof item.source === 'string')
    && (item.source_excerpt === undefined || item.source_excerpt === null || typeof item.source_excerpt === 'string')),
)
export async function approveActionContract(actionId, warrantHash) {
  if (typeof warrantHash !== 'string' || !/^[a-f0-9]{64}$/.test(warrantHash)) {
    throw new ApiError('Review a signed Warrant before approving this action.', 'invalid-request')
  }
  return actionRequest(`/api/actions/${actionId}/approve`, {
    method: 'POST',
    body: JSON.stringify({ warrant_hash: warrantHash }),
  })
}
export const rejectActionContract = (actionId) =>
  actionRequest(`/api/actions/${actionId}/reject`, { method: 'POST' })
export const executeActionContract = (actionId) =>
  receiptRequest(`/api/actions/${actionId}/execute`, { method: 'POST', timeoutMs: 90_000 })
export const getExecutionReceipt = (actionId, options) => receiptRequest(`/api/actions/${actionId}/receipt`, options)
export const reconcileActionContract = (actionId) =>
  receiptRequest(`/api/actions/${actionId}/reconcile`, { method: 'POST' })

export const getBrowserStatus = options => requireResponse(
  '/api/browser/status', options, value => hasStringFields(value, ['label', 'status']),
)
