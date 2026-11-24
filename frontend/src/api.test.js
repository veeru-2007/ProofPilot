import assert from 'node:assert/strict'
import test from 'node:test'
import { approveActionContract, createDemoScenario, createTask, getTask, listExecutionEvents, listTasks } from './api.js'

const task = { id: 'task-test', task: 'Inspect the example', status: 'queued' }

test('only requests with bodies carry a JSON Content-Type and create can reuse a request ID', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', (url, init) => Promise.resolve(
    Response.json(init.method === 'POST' ? task : []),
  ))
  await listTasks()
  await createDemoScenario()
  await createTask(task.task, null, 'request-id')
  assert.equal(fetch.mock.calls[0].arguments[1].headers.has('Content-Type'), false)
  assert.equal(fetch.mock.calls[1].arguments[1].headers.has('Content-Type'), false)
  assert.equal(fetch.mock.calls[2].arguments[1].headers.get('Content-Type'), 'application/json')
  assert.equal(JSON.parse(fetch.mock.calls[2].arguments[1].body).client_request_id, 'request-id')
})

test('HTML error responses preserve their HTTP status', async (t) => {
  t.mock.method(globalThis, 'fetch', () => Promise.resolve(new Response('<html>Error</html>', { status: 502 })))
  await assert.rejects(listTasks(), { kind: 'http', status: 502, message: 'HTTP 502 for GET /api/tasks' })
})

test('structured validation errors include the affected field', async (t) => {
  t.mock.method(globalThis, 'fetch', () => Promise.resolve(
    Response.json({ detail: [{ loc: ['body', 'task'], msg: 'Text is required' }] }, { status: 422 }),
  ))
  await assert.rejects(createTask('', null, 'request-id'), {
    kind: 'http',
    status: 422,
    message: 'task: Text is required (HTTP 422 for POST /api/tasks)',
  })
})

test('unexpected success payloads fail before reaching the UI', async (t) => {
  t.mock.method(globalThis, 'fetch', () => Promise.resolve(Response.json({ id: 'no-status' })))
  await assert.rejects(getTask('no-status'), { kind: 'invalid-response' })
})

test('request deadlines abort stalled requests', async (t) => {
  t.mock.method(globalThis, 'fetch', (_url, { signal }) => new Promise((_, reject) => {
    signal.addEventListener('abort', () => reject(signal.reason), { once: true })
  }))
  await assert.rejects(getTask(task.id, { timeoutMs: 5 }), { kind: 'timeout' })
})

test('event polling includes the persisted cursor', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', () => Promise.resolve(Response.json([])))
  await listExecutionEvents(task.id, { afterEventId: 'evt+previous' })
  const url = new URL(fetch.mock.calls[0].arguments[0])
  assert.equal(url.searchParams.get('task_id'), task.id)
  assert.equal(url.searchParams.get('after_event_id'), 'evt+previous')
})

test('approval submits the exact reviewed Warrant hash', async (t) => {
  const hash = 'a'.repeat(64)
  const action = { action_id: 'action-a', task_id: 'task-a', status: 'APPROVED', approval_digest: 'digest-a' }
  const fetch = t.mock.method(globalThis, 'fetch', () => Promise.resolve(Response.json(action)))
  await assert.rejects(approveActionContract(action.action_id), { kind: 'invalid-request' })
  assert.equal(fetch.mock.callCount(), 0)
  await approveActionContract(action.action_id, hash)
  const [url, { method, body }] = fetch.mock.calls[0].arguments
  assert.equal(new URL(url).pathname, '/api/actions/action-a/approve')
  assert.equal(method, 'POST')
  assert.deepEqual(JSON.parse(body), { warrant_hash: hash })
})
