import assert from 'node:assert/strict'
import test from 'node:test'
import { warrantControls } from './warrant.js'

const now = Date.parse('2026-11-24T00:00:00Z')
const warrant = {
  warrant_id: 'warrant-a',
  action_id: 'action-a',
  task_id: 'task-a',
  action_digest: 'digest-a',
  contract_hash: 'a'.repeat(64),
  proof_contract_version: 1,
  expires_at: '2026-11-24T00:20:00Z',
}
const pending = {
  action_id: warrant.action_id,
  task_id: warrant.task_id,
  approval_digest: warrant.action_digest,
  contract_version: warrant.proof_contract_version,
  status: 'PENDING_APPROVAL',
  warrant,
}
const review = {
  warrant,
  approval_status: 'PENDING_APPROVAL',
  approved_warrant_hash: null,
  signature_valid: true,
  signing_mode: 'local_demo',
}

test('an exact current signed review enables only Warrant approval', () => {
  assert.deepEqual(warrantControls(pending, review, now), {
    canApprove: true, canExecute: false, hash: warrant.contract_hash,
  })
})

test('an unavailable, invalid, expired, or stale review cannot approve an action', () => {
  assert.equal(warrantControls(pending, null, now).canApprove, false)
  assert.equal(warrantControls({ ...pending, warrant: null }, review, now).canApprove, false)
  assert.equal(warrantControls(pending, { ...review, signature_valid: false }, now).canApprove, false)
  assert.equal(warrantControls(pending, { ...review, signing_mode: 'disabled' }, now).canApprove, false)
  assert.equal(warrantControls(pending, review, Date.parse(warrant.expires_at)).canApprove, false)
  assert.equal(warrantControls(pending, { ...review, approval_status: 'EXPIRED' }, now).canApprove, false)
  assert.equal(warrantControls(pending, { ...review, warrant: { ...warrant, contract_hash: 'b'.repeat(64) } }, now).canApprove, false)
  assert.equal(warrantControls(pending, { ...review, warrant: { ...warrant, action_id: 'action-b' } }, now).canApprove, false)
})

test('execution requires the stored and reviewed approved Warrant hash', () => {
  const approvedAction = { ...pending, status: 'APPROVED', approved_warrant_hash: warrant.contract_hash }
  const approvedReview = { ...review, approval_status: 'APPROVED', approved_warrant_hash: warrant.contract_hash }
  assert.equal(warrantControls(approvedAction, approvedReview, now).canExecute, true)
  assert.equal(warrantControls(approvedAction, approvedReview, now).canApprove, false)
  assert.equal(warrantControls(approvedAction, review, now).canExecute, false)
  assert.equal(warrantControls(approvedAction, { ...approvedReview, approved_warrant_hash: null }, now).canExecute, false)
  assert.equal(warrantControls({ ...approvedAction, approved_warrant_hash: null }, approvedReview, now).canExecute, false)
})
