export function warrantMatchesAction(action, warrant) {
  return Boolean(action?.warrant && warrant
    && /^[a-f0-9]{64}$/.test(warrant.contract_hash)
    && warrant.contract_hash === action.warrant.contract_hash
    && warrant.warrant_id === action.warrant.warrant_id
    && warrant.action_id === action.action_id
    && warrant.task_id === action.task_id
    && warrant.action_digest === action.approval_digest
    && warrant.proof_contract_version === action.contract_version)
}

export function warrantControls(action, review, now = Date.now()) {
  const signedWarrant = review?.warrant
  const hash = signedWarrant?.contract_hash
  const valid = warrantMatchesAction(action, signedWarrant)
    && review.signature_valid === true
    && ['configured', 'local_demo'].includes(review.signing_mode)
    && review.approval_status === action.status
    && Date.parse(signedWarrant.expires_at) > now

  return {
    canApprove: valid && action.status === 'PENDING_APPROVAL',
    canExecute: valid && action.status === 'APPROVED'
      && action.approved_warrant_hash === hash && review.approved_warrant_hash === hash,
    hash: valid ? hash : null,
  }
}
