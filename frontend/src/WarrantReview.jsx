import CopyValue from './CopyValue'
import { warrantMatchesAction } from './warrant'

const signingLabels = {
  local_demo: 'Local demo key',
  configured: 'Configured signing key',
  disabled: 'Signing disabled',
}

function listText(items) {
  return Array.isArray(items) && items.length ? items.join(', ') : 'None'
}

function displayTime(value) {
  const timestamp = new Date(value)
  return value && !Number.isNaN(timestamp.getTime()) ? timestamp.toLocaleString() : 'Unavailable'
}

function budgetLabel(budget) {
  if (budget === 1) return '1 execution per approval'
  if (typeof budget === 'number') return `${budget} executions per approval`
  return budget && typeof budget === 'object' ? JSON.stringify(budget) : 'Unavailable'
}

function AdversarialReview({ decision, originalTask, action, receipt }) {
  const verified = receipt?.execution_status === 'VERIFIED_SUCCESS' && receipt?.outcome_verified === true
  return (
    <section className="adversarial-demo-panel" data-testid="adversarial-demo-panel" aria-label="Adversarial sandbox demonstration">
      <div className="adversarial-demo-heading">
        <div><span className="eyebrow">DEFENSE EVENT · LOCAL SIMULATION</span><h4>Untrusted instruction denied</h4></div>
        <span>Deterministic harness · no LLM processed this page</span>
      </div>
      <ol className="adversarial-flow">
        <li className="adversarial-legitimate">
          <span className="adversarial-index">01</span>
          <div><strong>Legitimate task</strong><p>{originalTask || action.task_id}</p></div>
        </li>
        <li className="adversarial-untrusted">
          <span className="adversarial-index">02</span>
          <div><strong>Untrusted page instruction</strong><p>{decision.source_excerpt || 'Recorded excerpt unavailable'}</p></div>
        </li>
        <li className="adversarial-attempt">
          <span className="adversarial-index">03</span>
          <div><strong>Unauthorized attempt</strong><p>{decision.action_type} to <code>{decision.target}</code></p><small>Requested data transfer is described in the recorded page instruction above; fixture values are dummy data.</small></div>
        </li>
        <li className="adversarial-denial">
          <span className="adversarial-index">04</span>
          <div>
            <strong>Warrant policy · {decision.decision.toUpperCase()} · {decision.rule_id}</strong>
            <p>{decision.reason}</p>
            <CopyValue value={decision.decision_id} label="policy audit record ID" />
          </div>
        </li>
        <li className="adversarial-legitimate">
          <span className="adversarial-index">05</span>
          <div><strong>Legitimate workflow</strong><p>{verified ? 'The approved action completed after the denied attempt.' : `Action state: ${action.status}.`}</p></div>
        </li>
        <li className={verified ? 'adversarial-legitimate' : 'adversarial-pending'}>
          <span className="adversarial-index">06</span>
          <div>
            <strong>Independent verification</strong>
            <p>{verified ? `Independently verified · ${receipt.verification_status} readback` : receipt ? `${receipt.execution_status} · ${receipt.verification_status}` : 'No execution receipt has been recorded yet.'}</p>
            {receipt?.receipt_id && <CopyValue value={receipt.receipt_id} label="execution receipt ID" />}
          </div>
        </li>
      </ol>
      <p className="adversarial-dispatch-note">This deterministic attempt entered the policy evaluator directly; it did not issue a browser request to the external target.</p>
    </section>
  )
}

export default function WarrantReview({ action, originalTask, receipt, review, policyDecisions = [], error, onRefresh, busy }) {
  const matched = warrantMatchesAction(action, review?.warrant)
  const warrant = matched ? review.warrant : action.warrant
  const reviewError = matched
    ? review.validation_error?.message
    : review ? 'The API returned a Warrant for a different action or revision.' : null
  const steps = Array.isArray(warrant?.plan?.steps) ? warrant.plan.steps : []
  const mode = review?.signing_mode ?? warrant?.signing_mode
  const signatureLabel = error || !warrant ? 'Unavailable'
    : !review ? 'Checking with the server…'
      : matched && review.signature_valid ? 'Signature valid' : 'Signature invalid'
  const latestPolicyDecision = policyDecisions.at(-1)
  const adversarialDecision = [...policyDecisions].reverse().find(item => item.source === 'sandbox_page_injection' && item.decision === 'deny')
  const policyStatus = !latestPolicyDecision
    ? 'No policy decision recorded'
    : latestPolicyDecision.decision === 'allow'
      ? `Allowed · ${latestPolicyDecision.rule_id}`
      : `Blocked · ${latestPolicyDecision.rule_id}`

  return (
    <section className="action-review-section warrant-review" aria-label="Warrant review">
      <div className="warrant-review-heading">
        <div><span className="eyebrow">HUMAN AUTHORIZATION</span><h3>Warrant review</h3></div>
        {warrant && (
          <button type="button" className="copy-digest-button" disabled={busy} onClick={onRefresh}>
            Refresh signature check
          </button>
        )}
      </div>

      <div className="warrant-review-status">
        <div><span>Server signature</span><strong className={`warrant-signature-status ${review?.signature_valid === true ? 'valid' : review?.signature_valid === false ? 'invalid' : 'pending'}`}>{signatureLabel}</strong></div>
        <div><span>Approval</span><strong>{matched ? review.approval_status : action.status}</strong></div>
        <div><span>Policy status</span><strong>{policyStatus}</strong></div>
      </div>

      {warrant ? (
        <>
          <div className="authorization-intent">
            <span className="eyebrow">WHAT THIS BROWSER MAY DO</span>
            <p>{action.target_description}</p>
            <div className="authorization-boundaries">
              <div><span>Permitted domain</span><strong>{listText(warrant.allowed_domains)}</strong></div>
              <div><span>Allowed actions</span><strong>{listText(warrant.allowed_action_types)}</strong></div>
              <div><span>Expires</span><strong>{displayTime(warrant.expires_at)}</strong></div>
              <div><span>Approval budget</span><strong>{budgetLabel(warrant.approval_budget)}</strong></div>
              <div><span>Action Contract</span><strong>{action.action_id}</strong></div>
              <div><span>ProofContract</span><strong>Version {warrant.proof_contract_version}</strong></div>
            </div>
          </div>

          <div className="warrant-plan-section">
            <div className="warrant-plan-heading"><div><span className="eyebrow">SIGNED ACTION PLAN</span><h4>Execution steps</h4></div><span>{steps.length} authorized steps</span></div>
            <ol className="warrant-steps">
              {steps.map((step, index) => (
                <li key={step.id}>
                  <span className="plan-step-number">{String(index + 1).padStart(2, '0')}</span>
                  <div className="plan-step-content">
                    <strong>{step.description}</strong>
                    <span>{step.id} · {step.action_type} · {step.target_domain} · {step.risk_level}</span>
                    <details className="plan-step-parameters">
                      <summary>Inspect exact parameters</summary>
                      <pre aria-label={`Exact parameters for ${step.id}`}>{JSON.stringify(step.parameters, null, 2)}</pre>
                    </details>
                  </div>
                </li>
              ))}
            </ol>
          </div>

          <details className="warrant-integrity-details">
            <summary>Inspect signed bindings and cryptographic material</summary>
            <div className="warrant-binding-grid">
              <div><span>Warrant ID</span><CopyValue value={warrant.warrant_id} label="Warrant ID" /></div>
              <div><span>Warrant hash</span><CopyValue value={warrant.contract_hash} label="Warrant hash" className="warrant-contract-hash full-digest" /></div>
              <div><span>ProofContract hash</span><CopyValue value={warrant.proof_contract_hash} label="ProofContract hash" /></div>
              <div><span>Plan hash</span><CopyValue value={warrant.plan_hash} label="Plan hash" /></div>
              <div><span>Prepared ActionContract digest</span><CopyValue value={action.approval_digest} label="prepared ActionContract digest" /></div>
              {action.approved_digest && <div><span>Approved ActionContract digest</span><CopyValue value={action.approved_digest} label="approved ActionContract digest" /></div>}
            </div>
            <dl className="warrant-integrity-meta">
              <div><dt>Signing mode</dt><dd>{signingLabels[mode] || 'Unavailable'}</dd></div>
              <div><dt>Plan version</dt><dd>{warrant.plan_version}</dd></div>
              <div><dt>Warrant state</dt><dd>{warrant.status}</dd></div>
              {action.approved_warrant_hash && <div><dt>Approved Warrant hash</dt><dd>{action.approved_warrant_hash === warrant.contract_hash ? 'Matches reviewed Warrant' : 'Does not match reviewed Warrant'}</dd></div>}
            </dl>
            <details className="warrant-signature-details"><summary>View signature</summary><pre>{warrant.signature}</pre></details>
          </details>
        </>
      ) : (
        <p className="warrant-review-note">
          This action has no signed Warrant.
          {action.status === 'PENDING_APPROVAL' && ' Reject it to prepare a new action with a Warrant.'}
          {action.status === 'APPROVED' && ' Discard the legacy approval to prepare a new action with a Warrant.'}
        </p>
      )}

      {adversarialDecision && <AdversarialReview decision={adversarialDecision} originalTask={originalTask} action={action} receipt={receipt} />}

      <section className="policy-decision-list" aria-label="Backend policy decisions">
        <div className="policy-audit-heading"><div><span className="eyebrow">AUDIT TRAIL</span><h4>Policy decisions</h4></div><span>{policyDecisions.length} recorded</span></div>
        {latestPolicyDecision ? (
          <div className={`policy-latest policy-${latestPolicyDecision.decision}`}>
            <strong>{latestPolicyDecision.decision.toUpperCase()} · {latestPolicyDecision.rule_id}</strong>
            <span>{latestPolicyDecision.reason}</span>
          </div>
        ) : <p>No backend policy decisions have been recorded for this action.</p>}
        {policyDecisions.length > 0 && (
          <details className="policy-audit-details">
            <summary>Inspect all {policyDecisions.length} backend decisions</summary>
            <ol>
              {[...policyDecisions].reverse().map(item => (
                <li key={item.decision_id} className={`policy-decision policy-${item.decision}`}>
                  <strong>{item.decision.toUpperCase()} · {item.rule_id}</strong>
                  <span>{item.phase} · {item.action_type}{item.step_id ? ` · ${item.step_id}` : ''}</span>
                  <code>{item.target}</code>
                  <p>{item.reason}</p>
                  {item.warrant_id && <CopyValue value={item.warrant_id} label="decision Warrant ID" />}
                  {item.contract_hash && <CopyValue value={item.contract_hash} label="decision Warrant hash" />}
                  <time dateTime={item.timestamp}>{displayTime(item.timestamp)}</time>
                </li>
              ))}
            </ol>
          </details>
        )}
      </section>

      {(error || reviewError) && <p className="warrant-review-note" role="alert">{error || reviewError}</p>}
      {matched && review.approval_status !== action.status && (
        <p className="warrant-review-note" role="alert">The approval status changed. Refresh the Warrant check before proceeding.</p>
      )}
    </section>
  )
}
