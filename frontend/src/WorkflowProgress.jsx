const ACTION_COMPLETE = new Set(['EXECUTING', 'OUTCOME_UNKNOWN', 'VERIFIED_SUCCESS', 'VERIFIED_FAILURE'])

function makeSteps({ task, proofContract, action, decisions, receipt }) {
  const isDemo = task?.task?.startsWith('SIMULATED DEMO:') === true
  const planSteps = action?.warrant?.plan?.steps
  const hasPlan = Array.isArray(planSteps) && planSteps.length > 0
  const hasApproval = action?.status === 'APPROVED' || ACTION_COMPLETE.has(action?.status)
  const attempted = receipt?.action_attempted === true
  const completed = receipt?.action_completed === true
  const adversarialDecision = decisions.find(item => item.source === 'sandbox_page_injection' && item.decision === 'deny')
  const hasPolicyDecision = decisions.some(item => item.phase === 'execution')
  const verified = receipt?.outcome_verified === true && receipt?.execution_status === 'VERIFIED_SUCCESS'

  return [
    {
      id: 'plan',
      label: 'Plan',
      done: Boolean(proofContract && (task?.status === 'completed' || hasPlan)),
      detail: hasPlan ? `${planSteps.length} signed steps` : proofContract ? `ProofContract v${proofContract.version}` : 'Research and scope',
    },
    {
      id: 'authorize',
      label: 'Authorize',
      done: hasApproval,
      current: action?.status === 'PENDING_APPROVAL',
      detail: action?.status === 'PENDING_APPROVAL'
        ? 'Warrant ready for review'
        : action?.status === 'APPROVED' || ACTION_COMPLETE.has(action?.status)
          ? `Approval ${action.status.toLowerCase().replaceAll('_', ' ')}`
          : 'Human review required',
    },
    {
      id: 'execute',
      label: 'Execute',
      done: completed,
      current: action?.status === 'EXECUTING' || (attempted && !completed),
      detail: completed ? 'Approved action completed' : attempted ? 'Action attempted' : action?.status === 'EXECUTING' ? 'Execution in progress' : 'Waiting for approval',
    },
    {
      id: 'defend',
      label: 'Defend',
      done: isDemo ? Boolean(adversarialDecision) : hasPolicyDecision,
      denied: Boolean(adversarialDecision),
      detail: adversarialDecision
        ? `${adversarialDecision.rule_id} · denied`
        : hasPolicyDecision ? 'Execution policy checks recorded' : 'Warrant checks run at execution',
    },
    {
      id: 'verify',
      label: 'Verify',
      done: verified,
      detail: verified ? 'Independent readback passed' : receipt?.verification_status || 'Outcome not verified',
    },
    {
      id: 'prove',
      label: 'Prove',
      done: Boolean(receipt?.receipt_id),
      detail: receipt?.receipt_id ? 'Persistent receipt available' : 'Receipt pending',
    },
  ]
}

export default function WorkflowProgress({ task, proofContract, action, decisions = [], receipt }) {
  const steps = makeSteps({ task, proofContract, action, decisions, receipt })
  const currentIndex = steps.findIndex(step => !step.done)

  return (
    <section className="workflow-progress" aria-label="Workflow progress">
      <div className="workflow-progress-heading">
        <div><span className="eyebrow">CONTROL SEQUENCE</span><h2>Plan <i>→</i> Authorize <i>→</i> Execute <i>→</i> Defend <i>→</i> Verify <i>→</i> Prove</h2></div>
        <span className="workflow-caption">Progress reflects persisted task, action, policy and receipt state.</span>
      </div>
      <ol className="workflow-steps">
        {steps.map((step, index) => {
          const state = step.denied ? 'denied' : step.done ? 'complete' : step.current || index === currentIndex ? 'current' : 'pending'
          return (
            <li key={step.id} className={`workflow-step workflow-${state}`} data-state={state}>
              <div className="workflow-step-marker" aria-hidden="true">{step.done && !step.denied ? '✓' : String(index + 1).padStart(2, '0')}</div>
              <div className="workflow-step-copy"><strong>{step.label}</strong><span>{step.detail}</span></div>
              {index < steps.length - 1 && <span className="workflow-connector" aria-hidden="true" />}
            </li>
          )
        })}
      </ol>
    </section>
  )
}
