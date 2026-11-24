import { requirementExpected, requirementOperator } from './trust'

function actionList(items) {
  return Array.isArray(items) && items.length ? items.join(', ') : 'None recorded'
}

export default function ProofContractOverview({ contract, taskStatus }) {
  return (
    <section className="proof-contract-overview" aria-label="Proof Contract">
      <div className="section-heading">
        <div><span className="eyebrow">TASK SCOPE</span><h2>Proof Contract</h2></div>
        {contract && <span className="contract-version">Version {contract.version}</span>}
      </div>
      {!contract ? (
        <div className="contract-empty">
          <strong>{taskStatus ? 'Contract not available yet' : 'No task selected'}</strong>
          <span>{taskStatus ? 'The task contract will appear when the API returns it.' : 'Create a task to define its goal and requirements.'}</span>
        </div>
      ) : (
        <>
          <div className="contract-goal"><span>GOAL</span><p>{contract.goal}</p></div>
          <div className="contract-requirements">
            <div className="contract-subheading"><h3>Requirements</h3><span>{contract.requirements.length} in contract</span></div>
            <ul>
              {contract.requirements.map(item => (
                <li key={item.id}>
                  <span className="contract-requirement-id">{item.id}</span>
                  <div><strong>{item.label}</strong><span>{item.field} {requirementOperator(item.operator)} {requirementExpected(item)}</span></div>
                  <span className={`requirement-kind ${item.hard_constraint ? 'hard' : 'soft'}`}>{item.hard_constraint ? 'Hard' : 'Preference'}</span>
                </li>
              ))}
            </ul>
          </div>
          <details className="contract-boundaries">
            <summary>Inspect contract boundaries</summary>
            <dl>
              <div><dt>Allowed actions</dt><dd>{actionList(contract.allowed_actions)}</dd></div>
              <div><dt>Approval required for</dt><dd>{actionList(contract.requires_approval_for)}</dd></div>
              <div><dt>Prohibited actions</dt><dd>{actionList(contract.prohibited_actions)}</dd></div>
              <div><dt>Allowed domains</dt><dd>{actionList(contract.allowed_domains)}</dd></div>
              <div><dt>Completion criteria</dt><dd>{actionList(contract.completion_criteria)}</dd></div>
            </dl>
            {contract.ambiguities?.length > 0 && (
              <div className="contract-ambiguities"><strong>Open ambiguities</strong><ul>{contract.ambiguities.map(item => <li key={item.id}>{item.clarification_question} · {item.blocking_stage}</li>)}</ul></div>
            )}
          </details>
        </>
      )}
    </section>
  )
}
