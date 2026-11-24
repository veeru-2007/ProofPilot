const STATUS_LABELS = {
  supported: 'Supported',
  failed: 'Failed',
  contradicted: 'Contradicted',
  unverified: 'Unverified',
  missing: 'Missing',
}

export function researchExecutionStatus(report, taskStatus) {
  if (typeof report?.execution_status === 'string' && report.execution_status) {
    return report.execution_status
  }
  const taskExecution = {
    created: 'PENDING', queued: 'PENDING', planned: 'PENDING', search_pending: 'PENDING',
    searching: 'RUNNING', browsing: 'RUNNING', verifying: 'RUNNING', analyzing: 'RUNNING',
    paused: 'RUNNING', awaiting_approval: 'RUNNING', executing: 'RUNNING',
    cancelled: 'CANCELLED', blocked: 'BLOCKED', failed: 'FAILED', partial: 'PARTIAL', completed: 'COMPLETED',
  }[taskStatus]
  if (taskExecution) return taskExecution
  if (report?.status === 'BLOCKED') return 'BLOCKED'
  if (report?.status === 'FAILED') return 'FAILED'
  if (report?.research_failures?.length) return 'COMPLETED_WITH_WARNINGS'
  return report?.status === 'COMPLETED' || report?.status === 'PARTIAL' ? 'COMPLETED' : 'UNAVAILABLE'
}

export function safeExternalUrl(value) {
  if (typeof value !== 'string' || !value.trim()) return null
  try {
    const url = new URL(value)
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null
  } catch {
    return null
  }
}

export function externalDomain(value) {
  const safeUrl = safeExternalUrl(value)
  if (!safeUrl) return null
  try {
    return new URL(safeUrl).hostname
  } catch {
    return null
  }
}

export function requirementOperator(operator) {
  return ({ eq: '=', lte: '≤', gte: '≥', contains: 'contains', one_of: 'one of', exists: 'exists' })[operator] || operator || 'unspecified'
}

export function requirementExpected(requirement) {
  const value = requirement?.expected
  if (value === null || value === undefined) return 'Not specified'
  const rendered = Array.isArray(value) ? value.join(' or ') : String(value)
  return requirement?.unit ? `${rendered} ${requirement.unit}` : rendered
}

function distinct(values) {
  return [...new Set(values.filter(value => typeof value === 'string' && value.trim()).map(value => value.trim()))]
}

function evidenceForCheck(requirement, evaluation, subject, evidence, claims) {
  const explicitIds = evaluation?.evidence_ids || []
  if (explicitIds.length) {
    const ids = new Set(explicitIds)
    const referencedClaims = claims.filter(claim => ids.has(claim.id))
    return evidence.filter(item => ids.has(item.evidence_id) || (
      (item.associated_requirement_ids || []).includes(requirement.id)
      && referencedClaims.some(claim => claim.subject === item.subject && claim.field === item.field
        && claim.value === item.value && claim.evidence?.source_url === item.source_url)
    ))
  }
  return evidence.filter(item => (item.associated_requirement_ids || []).includes(requirement.id)
    && (!subject || item.subject.toLowerCase() === subject.toLowerCase()))
}

function checkStatus(evaluation, evidence) {
  if (!evidence.length) return 'missing'
  if (evidence.some(item => item.extraction_status === 'CONTRADICTED')) return 'contradicted'
  const backendStatus = evaluation?.status
  if (backendStatus === 'CONFLICTING_EVIDENCE') return 'contradicted'
  if (backendStatus === 'NOT_SATISFIED') return 'failed'
  if (backendStatus === 'SATISFIED') {
    return evidence.some(item => item.extraction_status === 'SUPPORTED') ? 'supported' : 'unverified'
  }
  if (backendStatus === 'UNVERIFIED' || backendStatus === 'INVALID_EVIDENCE') return 'unverified'
  return 'unverified'
}

function toEvidenceDetail(record) {
  const url = safeExternalUrl(record.source_url)
  return {
    id: record.evidence_id,
    subject: record.subject,
    field: record.field,
    value: record.value,
    numericValue: record.numeric_value ?? null,
    unit: record.unit || null,
    currency: record.currency || null,
    currencySymbol: record.currency_symbol || null,
    context: Array.isArray(record.context) ? record.context : [],
    extractionStatus: record.extraction_status,
    quote: record.supporting_text || '',
    quoteKind: record.extraction_status === 'SUPPORTED' ? 'Supporting source excerpt' : 'Source excerpt',
    sourceTitle: record.source_title,
    sourceUrl: url,
    sourceDomain: record.source_domain || externalDomain(record.source_url) || 'Invalid or unavailable source URL',
    observedAt: record.observed_at,
  }
}

function sourceFailureType(source) {
  if (source?.failure_type) return source.failure_type
  if (source?.blocked_reason || source?.status_code === 401 || source?.status_code === 403) return 'blocked'
  if (source?.status_code === 408 || source?.status_code === 504) return 'timeout'
  if (typeof source?.status_code === 'number' && source.status_code >= 400) return 'unavailable'
  return null
}

function makeCheck(requirement, evaluation, subject, records, claims) {
  const evidence = evidenceForCheck(requirement, evaluation, subject, records, claims)
  const observedValues = distinct([
    evaluation?.observed_value,
    ...evidence.map(item => item.value),
  ])
  const status = checkStatus(evaluation, evidence)
  return {
    key: `${requirement.id}:${subject || 'all'}`,
    requirement,
    subject,
    observed: observedValues.join(' · ') || 'Not observed',
    requiredUnit: evaluation?.required_unit ?? null,
    requiredCurrency: evaluation?.required_currency ?? null,
    observedNumericValue: evaluation?.observed_numeric_value ?? null,
    observedUnit: evaluation?.observed_unit ?? null,
    observedCurrency: evaluation?.observed_currency ?? null,
    observedCurrencySymbol: evaluation?.observed_currency_symbol ?? null,
    conversionDetails: evaluation?.conversion_details ?? null,
    status,
    statusLabel: STATUS_LABELS[status],
    reason: evaluation?.reason || (status === 'missing' ? 'No linked evidence or requirement evaluation was returned.' : 'Evidence is available, but no requirement verdict was returned.'),
    backendStatus: evaluation?.status || null,
    evidence: evidence.map(toEvidenceDetail),
  }
}

export function deriveTrustOverview({ contract, report, claims = [], sources = [] } = {}) {
  const requirements = contract?.requirements?.length ? contract.requirements : (report?.requirements || [])
  const evaluations = report?.evaluations || []
  const records = report?.evidence || []
  const claimSubjects = claims.map(item => item.subject)
  const subjects = distinct([
    ...evaluations.map(item => item.subject),
    ...records.map(item => item.subject),
    ...claimSubjects,
    ...requirements.map(item => item.subject),
  ])
  const subjectScoped = evaluations.some(item => item.subject) || subjects.length > 0
  const checks = []

  for (const requirement of requirements) {
    if (subjectScoped) {
      for (const subject of subjects) {
        if (requirement.subject && requirement.subject !== subject) continue
        const evaluation = evaluations.find(item => item.requirement_id === requirement.id && item.subject === subject)
        checks.push(makeCheck(requirement, evaluation, subject, records, claims))
      }
    } else {
      const matchingEvaluations = evaluations.filter(item => item.requirement_id === requirement.id)
      if (matchingEvaluations.length) {
        for (const evaluation of matchingEvaluations) {
          checks.push(makeCheck(requirement, evaluation, evaluation.subject || requirement.subject || null, records, claims))
        }
      } else {
        checks.push(makeCheck(requirement, null, requirement.subject || null, records, claims))
      }
    }
  }

  const counts = Object.fromEntries(Object.keys(STATUS_LABELS).map(status => [status, checks.filter(check => check.status === status).length]))
  const evidenceBackedChecks = checks.filter(check => check.evidence.length > 0).length
  const sourceDomains = distinct(records.map(item => externalDomain(item.source_url)))
  const candidateSummaries = subjects.map(subject => {
    const candidateChecks = checks.filter(check => check.subject === subject)
    let label = 'Insufficient evidence'
    if (candidateChecks.some(check => check.status === 'contradicted')) label = 'Conflicting evidence'
    else if (candidateChecks.some(check => check.status === 'failed' && check.requirement.hard_constraint)) label = 'Fails a hard constraint'
    else if (candidateChecks.some(check => check.status === 'failed')) label = 'Does not meet a requirement'
    else if (candidateChecks.length && candidateChecks.every(check => check.status === 'supported')) label = 'Meets recorded requirements'
    else if (candidateChecks.some(check => check.status === 'missing')) label = 'Missing evidence'
    else if (candidateChecks.some(check => check.status === 'unverified')) label = 'Unverified'
    return { subject, checks: candidateChecks, label }
  })

  return {
    requirements,
    checks,
    counts,
    totalRequirements: requirements.length,
    totalChecks: checks.length,
    evidenceBackedChecks,
    sourceCount: sourceDomains.length,
    sourceDomains,
    candidateSummaries,
    reportContradictions: report?.contradictions || [],
    missingInformation: report?.missing_information || [],
    hasReport: Boolean(report),
    sourceFailures: (sources.length ? sources : (report?.sources_visited || []))
      .filter(item => sourceFailureType(item))
      .map(item => ({
        url: safeExternalUrl(item.url),
        domain: item.source_domain || externalDomain(item.url) || 'Unknown domain',
        title: item.title || 'Unavailable source',
        failureType: sourceFailureType(item),
        reason: item.failure_reason || item.blocked_reason || 'Source failure reason unavailable.',
        failedAt: item.failed_at || null,
        coverageImpact: item.coverage_impact || 'unassessed',
        affectedRequirementIds: Array.isArray(item.affected_requirement_ids) ? item.affected_requirement_ids : [],
      })),
  }
}

export function summarizeClaimVerifications(verifications = []) {
  const counts = { supported: 0, contradicted: 0, unverified: 0 }
  for (const verification of Array.isArray(verifications) ? verifications : []) {
    if (verification?.status === 'supported') counts.supported += 1
    else if (verification?.status === 'contradicted') counts.contradicted += 1
    else if (verification?.status === 'unverified') counts.unverified += 1
  }
  return { ...counts, total: counts.supported + counts.contradicted + counts.unverified }
}

export function deriveActionIntegrity(action, receipt) {
  if (!action) {
    return {
      authorization: 'No action prepared',
      execution: 'Not attempted',
      verification: 'Not available',
      receipt: 'No receipt',
      approvalBinding: 'Not available',
    }
  }

  const digestMatches = Boolean(action.approved_digest && action.approved_digest === action.approval_digest)
  let authorization = 'Not approved'
  if (action.status === 'PENDING_APPROVAL') authorization = 'Awaiting approval'
  else if (action.status === 'EXPIRED') authorization = 'Expired'
  else if (action.status === 'INVALIDATED') authorization = 'Invalidated'
  else if (action.status === 'REJECTED') authorization = 'Rejected'
  else if (action.approved_digest && digestMatches) authorization = 'Approved · digest matches'
  else if (action.approved_digest) authorization = 'Digest mismatch'

  const currentReceipt = action.action_id && receipt?.action_id !== action.action_id ? null : receipt

  const execution = currentReceipt
    ? (!currentReceipt.action_attempted ? 'Not attempted' : currentReceipt.action_completed ? 'Completed' : 'Attempted · not completed')
    : action.status === 'OUTCOME_UNKNOWN' ? 'Outcome unknown · reconcile'
      : action.status === 'EXECUTING' ? 'Executing'
        : `Not recorded · ${action.status}`
  const verification = currentReceipt
    ? currentReceipt.verification_status === 'contradicted'
      ? 'Outcome contradicted'
      : `${currentReceipt.outcome_verified ? 'Verified' : 'Not verified'} · ${currentReceipt.verification_status}`
    : 'Not recorded'

  return {
    authorization,
    execution,
    verification,
    receipt: currentReceipt ? `Persisted · ${currentReceipt.receipt_id}` : 'No receipt',
    approvalBinding: digestMatches ? 'Approved digest matches prepared action' : action.approved_digest ? 'Approved digest does not match' : 'No approved digest',
  }
}
