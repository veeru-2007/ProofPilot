import test from 'node:test'
import assert from 'node:assert/strict'
import {
  deriveActionIntegrity,
  deriveTrustOverview,
  externalDomain,
  researchExecutionStatus,
  safeExternalUrl,
  summarizeClaimVerifications,
} from './trust.js'

test('research process status stays separate from requirement completeness', () => {
  assert.equal(researchExecutionStatus({ status: 'PARTIAL', execution_status: 'COMPLETED_WITH_WARNINGS' }), 'COMPLETED_WITH_WARNINGS')
  assert.equal(researchExecutionStatus({ status: 'PARTIAL', research_failures: [] }), 'COMPLETED')
  assert.equal(researchExecutionStatus({ status: 'FAILED' }), 'FAILED')
  assert.equal(researchExecutionStatus(null, 'searching'), 'RUNNING')
  assert.equal(researchExecutionStatus(null, 'cancelled'), 'CANCELLED')
})

const requirements = [
  { id: 'price_limit', label: 'Maximum price', field: 'price', operator: 'lte', expected: 1500, unit: 'GBP', hard_constraint: true },
  { id: 'ram_minimum', label: 'Minimum RAM', field: 'ram', operator: 'gte', expected: 32, unit: 'GB', hard_constraint: true },
]

function evidence(evidenceId, subject, field, value, extractionStatus, associatedRequirementIds) {
  return {
    evidence_id: evidenceId,
    subject,
    field,
    value,
    source_url: `https://${evidenceId}.example.test/spec`,
    source_title: `${subject} specifications`,
    supporting_text: `${field} is ${value}`,
    observed_at: '2026-11-24T08:00:00Z',
    associated_requirement_ids: associatedRequirementIds,
    extraction_status: extractionStatus,
  }
}

test('metrics keep supported, failed, contradictory, unverified, and missing checks distinct', () => {
  const report = {
    evaluations: [
      { requirement_id: 'price_limit', subject: 'Dell G16', status: 'SATISFIED', observed_value: '1449', evidence_ids: ['dell-price'], reason: 'Below the limit.' },
      { requirement_id: 'ram_minimum', subject: 'Dell G16', status: 'SATISFIED', observed_value: '32', evidence_ids: ['dell-ram'], reason: 'Meets the minimum.' },
      { requirement_id: 'ram_minimum', subject: 'Lenovo LOQ 16', status: 'NOT_SATISFIED', observed_value: '16', evidence_ids: ['lenovo-ram'], reason: 'Below the minimum.' },
      { requirement_id: 'price_limit', subject: 'MSI Katana 15', status: 'CONFLICTING_EVIDENCE', observed_value: '1399 / 1599', evidence_ids: ['msi-price-a', 'msi-price-b'], reason: 'Sources disagree.' },
      { requirement_id: 'ram_minimum', subject: 'Unverified model', status: 'UNVERIFIED', observed_value: null, evidence_ids: ['unverified-ram'], reason: 'The value is unclear.' },
    ],
    evidence: [
      evidence('dell-price', 'Dell G16', 'price', '1449', 'SUPPORTED', ['price_limit']),
      evidence('dell-ram', 'Dell G16', 'ram', '32', 'SUPPORTED', ['ram_minimum']),
      evidence('lenovo-ram', 'Lenovo LOQ 16', 'ram', '16', 'SUPPORTED', ['ram_minimum']),
      evidence('msi-price-a', 'MSI Katana 15', 'price', '1399', 'SUPPORTED', ['price_limit']),
      evidence('msi-price-b', 'MSI Katana 15', 'price', '1599', 'CONTRADICTED', ['price_limit']),
      evidence('unverified-ram', 'Unverified model', 'ram', 'unclear', 'UNVERIFIED', ['ram_minimum']),
    ],
  }

  const overview = deriveTrustOverview({ contract: { requirements }, report })
  assert.equal(overview.totalRequirements, 2)
  assert.equal(overview.totalChecks, 8)
  assert.equal(overview.evidenceBackedChecks, 5)
  assert.equal(overview.counts.supported, 2)
  assert.equal(overview.counts.failed, 1)
  assert.equal(overview.counts.contradicted, 1)
  assert.equal(overview.counts.unverified, 1)
  assert.equal(overview.counts.missing, 3)
  assert.equal(overview.candidateSummaries.find(item => item.subject === 'Dell G16').label, 'Meets recorded requirements')
  assert.equal(overview.candidateSummaries.find(item => item.subject === 'Lenovo LOQ 16').label, 'Fails a hard constraint')
  assert.equal(overview.candidateSummaries.find(item => item.subject === 'MSI Katana 15').label, 'Conflicting evidence')
})

test('a check without linked evidence is missing and cannot be called supported', () => {
  const overview = deriveTrustOverview({
    contract: { requirements: [requirements[0]] },
    report: {
      evaluations: [{ requirement_id: 'price_limit', subject: 'Unknown model', status: 'SATISFIED', evidence_ids: [], reason: 'Backend verdict.' }],
      evidence: [],
    },
  })
  assert.equal(overview.checks[0].status, 'missing')
  assert.equal(overview.counts.supported, 0)
  assert.equal(overview.counts.missing, 1)
})

test('claim references resolve to their associated evidence record when IDs differ', () => {
  const sourceUrl = 'https://shop.example.test/product'
  const overview = deriveTrustOverview({
    contract: { requirements: [requirements[0]] },
    report: {
      evaluations: [{ requirement_id: 'price_limit', subject: 'Laptop A', status: 'SATISFIED', observed_value: '1400 GBP', evidence_ids: ['claim-1'], reason: 'Within the limit.' }],
      evidence: [{
        evidence_id: 'record-1',
        subject: 'Laptop A',
        field: 'Price',
        value: '1400 GBP',
        source_url: sourceUrl,
        source_title: 'Product page',
        supporting_text: 'Price: GBP 1400',
        observed_at: '2026-11-24T08:00:00Z',
        associated_requirement_ids: ['price_limit'],
        extraction_status: 'SUPPORTED',
      }],
    },
    claims: [{ id: 'claim-1', subject: 'Laptop A', field: 'Price', value: '1400 GBP', evidence: { source_url: sourceUrl, quote: 'A different claim quote.' } }],
  })
  assert.equal(overview.checks[0].status, 'supported')
  assert.equal(overview.checks[0].evidence[0].id, 'record-1')
  assert.equal(overview.checks[0].evidence[0].quote, 'Price: GBP 1400')
})

test('an evidence record keeps its own source and excerpt when a similar claim is available', () => {
  const record = evidence('record-1', 'Laptop A', 'price', '1400', 'UNVERIFIED', ['price_limit'])
  const report = {
    evaluations: [
      { requirement_id: 'price_limit', subject: 'Laptop A', status: 'UNVERIFIED', evidence_ids: [record.evidence_id] },
    ],
    evidence: [record],
  }
  const claims = [{
    id: 'other-claim',
    subject: record.subject,
    field: record.field,
    value: record.value,
    evidence: { source_url: 'https://other.example.test/product', quote: 'Unrelated quote' },
  }]
  const detail = deriveTrustOverview({ contract: { requirements: [requirements[0]] }, report, claims }).checks[0].evidence[0]
  assert.equal(detail.quote, record.supporting_text)
  assert.equal(detail.sourceUrl, record.source_url)
  assert.equal(detail.quoteKind, 'Source excerpt')
})

test('source links only allow HTTP and HTTPS URLs', () => {
  assert.equal(safeExternalUrl('https://example.test/source'), 'https://example.test/source')
  assert.equal(externalDomain('http://shop.example.test/item'), 'shop.example.test')
  assert.equal(safeExternalUrl('javascript:alert(1)'), null)
  assert.equal(safeExternalUrl('data:text/html,unsafe'), null)
  assert.equal(safeExternalUrl('not a URL'), null)
})

test('claim support stays separate from unresolved requirement currency and source coverage', () => {
  const sourceUrl = 'https://shop.example.test/product'
  const report = {
    requirements: [requirements[0]],
    evaluations: [{
      requirement_id: 'price_limit',
      subject: 'Laptop A',
      status: 'UNVERIFIED',
      required_currency: 'GBP',
      observed_currency: 'USD',
      observed_numeric_value: 1200,
      observed_currency_symbol: 'USD',
      evidence_ids: ['claim-price'],
      reason: 'The observed price is USD, but the requirement is GBP; no conversion was applied.',
    }],
    evidence: [{
      ...evidence('claim-price', 'Laptop A', 'Price', 'USD 1,200', 'SUPPORTED', ['price_limit']),
      source_url: sourceUrl,
      source_domain: 'shop.example.test',
      numeric_value: 1200,
      currency: 'USD',
      currency_symbol: 'USD',
      context: ['advertised_price'],
    }],
  }
  const overview = deriveTrustOverview({
    contract: { requirements: [requirements[0]] },
    report,
    sources: [{
      url: 'https://blocked.example.test/product',
      title: 'Protected listing',
      status_code: 403,
      failure_type: 'blocked',
      failure_reason: 'The source denied access.',
      failed_at: '2026-11-24T08:00:00Z',
      coverage_impact: 'unresolved',
      affected_requirement_ids: ['price_limit'],
    }],
  })
  assert.equal(overview.checks[0].status, 'unverified')
  assert.equal(overview.checks[0].backendStatus, 'UNVERIFIED')
  assert.equal(overview.checks[0].requiredCurrency, 'GBP')
  assert.equal(overview.checks[0].observedCurrency, 'USD')
  assert.equal(overview.checks[0].observedNumericValue, 1200)
  assert.deepEqual(overview.checks[0].evidence[0].context, ['advertised_price'])
  assert.equal(overview.sourceFailures[0].coverageImpact, 'unresolved')
  assert.deepEqual(overview.sourceFailures[0].affectedRequirementIds, ['price_limit'])

  const claims = summarizeClaimVerifications([
    { status: 'supported' }, { status: 'contradicted' }, { status: 'unverified' },
  ])
  assert.deepEqual(claims, { supported: 1, contradicted: 1, unverified: 1, total: 3 })
})

test('action integrity separates approval, execution, and verification', () => {
  const action = { status: 'APPROVED', approval_digest: 'same', approved_digest: 'same' }
  const uncertainReceipt = {
    receipt_id: 'receipt-1',
    action_attempted: true,
    action_completed: true,
    outcome_verified: false,
    verification_status: 'UNVERIFIED',
  }
  const integrity = deriveActionIntegrity(action, uncertainReceipt)
  assert.equal(integrity.authorization, 'Approved · digest matches')
  assert.equal(integrity.execution, 'Completed')
  assert.equal(integrity.verification, 'Not verified · UNVERIFIED')
  assert.equal(integrity.receipt, 'Persisted · receipt-1')
  assert.equal(deriveActionIntegrity({ ...action, approved_digest: 'different' }, null).authorization, 'Digest mismatch')
})

test('historical approval and another action receipt do not imply authorization or verification', () => {
  const action = { action_id: 'action-a', status: 'EXPIRED', approval_digest: 'same', approved_digest: 'same' }
  const receipt = { action_id: 'action-b', receipt_id: 'receipt-b', outcome_verified: true }
  const integrity = deriveActionIntegrity(action, receipt)
  assert.equal(integrity.authorization, 'Expired')
  assert.equal(integrity.verification, 'Not recorded')
  assert.equal(integrity.receipt, 'No receipt')
})
