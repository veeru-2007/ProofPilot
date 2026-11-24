import { useCallback, useEffect, useRef, useState } from 'react'
import {
  approveActionContract,
  API_URL,
  createDemoScenario,
  createTask,
  createActionContract,
  cancelTask,
  deleteTask,
  DEMO_TARGET_URL,
  executeActionContract,
  getActionContract,
  getActionPolicyDecisions,
  getActionWarrant,
  getExecutionReceipt,
  getTask,
  getTaskActions,
  getTaskContract,
  getBrowserStatus,
  listTasks,
  listExecutionEvents,
  pauseTask,
  reconcileActionContract,
  rejectActionContract,
  resumeTask,
  retryTask,
} from './api'
import {
  deriveActionIntegrity,
  deriveTrustOverview,
  externalDomain,
  researchExecutionStatus,
  requirementExpected,
  requirementOperator,
  safeExternalUrl,
  summarizeClaimVerifications,
} from './trust'
import WarrantReview from './WarrantReview'
import CopyValue from './CopyValue'
import ProofContractOverview from './ProofContractOverview'
import WorkflowProgress from './WorkflowProgress'
import { warrantControls } from './warrant'

const Icon = ({ name, size = 18 }) => {
  const paths = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
    plus: <><path d="M12 5v14M5 12h14"/></>,
    history: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-1.8 1.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-2.6V20a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L7.6 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 6.4 14h-.2v-2.6h.2A1.7 1.7 0 0 0 8 10.4a1.7 1.7 0 0 0-.3-1.9L7.6 8l1.8-1.8.1.1a1.7 1.7 0 0 0 1.9.3A1.7 1.7 0 0 0 12.4 5v-.2H15V5a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 8l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2V14H21a1.7 1.7 0 0 0-1.6 1z"/></>,
    search: <><circle cx="11" cy="11" r="6"/><path d="M16 16l4 4"/></>,
    globe: <><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.3 3 14.7 0 18M12 3c-3 3.3-3 14.7 0 18"/></>,
    external: <><path d="M14 4h6v6M20 4l-9 9"/><path d="M18 13v6H5V6h6"/></>,
    check: <path d="M5 12l4 4L19 6"/>,
    x: <><path d="M6 6l12 12M18 6L6 18"/></>,
    shield: <><path d="M12 3l7 3v5c0 4.6-2.9 7.8-7 10-4.1-2.2-7-5.4-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/></>,
    send: <><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></>,
    chevron: <path d="M8 10l4 4 4-4"/>,
    file: <><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/></>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
  }
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>
}

function StatusBadge({ status }) {
  const key = status.toLowerCase()
  return <span className={`status-badge ${key}`}><span className="status-dot" />{status}</span>
}

function formatTimestamp(value) {
  if (!value) return 'Timestamp unavailable'
  const timestamp = new Date(value)
  return Number.isNaN(timestamp.getTime()) ? String(value) : timestamp.toLocaleString()
}

function trustStatusClass(status) {
  return String(status || '').toLowerCase().replaceAll('_', '-')
}

function deriveResearchSourceSummary(taskData) {
  const report = taskData?.research_report
  const summary = report?.source_summary || {}
  const attempts = Array.isArray(report?.source_attempts) ? report.source_attempts : []
  const pageAttempts = attempts.filter(item => item.source_type === 'page')
  const searchAttempts = attempts.filter(item => item.source_type === 'search')
  const sources = Array.isArray(report?.sources_visited) && report.sources_visited.length
    ? report.sources_visited
    : (Array.isArray(taskData?.sources) ? taskData.sources : [])
  if (!pageAttempts.length && !sources.length) return summary

  const sourceKey = item => {
    const value = item?.source_url || item?.url || item?.source_identifier
    if (typeof value !== 'string' || !value.trim()) return null
    try {
      const parsed = new URL(value)
      const path = parsed.pathname.replace(/\/$/, '')
      return `${parsed.protocol}//${parsed.host.toLowerCase()}${path}${parsed.search}`
    } catch {
      return value.trim()
    }
  }
  const latestBySource = new Map()
  const attempted = new Set()
  const accessed = new Set()
  const failed = new Set()
  const usableEvidence = new Set()
  if (!sources.length) {
    for (const attempt of pageAttempts) {
      const key = attempt.source_identifier || sourceKey(attempt)
      if (!key) continue
      attempted.add(key)
      if (attempt.retrieval_succeeded) accessed.add(key)
      if (attempt.evidence_extracted && attempt.affected_requirement_ids?.length) usableEvidence.add(key)
      const previous = latestBySource.get(key)
      if (!previous || Number(attempt.attempt_number) >= Number(previous.attempt_number)) latestBySource.set(key, attempt)
    }
    for (const [key, attempt] of latestBySource) {
      if (attempt.failure_category && attempt.failure_category !== 'SUCCESS') failed.add(key)
    }
  } else {
    for (const attempt of pageAttempts) {
      if (attempt.evidence_extracted && attempt.affected_requirement_ids?.length) {
        const key = attempt.source_identifier || sourceKey(attempt)
        if (key) usableEvidence.add(key)
      }
    }
  }
  for (const source of sources) {
    const key = sourceKey(source)
    if (!key) continue
    attempted.add(key)
    if (source.failure_type || source.blocked_reason || (Number(source.status_code) >= 400)) failed.add(key)
    else accessed.add(key)
  }
  const recoveryOperations = new Set(attempts.map(item => item.recovery_operation_id).filter(Boolean))
  const evaluations = Array.isArray(report?.evaluations) ? report.evaluations : []
  return {
    ...summary,
    sources_discovered: Math.max(Number(summary.sources_discovered) || 0, attempted.size),
    source_attempts: pageAttempts.length || Number(summary.source_attempts) || 0,
    sources_attempted: attempted.size,
    sources_accessed: accessed.size,
    sources_with_usable_evidence: pageAttempts.length ? usableEvidence.size : (Number(summary.sources_with_usable_evidence) || 0),
    sources_failed: failed.size,
    search_requests: searchAttempts.length || Number(summary.search_requests) || 0,
    search_failures: searchAttempts.length
      ? searchAttempts.filter(item => item.failure_category !== 'SUCCESS').length
      : (Number(summary.search_failures) || 0),
    recovery_attempts: recoveryOperations.size || Number(summary.recovery_attempts) || 0,
    requirements_supported: evaluations.length
      ? evaluations.filter(item => item.status === 'SATISFIED').length
      : (Number(summary.requirements_supported) || 0),
    requirements_contradicted: evaluations.length
      ? evaluations.filter(item => ['NOT_SATISFIED', 'CONFLICTING_EVIDENCE'].includes(item.status)).length
      : (Number(summary.requirements_contradicted) || 0),
    requirements_unresolved: evaluations.length
      ? evaluations.filter(item => ['UNVERIFIED', 'INVALID_EVIDENCE'].includes(item.status)).length
      : (Number(summary.requirements_unresolved) || 0),
  }
}

function researchRecoveryMessage(taskData) {
  const report = taskData?.research_report
  if (!report) return taskData?.partial_failures?.join(' ') || 'Research details are not available yet.'
  const summary = deriveResearchSourceSummary(taskData)
  const attempts = Array.isArray(report.source_attempts) ? report.source_attempts : []
  const sources = Array.isArray(report.sources_visited) && report.sources_visited.length
    ? report.sources_visited
    : (Array.isArray(taskData?.sources) ? taskData.sources : [])
  const deniedKeys = new Set(attempts
    .filter(item => ['ACCESS_DENIED', 'AUTH_REQUIRED', 'ROBOTS_OR_RESTRICTION'].includes(item.failure_category))
    .map(item => item.source_url || item.source_identifier))
  for (const source of sources) {
    const reason = `${source.failure_reason || ''} ${source.blocked_reason || ''}`
    if ((source.failure_type === 'blocked' || source.status_code === 401 || source.status_code === 403)
      && /access denied|access restriction|authentication|login required|crawling restriction/i.test(reason)) {
      deniedKeys.add(source.url || source.source_domain)
    }
  }
  const denied = deniedKeys.size
  const unresolved = Number.isFinite(summary.requirements_unresolved)
    ? summary.requirements_unresolved
    : (report.evaluations || []).filter(item => ['UNVERIFIED', 'CONFLICTING_EVIDENCE', 'INVALID_EVIDENCE'].includes(item.status)).length
  const recovered = attempts.some(item => item.recovery_attempt_status === 'RECOVERED')
  const recoveryAttempted = (summary.recovery_attempts || 0) > 0 || attempts.some(item => item.recovery_operation_id)
  const accessed = summary.sources_accessed || 0
  const failed = (summary.sources_failed || 0) + (summary.search_failures || 0)

  if (denied && recovered) {
    return `${denied} source${denied === 1 ? '' : 's'} denied access. ProofPilot continued with public alternatives and recovered evidence${unresolved ? `; ${unresolved} requirement${unresolved === 1 ? '' : 's'} remain unresolved` : ''}.`
  }
  if (denied && recoveryAttempted) {
    return `${denied} source${denied === 1 ? '' : 's'} denied access. ProofPilot searched for alternative public sources; ${unresolved} requirement${unresolved === 1 ? '' : 's'} remain unresolved.`
  }
  if (denied) {
    return `${denied} source${denied === 1 ? '' : 's'} denied access. ProofPilot will not bypass the restriction; retry research to search public alternatives.`
  }
  if (taskData?.status === 'partial' || taskData?.status === 'failed') {
    return `Research is incomplete. ${accessed} source${accessed === 1 ? '' : 's'} were accessible, ${failed} failed, and ${unresolved} requirement${unresolved === 1 ? '' : 's'} remain unresolved.`
  }
  return taskData?.progress || 'Research completed with source details available below.'
}

const taskPollingStops = new Set(['completed', 'partial', 'failed', 'blocked', 'cancelled'])
const retryableResearchStatuses = new Set(['partial', 'failed'])
const executionEventTypes = [
  'task_created', 'task_queued', 'task_started', 'task_paused', 'task_resumed',
  'task_cancelled', 'task_completed', 'task_failed', 'search_started', 'search_completed',
  'source_discovered', 'source_opened', 'source_failed', 'source_attempt_recorded',
  'search_attempt_recorded', 'source_rejected_by_contract', 'requirement_recovery_started',
  'requirement_recovery_completed', 'requirement_recovery_limited', 'claim_extracted',
  'source_coverage_assessed', 'claim_verification_summary', 'evidence_attached',
  'contradiction_detected', 'analysis_started', 'report_generated',
]
const demoActionBlockingStates = new Set([
  'PREPARED', 'PENDING_APPROVAL', 'APPROVED', 'EXECUTING', 'OUTCOME_UNKNOWN', 'VERIFIED_SUCCESS',
])

function App() {
  const [task, setTask] = useState('Find 3 laptops for machine learning under £1,500')
  const [activeNav, setActiveNav] = useState('Overview')
  const [selectedClaimId, setSelectedClaimId] = useState(null)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [taskId, setTaskId] = useState(null)
  const [taskData, setTaskData] = useState(null)
  const [tasks, setTasks] = useState([])
  const [tasksLoading, setTasksLoading] = useState(false)
  const [tasksError, setTasksError] = useState('')
  const [creating, setCreating] = useState(false)
  const [executionEvents, setExecutionEvents] = useState([])
  const [eventConnection, setEventConnection] = useState('disconnected')
  const [claimFilter, setClaimFilter] = useState('all')
  const [proofContract, setProofContract] = useState(null)
  const [actionContract, setActionContract] = useState(null)
  const [loadedWarrantReview, setLoadedWarrantReview] = useState(null)
  const [warrantRefresh, setWarrantRefresh] = useState(0)
  const [loadedReceipt, setExecutionReceipt] = useState(null)
  const [copiedDigest, setCopiedDigest] = useState(null)
  const [actionBusy, setActionBusy] = useState(false)
  const [actionForm, setActionForm] = useState({ laptop: '', budget: '', ram: '', gpu: '', reason: 'Controlled demo request for the selected product.' })
  const [error, setError] = useState('')
  const [taskSyncError, setTaskSyncError] = useState('')
  const [browserStatus, setBrowserStatus] = useState({ label: 'Browser status unavailable', status: 'loading' })
  const activeTaskIdRef = useRef(null)
  const taskSelectionSequenceRef = useRef(0)
  const taskSelectionRequestRef = useRef(null)
  const taskListRequestSequenceRef = useRef(0)
  const taskReadGenerationRef = useRef(0)
  const actionContextGenerationRef = useRef(0)
  const refreshExecutionEventsRef = useRef(null)
  const pendingTaskRequestRef = useRef(null)
  const pendingControlsRef = useRef(new Set())

  const verificationByClaim = new Map((Array.isArray(taskData?.verifications) ? taskData.verifications : []).map(item => [item.claim_id, item]))
  const displayClaims = (Array.isArray(taskData?.claims) ? taskData.claims : []).filter(claim => claim?.evidence).map(claim => {
    const verification = verificationByClaim.get(claim.id)
    const status = verification?.status || claim.verification_status || 'unverified'
    return {
      id: claim.id,
      category: claim.subject,
      fact: `${claim.field}: ${claim.value}`,
      detail: verification?.reason || claim.verification_reason,
      evidence: claim.evidence.quote,
      context: claim.context || [],
      numericValue: claim.numeric_value ?? null,
      unit: claim.unit || null,
      currency: claim.currency || null,
      sourceDomain: claim.source_domain || externalDomain(claim.evidence.source_url),
      source: externalDomain(claim.evidence.source_url) || 'Invalid or unavailable source URL',
      url: safeExternalUrl(claim.evidence.source_url),
      timestamp: claim.evidence.timestamp,
      status: status.charAt(0).toUpperCase() + status.slice(1),
    }
  })
  const filteredClaims = displayClaims.filter(claim => {
    if (claimFilter === 'verified') return claim.status === 'Supported'
    if (claimFilter === 'review') return claim.status !== 'Supported'
    return true
  })
  const selectedClaim = displayClaims.find(claim => claim.id === selectedClaimId)
  const executionReceipt = loadedReceipt?.action_id === actionContract?.action_id ? loadedReceipt : null
  const warrantActionId = actionContract?.action_id
  const warrantActionStatus = actionContract?.status
  const warrantReviewKey = actionContract?.warrant?.contract_hash ? JSON.stringify([
    taskId, warrantActionId, warrantActionStatus, actionContract.warrant.contract_hash,
    actionContract.approval_digest, actionContract.approved_warrant_hash, warrantRefresh,
  ]) : null
  const currentWarrantReview = warrantReviewKey && loadedWarrantReview?.key === warrantReviewKey
    ? loadedWarrantReview : null
  const warrantPermission = warrantControls(actionContract, currentWarrantReview?.review)
  const taskStatus = taskData?.status
  const browserSessionDetail = browserStatus.status === 'ready'
    ? 'Ready'
    : browserStatus.session_status === 'starting'
      ? 'Starting session'
      : browserStatus.session_status === 'started'
        ? 'Session active'
        : browserStatus.session_status === 'stopped'
          ? 'Last session stopped'
          : browserStatus.session_status === 'failed'
            ? 'Last session failed'
            : browserStatus.session_status === 'cleanup_failed'
              ? 'Session cleanup failed'
              : browserStatus.status === 'configured_unchecked'
                ? 'AWS connection not checked'
                : 'Status unavailable'
  const supportedEvidence = (Array.isArray(taskData?.research_report?.evidence) ? taskData.research_report.evidence : []).filter(
    item => item.extraction_status === 'SUPPORTED',
  )
  const supportedProducts = [...new Map(supportedEvidence.map(item => [item.subject.trim().toLowerCase(), item.subject])).values()]
  const selectedProduct = actionForm.laptop || supportedProducts[0] || ''
  const trustOverview = deriveTrustOverview({
    contract: proofContract,
    report: taskData?.research_report,
    claims: taskData?.claims || [],
    sources: taskData?.sources || [],
  })
  const researchSourceSummary = deriveResearchSourceSummary(taskData)
  const researchSourceAttempts = Array.isArray(taskData?.research_report?.source_attempts)
    ? taskData.research_report.source_attempts
    : []
  const claimVerificationSummary = summarizeClaimVerifications(taskData?.verifications || [])
  const actionIntegrity = deriveActionIntegrity(actionContract, executionReceipt)
  const contractAllowsDemoAction = Boolean(
    taskStatus === 'completed'
      && proofContract?.allowed_actions?.includes('submit_form')
      && proofContract?.requires_approval_for?.includes('submit_form')
      && !proofContract?.prohibited_actions?.includes('submit_form'),
  )
  const canPrepareDemoAction = contractAllowsDemoAction && browserStatus.supports_demo_actions === true
    && !demoActionBlockingStates.has(actionContract?.status)

  const eventCategory = (eventType) => {
    if (eventType.includes('search') || eventType.includes('source') || eventType.includes('recovery')) return 'Research'
    if (eventType.includes('claim') || eventType.includes('evidence') || eventType.includes('contradiction')) return 'Evidence'
    if (eventType.includes('analysis') || eventType.includes('report')) return 'Analysis'
    if (eventType.includes('pause') || eventType.includes('resume') || eventType.includes('cancel')) return 'Control'
    if (eventType.includes('failed')) return 'Failure'
    if (eventType.includes('completed')) return 'Complete'
    return 'Task'
  }

  const stageDefinitions = [
    ['task_created', 'Task created'],
    ['task_started', 'Execution started'],
    ['search_started', 'Search sources'],
    ['source_opened', 'Open sources'],
    ['claim_extracted', 'Extract claims'],
    ['analysis_started', 'Analyze evidence'],
    ['report_generated', 'Generate report'],
  ]
  const timelineStages = stageDefinitions.map(([eventType, label]) => {
    const matching = executionEvents.filter((event) => event.event_type === eventType)
    const currentIndex = stageDefinitions.findLastIndex(([type]) =>
      executionEvents.some((event) => event.event_type === type),
    )
    const index = stageDefinitions.findIndex(([type]) => type === eventType)
    const failed = executionEvents.some((event) => event.event_type === 'task_failed')
    return {
      eventType,
      label,
      state: matching.length ? 'completed'
        : index === currentIndex + 1 && failed ? 'failed'
          : index === currentIndex + 1 && !taskPollingStops.has(taskStatus) ? 'current' : 'pending',
      timestamp: matching.at(-1)?.timestamp,
    }
  })
  const liveActivity = executionEvents.slice(-6).reverse()

  useEffect(() => {
    const lifetime = new AbortController()
    let interval
    async function loadBrowserStatus() {
      try {
        const status = await getBrowserStatus({ signal: lifetime.signal })
        if (!lifetime.signal.aborted) setBrowserStatus(status)
      } catch (error) {
        if (!lifetime.signal.aborted) {
          setBrowserStatus({ label: 'Browser status unavailable', status: 'error', error: error.message })
        }
      } finally {
        if (!lifetime.signal.aborted) {
          interval = window.setTimeout(loadBrowserStatus, taskStatus === 'browsing' ? 2000 : 15000)
        }
      }
    }
    loadBrowserStatus()
    return () => {
      lifetime.abort()
      window.clearTimeout(interval)
    }
  }, [taskStatus])

  const refreshTasks = useCallback(async ({ signal } = {}) => {
    const sequence = ++taskListRequestSequenceRef.current
    setTasksLoading(true)
    setTasksError('')
    try {
      const latestTasks = await listTasks({ signal })
      if (!signal?.aborted && sequence === taskListRequestSequenceRef.current) setTasks(latestTasks)
    } catch (tasksRequestError) {
      if (!signal?.aborted && sequence === taskListRequestSequenceRef.current) setTasksError(tasksRequestError.message)
    } finally {
      if (sequence === taskListRequestSequenceRef.current) setTasksLoading(false)
    }
  }, [])

  useEffect(() => {
    const lifetime = new AbortController()
    const timer = window.setTimeout(() => refreshTasks({ signal: lifetime.signal }), 0)
    return () => {
      lifetime.abort()
      window.clearTimeout(timer)
    }
  }, [refreshTasks])

  useEffect(() => {
    if (!taskId) return undefined

    const lifetime = new AbortController()
    const seen = new Set()
    let cursor
    let live = false
    let inFlight = false
    let timer
    let pollDelay = 2500
    const isCurrent = () => !lifetime.signal.aborted && activeTaskIdRef.current === taskId
    const mergeEvents = incoming => {
      if (!isCurrent() || !Array.isArray(incoming)) return
      const newEvents = incoming.filter(event => {
        if (event?.task_id !== taskId || typeof event.event_id !== 'string' || seen.has(event.event_id)) return false
        seen.add(event.event_id)
        cursor = event.event_id
        return true
      })
      if (newEvents.length) {
        setExecutionEvents(existing => [...existing, ...newEvents].sort(
          (left, right) => new Date(left.timestamp) - new Date(right.timestamp),
        ).slice(-500))
      }
    }

    const schedulePoll = (delay = pollDelay) => {
      if (timer !== undefined || !isCurrent() || live) return
      timer = window.setTimeout(() => {
        timer = undefined
        poll()
      }, delay)
    }
    async function poll() {
      if (!isCurrent() || inFlight) return
      inFlight = true
      const requestedCursor = cursor
      try {
        const events = await listExecutionEvents(taskId, { afterEventId: requestedCursor, signal: lifetime.signal })
        if (!isCurrent()) return
        mergeEvents(events)
        if (!live) setEventConnection('polling')
        pollDelay = 2500
      } catch (error) {
        if (!isCurrent()) return
        if (error.status === 409 && !live && requestedCursor === cursor) {
          cursor = undefined
          seen.clear()
          setExecutionEvents([])
        }
        if (!live) setEventConnection('error')
        pollDelay = Math.min(pollDelay * 2, 15_000)
      } finally {
        inFlight = false
        schedulePoll()
      }
    }

    refreshExecutionEventsRef.current = poll

    let source
    if (typeof EventSource !== 'undefined') {
      source = new EventSource(`${API_URL}/api/tasks/${encodeURIComponent(taskId)}/events/stream`)

      source.onopen = () => {
        if (!isCurrent()) return
        live = true
        window.clearTimeout(timer)
        timer = undefined
        setEventConnection('live')
      }

      source.onerror = () => {
        if (!isCurrent()) return
        live = false
        setEventConnection('reconnecting')
        schedulePoll(2500)
      }

      const receive = (message) => {
        if (!isCurrent()) return
        try {
          mergeEvents([JSON.parse(message.data)])
        } catch {
          live = false
          setEventConnection('error')
          schedulePoll(2500)
        }
      }
      source.onmessage = receive
      executionEventTypes.forEach(type => source.addEventListener(type, receive))
    }
    schedulePoll(source ? 2500 : 0)

    return () => {
      lifetime.abort()
      source?.close()
      window.clearTimeout(timer)
      refreshExecutionEventsRef.current = null
    }
  }, [taskId])

  useEffect(() => {
    if (!taskId || !taskStatus) return
    if (taskPollingStops.has(taskStatus)) return

    const lifetime = new AbortController()
    let inFlight = false
    const pollTask = async () => {
      if (lifetime.signal.aborted || inFlight || activeTaskIdRef.current !== taskId) return
      const generation = taskReadGenerationRef.current
      const isCurrent = () => !lifetime.signal.aborted && activeTaskIdRef.current === taskId
        && taskReadGenerationRef.current === generation
      inFlight = true
      try {
        const latest = await getTask(taskId, { signal: lifetime.signal })
        if (isCurrent() && latest.id === taskId) {
          setTaskData(latest)
          setTaskSyncError('')
        }
      } catch (pollError) {
        if (isCurrent()) setTaskSyncError(pollError.message)
      } finally {
        inFlight = false
      }
    }
    const interval = window.setInterval(pollTask, 1500)
    return () => {
      lifetime.abort()
      window.clearInterval(interval)
    }
  }, [taskId, taskStatus])

  useEffect(() => {
    if (!taskId || taskData?.id !== taskId || taskStatus !== 'completed') {
      return
    }
    const lifetime = new AbortController()
    const generation = actionContextGenerationRef.current
    const isCurrent = () => !lifetime.signal.aborted && activeTaskIdRef.current === taskId
      && generation === actionContextGenerationRef.current
    const loadActionContext = async () => {
      try {
        const [contract, actions] = await Promise.all([
          getTaskContract(taskId, { signal: lifetime.signal }),
          getTaskActions(taskId, { signal: lifetime.signal }),
        ])
        if (!isCurrent()) return
        setProofContract(contract)
        const actionId = taskData.action_contract_id
        const taskActions = actions.filter(item => item.task_id === taskId)
        const current = taskActions.find(item => item.action_id === actionId)
          || taskActions.filter(item => demoActionBlockingStates.has(item.status))
            .sort((left, right) => new Date(right.created_at) - new Date(left.created_at))[0]
        setActionContract(current || null)
        if (current?.execution_receipt_id) {
          const receipt = await getExecutionReceipt(current.action_id, { signal: lifetime.signal })
          if (isCurrent() && receipt.action_id === current.action_id && receipt.task_id === taskId) {
            setExecutionReceipt(receipt)
          }
        } else {
          setExecutionReceipt(null)
        }
      } catch (loadError) {
        if (isCurrent()) setError(loadError.message)
      }
    }
    loadActionContext()
    return () => { lifetime.abort() }
  }, [taskId, taskStatus, taskData?.id, taskData?.action_contract_id])

  useEffect(() => {
    if (!taskId || !warrantActionId || !warrantReviewKey) return
    const lifetime = new AbortController()
    const selection = taskSelectionSequenceRef.current
    const isCurrent = () => !lifetime.signal.aborted && activeTaskIdRef.current === taskId
      && selection === taskSelectionSequenceRef.current
    const loadWarrantReview = async () => {
      const policyDecisionsPromise = getActionPolicyDecisions(warrantActionId, { signal: lifetime.signal })
      try {
        const [review, policyDecisions] = await Promise.all([
          getActionWarrant(warrantActionId, { signal: lifetime.signal }),
          policyDecisionsPromise,
        ])
        if (!isCurrent()) return
        setLoadedWarrantReview({ key: warrantReviewKey, review, policyDecisions })
        if (review.approval_status !== warrantActionStatus) {
          const updated = await getActionContract(warrantActionId, { signal: lifetime.signal })
          if (isCurrent() && updated.action_id === warrantActionId && updated.task_id === taskId) setActionContract(updated)
        }
      } catch (error) {
        if (!isCurrent()) return
        const policyDecisions = await policyDecisionsPromise.catch(() => [])
        if (!isCurrent()) return
        setLoadedWarrantReview({
          key: warrantReviewKey,
          error: error.status === 404 ? 'The API could not find a signed Warrant for this action.' : error.message,
          policyDecisions,
        })
      }
    }
    loadWarrantReview()
    return () => { lifetime.abort() }
  }, [taskId, warrantActionId, warrantActionStatus, warrantReviewKey])

  const clearTaskView = (nextTaskId) => {
    const taskChanged = activeTaskIdRef.current !== nextTaskId
    const sequence = ++taskSelectionSequenceRef.current
    taskSelectionRequestRef.current?.abort()
    taskReadGenerationRef.current += 1
    actionContextGenerationRef.current += 1
    activeTaskIdRef.current = nextTaskId
    setError('')
    setTaskSyncError('')
    setTaskId(nextTaskId)
    setTaskData(null)
    setSelectedClaimId(null)
    setCopiedDigest(null)
    if (taskChanged) {
      setExecutionEvents([])
      setEventConnection(nextTaskId ? 'connecting' : 'disconnected')
    }
    setProofContract(null)
    setActionContract(null)
    setLoadedWarrantReview(null)
    setExecutionReceipt(null)
    setActionBusy(false)
    return sequence
  }

  const runTask = async () => {
    if (!task.trim() || creating) return
    const sequence = clearTaskView(null)
    setCreating(true)
    setActionForm({ laptop: '', budget: '', ram: '', gpu: '', reason: 'Controlled demo request for the selected product.' })
    const pending = pendingTaskRequestRef.current?.task === task
      ? pendingTaskRequestRef.current
      : { task, id: crypto.randomUUID() }
    pendingTaskRequestRef.current = pending
    try {
      const created = await createTask(task, undefined, pending.id)
      if (pendingTaskRequestRef.current === pending) pendingTaskRequestRef.current = null
      if (sequence !== taskSelectionSequenceRef.current) return
      activeTaskIdRef.current = created.id
      setTaskId(created.id)
      setTaskData(created)
      setEventConnection('connecting')
      setActiveNav('Overview')
      await refreshTasks()
    } catch (taskError) {
      if (taskError.status && taskError.status < 500 && pendingTaskRequestRef.current === pending) {
        pendingTaskRequestRef.current = null
      }
      if (sequence === taskSelectionSequenceRef.current) setError(taskError.message)
    } finally {
      setCreating(false)
    }
  }

  const runDemoScenario = async () => {
    if (creating) return
    const sequence = clearTaskView(null)
    setCreating(true)
    setActionForm({
      laptop: 'Dell G16',
      budget: 'GBP 1500',
      ram: '32GB DDR5',
      gpu: 'RTX 4060',
      reason: 'Controlled simulated demo request for the Dell G16 fixture.',
    })
    try {
      const created = await createDemoScenario()
      if (sequence !== taskSelectionSequenceRef.current) return
      activeTaskIdRef.current = created.id
      setTask(created.task)
      setTaskId(created.id)
      setTaskData(created)
      setEventConnection('connecting')
      setActiveNav('Overview')
      await refreshTasks()
    } catch (demoError) {
      if (sequence === taskSelectionSequenceRef.current) setError(demoError.message)
    } finally {
      setCreating(false)
    }
  }

  const openTask = async (id) => {
    if (activeTaskIdRef.current === id && taskData?.id === id) {
      setActiveNav('Overview')
      return
    }
    const sequence = clearTaskView(id)
    const lifetime = new AbortController()
    taskSelectionRequestRef.current = lifetime
    setActionForm({ laptop: '', budget: '', ram: '', gpu: '', reason: 'Controlled demo request for the selected product.' })
    try {
      const selected = await getTask(id, { signal: lifetime.signal })
      if (sequence !== taskSelectionSequenceRef.current) return
      if (selected.id !== id) throw new Error('The API returned a different task.')
      setTaskId(selected.id)
      setTask(selected.task)
      setTaskData(selected)
      setActiveNav('Overview')
    } catch (taskRequestError) {
      if (sequence === taskSelectionSequenceRef.current) setError(taskRequestError.message)
    } finally {
      if (taskSelectionRequestRef.current === lifetime) taskSelectionRequestRef.current = null
    }
  }

  const updateTask = async (id, command) => {
    if (!id || pendingControlsRef.current.has(id)) return
    const selection = taskSelectionSequenceRef.current
    const isCurrent = () => activeTaskIdRef.current === id && taskSelectionSequenceRef.current === selection
    pendingControlsRef.current.add(id)
    if (isCurrent()) {
      taskReadGenerationRef.current += 1
      setError('')
    }
    try {
      const updated = await command(id)
      if (isCurrent() && updated.id === id) {
        taskReadGenerationRef.current += 1
        setTaskData(updated)
        setTaskSyncError('')
        if (command === retryTask) {
          actionContextGenerationRef.current += 1
          setSelectedClaimId(null)
          setCopiedDigest(null)
          setProofContract(null)
          setActionContract(null)
          setLoadedWarrantReview(null)
          setExecutionReceipt(null)
        }
      }
      await refreshTasks()
    } catch (taskError) {
      if (isCurrent()) setError(taskError.message)
      else setTasksError(taskError.message)
    } finally {
      pendingControlsRef.current.delete(id)
    }
  }

  const removeTask = async (id) => {
    try {
      await deleteTask(id)
      if (activeTaskIdRef.current === id) {
        clearTaskView(null)
        setTask('')
      }
      await refreshTasks()
    } catch (deleteError) {
      setError(deleteError.message)
    }
  }

  const startNewTask = () => {
    clearTaskView(null)
    pendingTaskRequestRef.current = null
    setTask('')
    setActionForm({ laptop: '', budget: '', ram: '', gpu: '', reason: 'Controlled demo request for the selected product.' })
    setActiveNav('Overview')
    setSidebarOpen(false)
  }

  const copyApprovalDigest = async () => {
    const digest = actionContract?.approval_digest
    const selection = taskSelectionSequenceRef.current
    if (!digest) return
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard access is unavailable in this browser.')
      await navigator.clipboard.writeText(digest)
      if (selection === taskSelectionSequenceRef.current) {
        setCopiedDigest(digest)
        setError('')
      }
    } catch (copyError) {
      if (selection === taskSelectionSequenceRef.current) {
        setError(copyError.message || 'Could not copy the approval digest.')
      }
    }
  }

  const performActionOperation = async (operation, { returnsReceipt = false } = {}) => {
    if (!taskId || actionBusy) return
    const requestedTaskId = taskId
    const requestedActionId = actionContract?.action_id
    const selection = taskSelectionSequenceRef.current
    const generation = ++actionContextGenerationRef.current
    const isCurrent = () => activeTaskIdRef.current === requestedTaskId
      && taskSelectionSequenceRef.current === selection
      && actionContextGenerationRef.current === generation
    setError('')
    setActionBusy(true)
    try {
      const result = await operation()
      if (!isCurrent()) return
      if (returnsReceipt) {
        if (result.action_id !== requestedActionId || result.task_id !== requestedTaskId) {
          throw new Error('The API returned a receipt for a different action.')
        }
        setExecutionReceipt(result)
        const latestAction = await getActionContract(requestedActionId)
        if (!isCurrent()) return
        if (latestAction.action_id !== requestedActionId || latestAction.task_id !== requestedTaskId) {
          throw new Error('The API returned a different action while refreshing.')
        }
        setActionContract(latestAction)
      } else {
        if (result.task_id !== requestedTaskId) {
          throw new Error('The API returned an action for a different task.')
        }
        setActionContract(result)
      }
      const latestTask = await getTask(requestedTaskId)
      if (isCurrent() && latestTask.id === requestedTaskId) setTaskData(latestTask)
    } catch (actionError) {
      if (!isCurrent()) return
      setError(actionError.message)
      if (requestedActionId) {
        try {
          const latestAction = await getActionContract(requestedActionId)
          if (!isCurrent()) return
          if (latestAction.action_id !== requestedActionId || latestAction.task_id !== requestedTaskId) return
          setActionContract(latestAction)
          if (latestAction.execution_receipt_id) {
            const latestReceipt = await getExecutionReceipt(requestedActionId)
            if (isCurrent() && latestReceipt.action_id === requestedActionId && latestReceipt.task_id === requestedTaskId) {
              setExecutionReceipt(latestReceipt)
            }
          }
          setWarrantRefresh(version => version + 1)
        } catch { /* Preserve the last confirmed action state. */ }
      }
    } finally {
      if (isCurrent()) setActionBusy(false)
    }
  }

  const prepareDemoAction = () => {
    if (!taskId || !canPrepareDemoAction) return
    const evidenceIds = supportedEvidence
      .filter(item => item.subject.trim().toLowerCase() === selectedProduct.trim().toLowerCase())
      .map(item => item.evidence_id)
    const requirementIds = proofContract.requirements.filter(item => item.hard_constraint).map(item => item.id)
    return performActionOperation(() => createActionContract(taskId, {
      action_type: 'submit_demo_request',
      target_url: DEMO_TARGET_URL,
      payload: { ...actionForm, laptop: selectedProduct },
      associated_requirement_ids: requirementIds,
      associated_evidence_ids: evidenceIds,
    }))
  }

  const approveAction = () => {
    const permission = warrantControls(actionContract, currentWarrantReview?.review)
    if (permission.canApprove) {
      return performActionOperation(() => approveActionContract(actionContract.action_id, permission.hash))
    }
  }

  const rejectAction = () => {
    if (actionContract?.status === 'PENDING_APPROVAL' || (
      actionContract?.status === 'APPROVED' && !actionContract.warrant
    )) {
      return performActionOperation(() => rejectActionContract(actionContract.action_id))
    }
  }

  const executeAction = () => {
    if (warrantControls(actionContract, currentWarrantReview?.review).canExecute) {
      return performActionOperation(() => executeActionContract(actionContract.action_id), { returnsReceipt: true })
    }
  }

  const reconcileAction = () => {
    if (actionContract?.status === 'OUTCOME_UNKNOWN') {
      return performActionOperation(() => reconcileActionContract(actionContract.action_id), { returnsReceipt: true })
    }
  }

  return (
    <div className="app-shell">
      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
        <div className="sidebar-brand-block">
          <div className="brand">
            <div className="brand-mark"><span /><span /><span /></div>
            <span>ProofPilot</span>
          </div>
          <p>AI browser control</p>
        </div>

        <div className="environment-card" aria-label="Browser environment status">
          <span className={`environment-led ${browserStatus.status}`} />
          <div>
            <strong>{browserStatus.supports_demo_actions === true ? 'Local sandbox' : browserStatus.label}</strong>
            <span>{browserStatus.label} · {browserSessionDetail}</span>
          </div>
        </div>

        <button className="new-task" onClick={startNewTask}>
          <Icon name="plus" size={17} /><span>New task</span>
        </button>

        <nav className="nav-list" aria-label="Main navigation">
          {[
            ['Overview', 'grid'],
            ['Tasks', 'file'],
            ['Activity', 'history'],
          ].map(([label, icon]) => (
            <button key={label} className={activeNav === label ? 'active' : ''} aria-current={activeNav === label ? 'page' : undefined} onClick={() => setActiveNav(label)}>
              <Icon name={icon} /><span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-recent">
          <div className="sidebar-section-title"><span>Recent runs</span><button onClick={() => setActiveNav('Tasks')} aria-label="View all tasks">All</button></div>
          {tasks.slice(0, 4).map(item => (
            <button key={item.id} className={`sidebar-task ${item.id === taskId ? 'selected' : ''}`} onClick={() => { openTask(item.id); setSidebarOpen(false) }}>
              <span className={`sidebar-task-state task-status-${item.status}`} />
              <span><strong>{item.task}</strong><small>{item.status} · {new Date(item.created_at).toLocaleDateString()}</small></span>
            </button>
          ))}
          {!tasks.length && <p className="sidebar-no-tasks">Your runs will appear here.</p>}
        </div>

        <div className="sidebar-footer">
          <button className={activeNav === 'Settings' ? 'active' : ''} aria-current={activeNav === 'Settings' ? 'page' : undefined} onClick={() => setActiveNav('Settings')}><Icon name="settings" /><span>Environment settings</span></button>
          <div className="sidebar-connection"><span>Event stream</span><strong className={`connection-${eventConnection}`}>{eventConnection}</strong></div>
        </div>
      </aside>

      {sidebarOpen && <button className="sidebar-backdrop" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}

      <main className="main">
        <header className="topbar">
          <button className="menu-button" aria-label="Open navigation" onClick={() => setSidebarOpen(true)}><span /></button>
          <div className="breadcrumbs"><span>Workspace</span><b>/</b><strong>{activeNav === 'Overview' ? (taskData?.task || 'New task') : activeNav}</strong></div>
          <div className="top-actions">
            <div className="header-event-state"><span className={`event-led ${eventConnection}`} /><span>Event stream</span><strong>{eventConnection}</strong></div>
            <button className="top-new-task" onClick={startNewTask}><Icon name="plus" size={15} />New task</button>
          </div>
        </header>

        <div className="content">
          <section className="workspace-titlebar">
            <div>
              <span className="eyebrow">PROOFPILOT CONTROL PLANE</span>
              <h1>{activeNav === 'Overview' ? (taskData?.task || 'AI browser workspace') : activeNav === 'Tasks' ? 'Task library' : activeNav === 'Activity' ? 'Execution activity' : 'Environment settings'}</h1>
              <p>{taskData ? `${taskData.progress || taskData.status} · Updated ${formatTimestamp(taskData.updated_at || taskData.created_at)}` : 'Research, review authorization, and prove what the browser did.'}</p>
            </div>
            <div className="workspace-title-meta">
              {taskData && <>
                <StatusBadge status={taskData.status} />
                <CopyValue value={taskData.id} label="task ID" className="task-id-copy" />
              </>}
              <span className="workspace-provider">{browserStatus.label}</span>
            </div>
          </section>

          {activeNav === 'Overview' && <section className="task-composer">
            <div className="composer-heading">
              <div>
                <span className="eyebrow">TASK REQUEST</span>
                <h2>What should we investigate?</h2>
              </div>
              <span className="composer-note">A ProofContract will define the task boundary.</span>
            </div>
            <div className="input-wrap">
              <textarea
                value={task}
                onChange={(e) => setTask(e.target.value)}
                aria-label="Research task"
                placeholder="Describe what you want the agent to research..."
              />
              <div className="input-footer">
                <span className="source-toggle"><Icon name="shield" size={14} /> Task-scoped research</span>
                <div className="composer-actions">
                  <button className="demo-load-button" onClick={runDemoScenario} disabled={creating}>
                    {creating ? 'Loading...' : 'Load simulated demo'}
                  </button>
                  <button className="run-button" onClick={runTask} disabled={!task.trim() || creating}>
                    {creating ? 'Creating...' : 'Run research'} <Icon name="send" size={15} />
                  </button>
                </div>
              </div>
            </div>
            <div className="examples">
              <span>Try:</span>
              {[
                'Compare M2 MacBooks under $2,000',
                'Find public EV charging options',
                'Research gaming laptops under £1,500',
              ].map(example => (
                <button key={example} onClick={() => setTask(example)}>{example}</button>
              ))}
            </div>
            {(error || taskSyncError || taskData?.status === 'failed' || taskData?.status === 'partial' || taskData?.status === 'blocked') && (
              <div className="error-banner" role="alert">
                <Icon name="x" size={15} />
                <span>{error || taskSyncError || taskData?.error || researchRecoveryMessage(taskData)}</span>
                {taskId && !error && !taskSyncError && retryableResearchStatuses.has(taskStatus) && (
                  <button onClick={() => updateTask(taskId, retryTask)}>Retry research</button>
                )}
              </div>
            )}
          </section>}

          {(error || taskSyncError) && activeNav !== 'Overview' && (
            <div className="error-banner" role="alert"><Icon name="x" size={15} /><span>{error || taskSyncError}</span></div>
          )}

          {activeNav === 'Overview' && taskData?.task?.startsWith('SIMULATED DEMO:') && (
            <div className="simulated-demo-banner" role="note">
              <strong>SIMULATED DEMO DATA</strong>
              <span>Three local fixture pages are shown. No public search or live product research was performed.</span>
            </div>
          )}

          {activeNav === 'Overview' && <>
            <WorkflowProgress
              task={taskData}
              proofContract={proofContract}
              action={actionContract}
              decisions={currentWarrantReview?.policyDecisions || []}
              receipt={executionReceipt}
            />
            <ProofContractOverview contract={proofContract} taskStatus={taskStatus} />
          </>}

          {activeNav === 'Tasks' && (
            <section className="panel task-list-panel">
              <div className="panel-header">
                <div><span className="eyebrow">TASK MANAGEMENT</span><h2>Tasks</h2></div>
                <button className="text-button" onClick={refreshTasks} disabled={tasksLoading}>
                  {tasksLoading ? 'Refreshing...' : 'Refresh'}
                </button>
              </div>
              {tasksError && <div className="error-banner" role="alert"><span>{tasksError}</span></div>}
              {tasksLoading && !tasks.length ? (
                <div className="empty-state">Loading tasks...</div>
              ) : tasks.length ? (
                <div className="task-list">
                  {tasks.map((item) => (
                    <article className="task-list-item" key={item.id}>
                      <button className="task-list-main" onClick={() => openTask(item.id)}>
                        <span className={`task-status task-status-${item.status}`}>{item.status}</span>
                        <strong>{item.task}</strong>
                        <span>{item.progress}</span>
                        <time>{new Date(item.created_at).toLocaleString()}</time>
                      </button>
                      <div className="task-list-actions">
                        {retryableResearchStatuses.has(item.status) && (
                          <button onClick={() => updateTask(item.id, retryTask)}>Retry</button>
                        )}
                        {!taskPollingStops.has(item.status) && (
                          <button onClick={() => updateTask(item.id, cancelTask)}>Cancel</button>
                        )}
                        {!taskPollingStops.has(item.status) && (
                          <button onClick={() => updateTask(item.id, item.status === 'paused' ? resumeTask : pauseTask)}>
                            {item.status === 'paused' ? 'Resume' : 'Pause'}
                          </button>
                        )}
                        {['completed', 'failed', 'cancelled', 'partial'].includes(item.status) && (
                          <button onClick={() => removeTask(item.id)}>Delete</button>
                        )}
                      </div>
                    </article>
                  ))}
                </div>
              ) : (
                <div className="empty-state">No tasks yet. Create one from the research task form.</div>
              )}
            </section>
          )}

          {activeNav === 'Activity' && (
            <section className="panel activity-page">
              <div className="panel-header">
                <div><span className="eyebrow">EXECUTION HISTORY</span><h2>Activity</h2></div>
                <div className="event-status">
                  <span className={eventConnection} />
                  {eventConnection}
                  <button className="text-button" onClick={() => refreshExecutionEventsRef.current?.()} disabled={!taskId}>Refresh</button>
                </div>
              </div>
              {executionEvents.length ? (
                <div className="activity-page-list">
                  {executionEvents.slice().reverse().map((event) => (
                    <button key={event.event_id} onClick={() => openTask(event.task_id)}>
                      <code>{eventCategory(event.event_type)}</code>
                      <strong>{event.event_type.replaceAll('_', ' ')}</strong>
                      <span>{event.message}</span>
                      <time>{new Date(event.timestamp).toLocaleString()}</time>
                    </button>
                  ))}
                </div>
              ) : <div className="empty-state">No execution events yet.</div>}
            </section>
          )}

          {activeNav === 'Settings' && (
            <section className="panel settings-page">
              <div className="panel-header">
                <div><span className="eyebrow">LOCAL SETTINGS</span><h2>Settings</h2></div>
              </div>
              <div className="settings-content">
                <label>
                  Browser environment
                  <span>{browserStatus.label} · {browserSessionDetail}</span>
                </label>
                <label>
                  AgentCore region
                  <span>{browserStatus.provider === 'agentcore' ? browserStatus.region : 'Not applicable'}</span>
                </label>
                <label>
                  Browser diagnostics
                  <span>{browserStatus.error || browserSessionDetail}</span>
                </label>
                <label>
                  Demo action target
                  <span>{browserStatus.supports_demo_actions ? 'Available' : 'Unavailable with remote browser'}</span>
                </label>
                <label>
                  API endpoint
                  <span>{API_URL}</span>
                </label>
              </div>
            </section>
          )}

          {(activeNav === 'Overview') && <div className="dashboard-grid">
            <section className="panel execution-panel">
              <div className="panel-header">
                <div><span className="eyebrow">EXECUTION</span><h2>Agent timeline</h2></div>
                <div className="execution-actions">
                  <span className={`browser-provider-pill ${browserStatus.provider === 'agentcore' ? 'remote' : ''}`}>
                    {browserStatus.label} · {browserSessionDetail}
                  </span>
                  <span className="running-pill"><span /> {taskData?.status || 'Idle'} {taskData?.progress_percent ? `${taskData.progress_percent}%` : ''}</span>
                  {taskId && taskStatus === 'paused' && <button onClick={() => updateTask(taskId, resumeTask)}>Resume</button>}
                  {taskId && taskStatus && taskStatus !== 'paused' && !taskPollingStops.has(taskStatus) && (
                    <button onClick={() => updateTask(taskId, pauseTask)}>Pause</button>
                  )}
                  {taskId && taskStatus && !taskPollingStops.has(taskStatus) && (
                    <button onClick={() => updateTask(taskId, cancelTask)}>Cancel</button>
                  )}
                </div>
              </div>
              <div className="timeline">
                {timelineStages.length ? timelineStages.map((stage, index) => (
                  <div className="timeline-item" key={stage.eventType}>
                    <div className={`timeline-marker ${stage.state}`}><Icon name={stage.state === 'completed' ? 'check' : stage.state === 'failed' ? 'x' : 'clock'} size={13} /></div>
                    {index < timelineStages.length - 1 && <div className="timeline-line" />}
                    <div className="timeline-copy">
                      <strong>{stage.label}</strong>
                      <span>{stage.state === 'pending' ? 'Waiting' : stage.state}</span>
                    </div>
                    <time className="timeline-meta">
                      {stage.timestamp ? new Date(stage.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : ''}
                    </time>
                  </div>
                )) : (
                  <div className="empty-state"><Icon name="clock" /><span>No active execution. Submit a task to begin.</span></div>
                )}
              </div>
            </section>

            <section className="panel activity-panel">
              <div className="panel-header">
                <div><span className="eyebrow">LIVE FEED</span><h2>Activity</h2></div>
                <div className="event-status">
                  <span className={eventConnection} />
                  {eventConnection}
                  <button className="text-button" onClick={() => setActiveNav('Activity')}>View all</button>
                </div>
              </div>
              <div className="activity-list">
                {liveActivity.length ? liveActivity.map((event) => (
                  <div className="activity-item" key={event.event_id}>
                    <div className={`activity-icon ${event.event_type.includes('failed') ? 'blue' : event.event_type.includes('cancel') ? 'purple' : 'green'}`}>
                      <Icon name={event.event_type.includes('failed') ? 'x' : event.event_type.includes('search') ? 'search' : 'check'} size={14} />
                    </div>
                    <div><strong>{event.event_type.replaceAll('_', ' ')}</strong><span>{event.message}</span></div>
                    <time>{new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</time>
                  </div>
                )) : (
                  <div className="empty-state">Waiting for real execution events.</div>
                )}
              </div>
            </section>

            <section className="panel trust-dashboard" aria-label="Task trust and evidence overview">
              <div className="panel-header">
                <div><span className="eyebrow">PROOF STATUS</span><h2>Trust and evidence overview</h2></div>
                <span className={`trust-report-state trust-${trustStatusClass(taskData?.research_report?.status || 'unavailable')}`}>
                  Research process: {researchExecutionStatus(taskData?.research_report, taskStatus)}
                </span>
              </div>
              <div className="trust-state-grid">
                {[
                  ['Action authorization', actionIntegrity.authorization],
                  ['Execution status', actionIntegrity.execution],
                  ['Verification status', actionIntegrity.verification],
                  ['Receipt status', actionIntegrity.receipt],
                  ['Browser provider', `${browserStatus.label} · ${browserSessionDetail}`],
                ].map(([label, value]) => (
                  <div className="trust-state" key={label}><span>{label}</span><strong>{value}</strong></div>
                ))}
              </div>

              <div className="trust-metrics" aria-label="Requirement evidence metrics">
                <div className="trust-metric"><span>Contract requirements</span><strong>{trustOverview.totalRequirements || 'Not available'}</strong><small>Unique constraints in the ProofContract</small></div>
                <div className="trust-metric"><span>Evidence coverage</span><strong>{trustOverview.hasReport && trustOverview.totalChecks ? `${trustOverview.evidenceBackedChecks} / ${trustOverview.totalChecks}` : 'Not available'}</strong><small>Checks with linked records / applicable candidate checks</small></div>
                <div className="trust-metric trust-supported"><span>Supported checks</span><strong>{trustOverview.hasReport ? trustOverview.counts.supported : 'Not available'}</strong><small>Evidence-backed satisfied evaluations</small></div>
                <div className="trust-metric trust-failed"><span>Failed checks</span><strong>{trustOverview.hasReport ? trustOverview.counts.failed : 'Not available'}</strong><small>Requirement not satisfied</small></div>
                <div className="trust-metric trust-contradicted"><span>Contradicted checks</span><strong>{trustOverview.hasReport ? trustOverview.counts.contradicted : 'Not available'}</strong><small>Conflicting evidence remains visible</small></div>
                <div className="trust-metric trust-unverified"><span>Unverified checks</span><strong>{trustOverview.hasReport ? trustOverview.counts.unverified : 'Not available'}</strong><small>Evidence exists, verdict is incomplete</small></div>
                <div className="trust-metric trust-missing"><span>Missing evidence</span><strong>{trustOverview.hasReport ? trustOverview.counts.missing : 'Not available'}</strong><small>No linked evidence record to inspect</small></div>
                <div className="trust-metric"><span>Evidence source domains</span><strong>{trustOverview.hasReport ? trustOverview.sourceCount : 'Not available'}</strong><small>Unique HTTP(S) domains in evidence records</small></div>
              </div>
              <p className="trust-metric-note">Evidence coverage measures evidence availability, not correctness, accuracy, or likelihood of success. Supported counts are separate backend evaluations with linked supporting evidence.</p>

              {researchSourceAttempts.length > 0 && (
                <details className="research-recovery-details">
                  <summary>
                    Source recovery · {researchSourceSummary.sources_accessed || 0} accessed · {researchSourceSummary.sources_failed || 0} failed · {researchSourceSummary.recovery_attempts || 0} recovery attempts
                  </summary>
                  <div className="research-recovery-content">
                    <div className="research-recovery-stats">
                      <span>{researchSourceSummary.sources_discovered || 0} discovered</span>
                      <span>{researchSourceSummary.sources_attempted || 0} attempted</span>
                      <span>{researchSourceSummary.sources_with_usable_evidence || 0} with relevant evidence</span>
                      <span>{researchSourceSummary.sources_rejected || 0} rejected by contract</span>
                      <span>{researchSourceSummary.requirements_supported || 0} supported</span>
                      <span>{researchSourceSummary.requirements_contradicted || 0} contradicted</span>
                      <span>{researchSourceSummary.requirements_unresolved || 0} unresolved</span>
                      <span>Completeness: {taskData?.research_report?.status || 'Unavailable'}</span>
                    </div>
                    <ul className="research-attempt-list">
                      {researchSourceAttempts.map(attempt => {
                        const url = safeExternalUrl(attempt.source_url)
                        const label = attempt.domain || (attempt.source_type === 'search' ? 'Search provider' : 'Unknown domain')
                        return <li key={attempt.attempt_id}>
                          <div className="research-attempt-heading">
                            <strong>{label}</strong>
                            <span className={`research-attempt-status ${attempt.failure_category === 'SUCCESS' ? 'success' : 'failure'}`}>
                              {String(attempt.failure_category || 'UNKNOWN_FAILURE').replaceAll('_', ' ')}
                            </span>
                          </div>
                          <p>{attempt.error_description || (attempt.evidence_extracted ? 'Evidence extracted from the accessible page.' : attempt.retrieval_succeeded ? 'Page retrieved; no structured evidence was extracted.' : 'Source attempt recorded.')}</p>
                          <small>
                            Attempt {attempt.attempt_number} · {formatTimestamp(attempt.timestamp)}
                            {attempt.http_status ? ` · HTTP ${attempt.http_status}` : ''}
                            {attempt.recovery_attempt_status && attempt.recovery_attempt_status !== 'NOT_NEEDED' ? ` · Recovery: ${attempt.recovery_attempt_status.replaceAll('_', ' ').toLowerCase()}` : ''}
                            {attempt.alternative_sources_found ? ' · Alternative source found' : ''}
                            {attempt.affects_requirement
                              ? ` · ${attempt.recovery_attempt_status === 'RECOVERED' ? 'Evidence recovered for' : 'Affected requirements:'} ${attempt.affected_requirement_ids?.join(', ') || 'unassigned'}`
                              : ' · No requirement impact identified'}
                          </small>
                          {url && <a href={url} target="_blank" rel="noreferrer noopener">Open public source</a>}
                        </li>
                      })}
                    </ul>
                  </div>
                </details>
              )}

              <section className="claim-verification-layer" aria-label="Claim source verification">
                <div><span className="eyebrow">CLAIM VERIFICATION · SOURCE SUPPORT</span><strong>{claimVerificationSummary.total || 'Not available'}</strong><small>Claims checked against collected page text</small></div>
                <div><span>Supported claims</span><strong>{claimVerificationSummary.total ? claimVerificationSummary.supported : 'Not available'}</strong></div>
                <div><span>Contradicted claims</span><strong>{claimVerificationSummary.total ? claimVerificationSummary.contradicted : 'Not available'}</strong></div>
                <div><span>Unverified claims</span><strong>{claimVerificationSummary.total ? claimVerificationSummary.unverified : 'Not available'}</strong></div>
                <p>Claim verification checks whether an excerpt supports an extracted statement. Requirement evaluation separately checks that verified observation against the ProofContract.</p>
              </section>

              {trustOverview.candidateSummaries.length > 0 && (
                <div className="trust-candidates">
                  <h3>Candidate review</h3>
                  <div className="trust-candidate-grid">
                    {trustOverview.candidateSummaries.map(candidate => {
                      const supportedCount = candidate.checks.filter(check => check.status === 'supported').length
                      return <article className="trust-candidate" key={candidate.subject}>
                        <div><strong>{candidate.subject}</strong><span className={`trust-verdict trust-${trustStatusClass(candidate.label)}`}>{candidate.label}</span></div>
                        <small>{supportedCount} supported / {candidate.checks.length} applicable checks</small>
                      </article>
                    })}
                  </div>
                </div>
              )}

              {taskData?.task?.startsWith('SIMULATED DEMO:') && (
                <div className="trust-demo-note" role="note">
                  <strong>Deterministic fixture</strong>
                  <span>Local pages only; no public search or live product research. Instruction-like source text is untrusted and does not grant permission to act.</span>
                </div>
              )}

              <div className="trust-explorer">
                <div className="trust-explorer-heading">
                  <div><span className="eyebrow">REQUIREMENT DETAIL</span><h3>Requirement evidence explorer</h3></div>
                  <span>{trustOverview.hasReport ? `${trustOverview.checks.length} applicable checks` : 'Not available'}</span>
                </div>
                {!trustOverview.hasReport ? (
                  <div className="empty-state">A research report is not available for this task.</div>
                ) : trustOverview.checks.length ? (
                  <div className="trust-check-list">
                    {trustOverview.checks.map(check => (
                      <article className={`trust-check trust-check-${check.status}`} key={check.key}>
                        <div className="trust-check-header">
                          <div><span className="trust-subject">{check.subject || 'Task requirement'}</span><h4>{check.requirement.label}</h4></div>
                          <span className={`trust-verdict trust-${check.status}`}>{check.statusLabel}</span>
                        </div>
                        <dl className="trust-check-values">
                          <div><dt>Required constraint</dt><dd>{check.requirement.field} {requirementOperator(check.requirement.operator)} {requirementExpected(check.requirement)}</dd></div>
                          <div><dt>Observed value</dt><dd>{check.observed}{check.observedNumericValue !== null && <small className="structured-observation">Parsed observation: {check.observedCurrencySymbol || check.observedCurrency || ''}{check.observedNumericValue}{check.observedUnit ? ` ${check.observedUnit}` : ''}</small>}</dd></div>
                          <div><dt>Evaluation result</dt><dd>{check.reason}</dd></div>
                          <div><dt>Backend requirement status</dt><dd>{check.backendStatus || 'Not returned'}{check.requiredCurrency ? ` · required currency ${check.requiredCurrency}` : ''}{check.requiredUnit ? ` · required unit ${check.requiredUnit}` : ''}{check.observedCurrency ? ` · observed currency ${check.observedCurrency}` : ''}{check.observedUnit ? ` · observed unit ${check.observedUnit}` : ''}</dd></div>
                        </dl>
                        {check.evidence.length ? (
                          <div className="trust-evidence-list">
                            {check.evidence.map(evidence => {
                              const contradictory = evidence.extractionStatus === 'CONTRADICTED'
                              const evidenceTitle = contradictory ? 'Contradictory evidence' : evidence.extractionStatus === 'SUPPORTED' ? 'Supporting evidence' : 'Unverified source evidence'
                              return <div className={`trust-evidence trust-evidence-${trustStatusClass(evidence.extractionStatus)}`} key={evidence.id}>
                                <div className="trust-evidence-heading"><strong>{evidenceTitle}</strong><span>{evidence.field}: {evidence.value} · linked to {check.requirement.id}</span></div>
                                 {(evidence.numericValue !== null || evidence.context.length > 0) && <p className="evidence-context">{evidence.numericValue !== null ? `Parsed: ${evidence.currencySymbol || evidence.currency || ''}${evidence.numericValue}${evidence.unit ? ` ${evidence.unit}` : ''}` : ''}{evidence.context.length ? `${evidence.numericValue !== null ? ' · ' : ''}Context: ${evidence.context.join(', ').replaceAll('_', ' ')}` : ''}</p>}
                                {evidence.quote ? <blockquote><small>{evidence.quoteKind}</small>{evidence.quote}</blockquote> : <p className="trust-no-quote">No quoted text is available for this evidence record.</p>}
                                <div className="trust-source-row">
                                  <div><strong>{evidence.sourceTitle || evidence.sourceDomain}</strong><span>{evidence.sourceDomain} · observed {formatTimestamp(evidence.observedAt)}</span></div>
                                  {evidence.sourceUrl ? <a href={evidence.sourceUrl} target="_blank" rel="noreferrer noopener" aria-label={`Open source ${evidence.sourceDomain}`}><Icon name="external" size={14} /> Open source</a> : <span className="trust-link-unavailable">External link unavailable</span>}
                                </div>
                              </div>
                            })}
                          </div>
                        ) : (
                          <div className="trust-missing-note">No linked evidence record was returned for this requirement check.</div>
                        )}
                      </article>
                    ))}
                  </div>
                ) : (
                  <div className="empty-state">No requirement checks are available in this report.</div>
                )}
                {(trustOverview.reportContradictions.length > 0 || trustOverview.missingInformation.length > 0) && (
                  <div className="trust-report-notes">
                    {trustOverview.reportContradictions.length > 0 && <div><h4>Report contradictions</h4><ul>{trustOverview.reportContradictions.map((item, index) => <li key={`contradiction-${index}`}>{item}</li>)}</ul></div>}
                    {trustOverview.missingInformation.length > 0 && <div><h4>Missing information reported</h4><ul>{trustOverview.missingInformation.map((item, index) => <li key={`missing-${index}`}>{item}</li>)}</ul></div>}
                  </div>
                )}
                {trustOverview.sourceFailures.length > 0 && <section className="source-failure-list" aria-label="Source access and coverage failures">
                  <div className="trust-explorer-heading"><div><span className="eyebrow">SOURCE COVERAGE</span><h3>Access and collection issues</h3></div><span>{trustOverview.sourceFailures.length} source failures</span></div>
                  {trustOverview.sourceFailures.map((failure, index) => <article className={`source-failure source-failure-${trustStatusClass(failure.coverageImpact)}`} key={`${failure.url || failure.domain}:${failure.failedAt || index}`}>
                    <div className="source-failure-top"><strong>{failure.title}</strong><span>{failure.failureType.replaceAll('_', ' ')}</span></div>
                    <p>{failure.reason}</p>
                    <div className="source-failure-meta"><span>{failure.domain} · failed {formatTimestamp(failure.failedAt)}</span><strong>Requirement coverage: {failure.coverageImpact}</strong></div>
                    <small>{failure.affectedRequirementIds.length ? `Unresolved requirements: ${failure.affectedRequirementIds.join(', ')}` : 'No unresolved requirement was attributed to this source failure.'}</small>
                    {failure.url && <a href={failure.url} target="_blank" rel="noreferrer noopener">Open source URL</a>}
                  </article>)}
                </section>}
              </div>
            </section>

            <section className="panel results-panel">
              <div className="panel-header results-header">
                <div><span className="eyebrow">FINDINGS</span><h2>Research results <span className="count-badge">{displayClaims.length}</span></h2></div>
                <div className="result-filters">
                  <button className={claimFilter === 'all' ? 'filter-active' : ''} onClick={() => setClaimFilter('all')}>All</button>
                  <button className={claimFilter === 'verified' ? 'filter-active' : ''} onClick={() => setClaimFilter('verified')}>Verified</button>
                  <button className={claimFilter === 'review' ? 'filter-active' : ''} onClick={() => setClaimFilter('review')}>Needs review</button>
                </div>
              </div>
              <div className="results-layout">
                <div className="result-list">
                  {filteredClaims.length ? filteredClaims.map(claim => (
                    <button
                      key={claim.id}
                      className={`result-card ${selectedClaim?.id === claim.id ? 'selected' : ''}`}
                      onClick={() => setSelectedClaimId(claim.id)}
                    >
                      <div className="result-card-top">
                        <span className="claim-category">{claim.category}</span>
                        <StatusBadge status={claim.status} />
                      </div>
                      <h3>{claim.fact}</h3>
                      <p>{claim.detail}</p>
                      <div className="source-row">
                        <Icon name="globe" size={14} /><span>{claim.source}</span>
                        <Icon name="external" size={13} />
                      </div>
                    </button>
                  )) : (
                    <div className="empty-state results-empty"><Icon name="search" /><span>{taskData?.partial_failures?.length ? taskData.partial_failures.join(' ') : 'No extracted claims yet.'}</span></div>
                  )}
                </div>

                {selectedClaim ? <aside className="evidence-panel">
                  <div className="evidence-heading">
                    <div><span className="eyebrow">EVIDENCE</span><h2>{selectedClaim.category}</h2></div>
                    <StatusBadge status={selectedClaim.status} />
                  </div>
                  <div className="evidence-fact">
                    <span>EXTRACTED CLAIM</span>
                    <strong>{selectedClaim.fact}</strong>
                  </div>
                  {(selectedClaim.numericValue !== null || selectedClaim.unit || selectedClaim.currency || selectedClaim.context.length > 0) && <div className="evidence-observation">
                    <span>STRUCTURED OBSERVATION</span>
                    <strong>{selectedClaim.currencySymbol || selectedClaim.currency || ''}{selectedClaim.numericValue ?? selectedClaim.fact}{selectedClaim.unit ? ` ${selectedClaim.unit}` : ''}</strong>
                    {selectedClaim.currency && <small>Original currency: {selectedClaim.currency}; no conversion applied</small>}
                    {selectedClaim.context.length > 0 && <small>Context: {selectedClaim.context.join(', ').replaceAll('_', ' ')}</small>}
                    {selectedClaim.sourceDomain && <small>Source domain: {selectedClaim.sourceDomain}</small>}
                  </div>}
                  <div className="evidence-quote">
                    <span>SUPPORTING EXCERPT</span>
                    <blockquote>{selectedClaim.evidence}</blockquote>
                  </div>
                  <div className="evidence-source">
                    <div className="domain-icon">{selectedClaim.source[0].toUpperCase()}</div>
                    <div><strong>{selectedClaim.source}</strong><span>Observed {formatTimestamp(selectedClaim.timestamp)}</span></div>
                    {selectedClaim.url ? <a href={selectedClaim.url} target="_blank" rel="noreferrer noopener" aria-label={`Open ${selectedClaim.source}`}><Icon name="external" size={16} /></a> : <span className="trust-link-unavailable">Link unavailable</span>}
                  </div>
                  <div className={`verification-note ${selectedClaim.status.toLowerCase()}`}>
                    <Icon name={selectedClaim.status === 'Supported' ? 'shield' : 'clock'} size={16} />
                    <div>
                      <strong>{selectedClaim.status === 'Supported' ? 'Evidence matched' : selectedClaim.status === 'Contradicted' ? 'Evidence conflict' : 'Evidence incomplete'}</strong>
                      <span>{selectedClaim.status === 'Supported' ? 'The claim is directly supported by the source.' : 'Review the excerpt before relying on this claim.'}</span>
                    </div>
                  </div>
                </aside> : (
                  <aside className="evidence-panel"><div className="empty-state"><Icon name="file" /><span>Select a result when evidence is available.</span></div></aside>
                )}
              </div>
            </section>

            <section className="panel approval-panel">
              <div className="panel-header">
                <div><span className="eyebrow">PERMITTED ACTION</span><h2>Demo action contract</h2></div>
                <span className={`action-status action-status-${(actionContract?.status || 'none').toLowerCase()}`}>
                  {actionContract?.status || (taskStatus === 'completed' ? 'No action' : 'Unavailable')}
                </span>
              </div>
              {canPrepareDemoAction && (
                <div className="action-preparation">
                  <p>Prepare a request for the local demo form. Preparation does not submit it; the exact payload and evidence will be shown for review first.</p>
                  <label>Selected product
                  <select value={selectedProduct} onChange={event => setActionForm(current => ({ ...current, laptop: event.target.value }))}>
                      {supportedProducts.map(product => <option key={product} value={product}>{product}</option>)}
                    </select>
                  </label>
                  {[
                    ['budget', 'Budget'], ['ram', 'RAM'], ['gpu', 'GPU'], ['reason', 'Reason'],
                  ].map(([field, label]) => (
                    <label key={field}>{label}
                      <input
                        value={actionForm[field]}
                        onChange={event => setActionForm(current => ({ ...current, [field]: event.target.value }))}
                        maxLength={field === 'reason' ? 1000 : 100}
                      />
                    </label>
                  ))}
                  <div className="action-policy-note">Target: <code>{DEMO_TARGET_URL}</code><br />Required hard constraints: {proofContract.requirements.filter(item => item.hard_constraint).map(item => item.id).join(', ') || 'none'}.</div>
                  <div className="approval-actions">
                    <button className="approve-button" onClick={prepareDemoAction} disabled={actionBusy || !selectedProduct || !actionForm.budget.trim() || !actionForm.ram.trim() || !actionForm.gpu.trim() || !actionForm.reason.trim() || !supportedProducts.length}>
                      {actionBusy ? 'Preparing...' : 'Prepare exact action'}
                    </button>
                  </div>
                </div>
              )}
              {!actionContract && !canPrepareDemoAction && (
                <div className="empty-state approval-empty"><Icon name="shield" /><span>
                  {taskStatus !== 'completed'
                    ? 'A completed research report and ProofContract are required before preparing a demo action.'
                    : contractAllowsDemoAction && browserStatus.supports_demo_actions !== true
                      ? 'The selected browser provider must support the controlled demo form.'
                      : proofContract
                        ? 'The ProofContract does not authorize a demo form submission.'
                      : 'Loading the ProofContract and any saved action...'}
                </span></div>
              )}
              {actionContract && (
                <div className="action-contract-content">
                  <div className="action-summary">
                    <div className="action-icon"><Icon name="file" /></div>
                    <div><strong>{actionContract.target_description}</strong><span>{actionContract.action_type} · ProofContract v{actionContract.contract_version}</span><CopyValue value={actionContract.action_id} label="ActionContract ID" /></div>
                  </div>
                  <div className="action-review-section">
                    <h3>Target</h3>
                    {safeExternalUrl(actionContract.target_url) ? <a href={safeExternalUrl(actionContract.target_url)} target="_blank" rel="noreferrer noopener">{actionContract.target_url}</a> : <span>{actionContract.target_url} · external link unavailable</span>}
                    <span>{actionContract.target_domain}</span>
                  </div>
                  <div className="action-review-section">
                    <h3>Exact payload</h3>
                    <dl className="action-payload">
                      {Object.entries(actionContract.payload || {}).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{String(value)}</dd></div>)}
                    </dl>
                  </div>
                  <div className="action-review-section">
                    <h3>Preconditions</h3>
                    <ul>{actionContract.preconditions.map(item => <li key={item.condition_id}>{item.description} <strong>{item.satisfied ? 'Satisfied' : 'Not satisfied'}</strong></li>)}</ul>
                  </div>
                  <div className="action-review-section">
                    <h3>Expected postconditions</h3>
                    <ul>{actionContract.expected_postconditions.map(item => <li key={item.condition_id}>{item.description}</li>)}</ul>
                  </div>
                  <div className="action-review-section action-references">
                    <h3>Authorization references</h3>
                    <span>Requirements: {actionContract.associated_requirement_ids.join(', ') || 'none'}</span>
                    <span>Target policy: {actionContract.permission_context.target_policy}</span>
                    <h3>Associated evidence</h3>
                    <ul className="action-evidence-list">{actionContract.associated_evidence_ids.map(evidenceId => {
                      const evidence = taskData?.research_report?.evidence?.find(item => item.evidence_id === evidenceId)
                      return <li key={evidenceId}>
                        {evidence ? <>
                          <strong>{evidence.subject} · {evidence.field}: {evidence.value}</strong>
                          {safeExternalUrl(evidence.source_url) ? <a href={safeExternalUrl(evidence.source_url)} target="_blank" rel="noreferrer noopener">{evidence.source_title}</a> : <span>External link unavailable · {evidence.source_title}</span>}
                          <span>{evidence.supporting_text}</span>
                        </> : <span>{evidenceId}</span>}
                      </li>
                    })}</ul>
                    <h3>Approval and idempotency</h3>
                    <span>Approval state: {actionIntegrity.authorization}</span>
                    <span>Digest binding: {actionIntegrity.approvalBinding}</span>
                     <span>Idempotency key: <CopyValue value={actionContract.idempotency_key} label="idempotency key" /></span>
                    <span>Idempotency state: {executionReceipt ? 'Receipt persisted for this action' : actionContract.status === 'OUTCOME_UNKNOWN' ? 'Outcome unknown; reconcile before any retry' : 'Key assigned; no receipt recorded yet'}</span>
                    <div className="digest-row"><span>Approval digest (prepared): <code>{actionContract.approval_digest.slice(0, 16)}…</code></span><button type="button" className="copy-digest-button" onClick={copyApprovalDigest}>{copiedDigest === actionContract.approval_digest ? 'Copied' : 'Copy digest'}</button></div>
                    <details><summary>Inspect full approval digest</summary><code className="full-digest">{actionContract.approval_digest}</code></details>
                    {actionContract.approved_digest && <details><summary>Inspect approved digest</summary><code className="full-digest">{actionContract.approved_digest}</code></details>}
                    <small className="digest-explainer">A matching digest binds approval to this prepared action. Backend permission and precondition checks still apply.</small>
                  </div>
                  <div className="action-review-section">
                    <h3>Prohibited effects</h3>
                    <ul>{actionContract.prohibited_effects.map(effect => <li key={effect}>{effect}</li>)}</ul>
                  </div>
                  <WarrantReview
                    action={actionContract}
                    originalTask={taskData?.task}
                    receipt={executionReceipt}
                    review={currentWarrantReview?.review}
                    policyDecisions={currentWarrantReview?.policyDecisions || []}
                    error={currentWarrantReview?.error}
                    busy={actionBusy}
                    onRefresh={() => setWarrantRefresh(version => version + 1)}
                  />
                  {actionContract.status === 'PENDING_APPROVAL' && (
                    <div className="approval-actions">
                      <button className="cancel-button" onClick={rejectAction} disabled={actionBusy}>Reject action</button>
                      <button className="approve-button" onClick={approveAction} disabled={actionBusy || !warrantPermission.canApprove}><Icon name="shield" size={16} /> {actionBusy ? 'Saving...' : 'Approve Warrant'}</button>
                    </div>
                  )}
                  {actionContract.status === 'APPROVED' && (
                    <div className="approval-actions">
                      {actionContract.approved_warrant_hash && (
                        <span className="action-approved-note">Warrant approved: {actionContract.approved_warrant_hash.slice(0, 16)}…</span>
                      )}
                      {!actionContract.warrant && <button className="cancel-button" onClick={rejectAction} disabled={actionBusy}>Discard legacy approval</button>}
                      <button className="approve-button" onClick={executeAction} disabled={actionBusy || !warrantPermission.canExecute}><Icon name="send" size={15} /> {actionBusy ? 'Executing...' : 'Execute approved action'}</button>
                    </div>
                  )}
                  {actionContract.status === 'OUTCOME_UNKNOWN' && (
                    <div className="unknown-outcome">
                      <p>The submission may have reached the demo server. Reconciliation checks the durable record without repeating the submission.</p>
                      <button className="approve-button" onClick={reconcileAction} disabled={actionBusy}>{actionBusy ? 'Checking record...' : 'Reconcile outcome'}</button>
                    </div>
                  )}
                  {executionReceipt && (
                    <section className={`execution-receipt ${executionReceipt.outcome_verified && executionReceipt.execution_status === 'VERIFIED_SUCCESS' ? 'receipt-success' : 'receipt-unverified'}`}>
                      <h3>Persisted proof receipt</h3>
                      <strong>{executionReceipt.outcome_verified && executionReceipt.execution_status === 'VERIFIED_SUCCESS' ? 'Outcome independently verified' : `Outcome: ${executionReceipt.execution_status}`}</strong>
                      <dl>
                        <div><dt>Receipt</dt><dd><CopyValue value={executionReceipt.receipt_id} label="execution receipt ID" /></dd></div>
                        <div><dt>Task</dt><dd><CopyValue value={executionReceipt.task_id} label="receipt task ID" /></dd></div>
                        <div><dt>Action</dt><dd><CopyValue value={executionReceipt.action_id} label="receipt ActionContract ID" /> · {executionReceipt.action_type}</dd></div>
                        <div><dt>Prepared action approval</dt><dd>{actionIntegrity.authorization}</dd></div>
                        <div><dt>Approved digest</dt><dd><CopyValue value={executionReceipt.approved_digest} label="receipt approved digest" /></dd></div>
                        {executionReceipt.approved_warrant_hash && (
                          <div><dt>Approved Warrant hash</dt><dd><CopyValue value={executionReceipt.approved_warrant_hash} label="receipt approved Warrant hash" /></dd></div>
                        )}
                        <div><dt>Action attempted</dt><dd>{executionReceipt.action_attempted ? 'Yes' : 'No'}</dd></div>
                        <div><dt>Action completed</dt><dd>{executionReceipt.action_completed ? 'Yes' : 'No'}</dd></div>
                        <div><dt>Outcome verified</dt><dd>{executionReceipt.outcome_verified ? 'Yes' : 'No'} · {executionReceipt.verification_status}</dd></div>
                        <div><dt>Approval timestamp</dt><dd>{formatTimestamp(executionReceipt.approval_timestamp)}</dd></div>
                        <div><dt>Execution timestamp</dt><dd>{formatTimestamp(executionReceipt.execution_timestamp)}</dd></div>
                        <div><dt>Verification timestamp</dt><dd>{formatTimestamp(executionReceipt.verification_timestamp)}</dd></div>
                        <div><dt>Target</dt><dd>{safeExternalUrl(executionReceipt.target_url) ? <a href={safeExternalUrl(executionReceipt.target_url)} target="_blank" rel="noreferrer noopener">{executionReceipt.target_url}</a> : 'External link unavailable'}</dd></div>
                        <div><dt>Idempotency reference</dt><dd><CopyValue value={actionContract?.idempotency_key} label="receipt idempotency reference" /></dd></div>
                        <div><dt>Reconciliation</dt><dd>{executionReceipt.execution_status === 'OUTCOME_UNKNOWN' ? 'Required; outcome remains uncertain' : 'No unresolved outcome reported'}</dd></div>
                        {executionReceipt.resulting_record_id && <div><dt>Demo record</dt><dd><CopyValue value={executionReceipt.resulting_record_id} label="demo record ID" /></dd></div>}
                      </dl>
                      <div className="receipt-payload"><strong>Executed payload</strong><dl>{Object.entries(executionReceipt.payload || {}).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{String(value)}</dd></div>)}</dl></div>
                      {executionReceipt.verified_postconditions?.length > 0 && <p>Verified: {executionReceipt.verified_postconditions.join('; ')}</p>}
                      {executionReceipt.failed_postconditions?.length > 0 && <p>Not verified: {executionReceipt.failed_postconditions.join('; ')}</p>}
                      {executionReceipt.execution_error && <p className="receipt-error">{executionReceipt.execution_error}</p>}
                      <details className="receipt-details"><summary>Inspect full receipt</summary><pre>{JSON.stringify(executionReceipt, null, 2)}</pre></details>
                    </section>
                  )}
                </div>
              )}
            </section>

            <section className="panel audit-panel">
              <div className="panel-header">
                <div><span className="eyebrow">AUDIT TRAIL</span><h2>Execution history</h2></div>
                <button
                  className="text-button"
                  disabled={!taskData}
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(taskData, null, 2)], { type: 'application/json' })
                    const url = URL.createObjectURL(blob)
                    const anchor = document.createElement('a')
                    anchor.href = url
                    anchor.download = `${taskData?.id || 'proofpilot-task'}.json`
                    anchor.click()
                    URL.revokeObjectURL(url)
                  }}
                >
                  Export JSON
                </button>
              </div>
              <div className="audit-list">
                {taskData?.audit?.length ? taskData.audit.map((item) => (
                  <div className="audit-row" key={item.id}>
                    <time>{new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</time>
                    <code>{item.action}</code><span>{item.detail}</span><b>{item.actor}</b>
                  </div>
                )) : (
                  <div className="empty-state"><Icon name="history" /><span>No audit events yet.</span></div>
                )}
              </div>
            </section>
          </div>}
        </div>
      </main>

    </div>
  )
}

export default App
