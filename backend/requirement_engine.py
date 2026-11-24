import re
from collections import defaultdict

from models import (
    ActionType,
    Claim,
    CompletionCriterionResult,
    CompletionCriterionStatus,
    ContractAmbiguity,
    EvidenceExtractionStatus,
    EvidenceRecord,
    ProofContract,
    Requirement,
    RequirementEvaluation,
    RequirementEvaluationStatus,
    RequirementOperator,
    ResearchReport,
    ResearchExecutionStatus,
    ResearchSourceSummary,
    ResearchReportStatus,
    SourceAttemptRecord,
    SourceFailureCategory,
    SourceRecord,
    VerificationStatus,
)
from observation import normalize_currency, parse_observation


_READ_ONLY_RESEARCH_ACTIONS = {
    ActionType.SEARCH_PUBLIC_WEB,
    ActionType.BROWSE_PUBLIC_PAGE,
    ActionType.EXTRACT_EVIDENCE,
}
class ContractPermissionError(PermissionError):
    pass


def enforce_research_permission(contract: ProofContract, action: ActionType) -> None:
    if action in contract.prohibited_actions:
        raise ContractPermissionError(f"The Proof Contract prohibits {action.value}.")
    if action not in contract.allowed_actions:
        raise ContractPermissionError(f"The Proof Contract does not allow {action.value}.")
    if action in contract.requires_approval_for:
        raise ContractPermissionError(f"{action.value} requires approval and cannot run during research.")
    if action not in _READ_ONLY_RESEARCH_ACTIONS:
        raise ContractPermissionError(f"{action.value} is not a read-only research action.")


def _canonical_field(field: str) -> str:
    normalized = re.sub(r"[^a-z0-9]", "", field.casefold())
    aliases = {
        "cost": "price",
        "price": "price",
        "warrantyyears": "warranty",
        "warranty": "warranty",
        "storagecapacity": "capacity",
        "capacity": "capacity",
        "storage": "capacity",
        "memory": "ram",
        "ram": "ram",
        "cpu": "processor",
        "processor": "processor",
        "gpu": "gpu",
        "interface": "interface",
        "usb": "interface",
        "thunderbolt": "interface",
    }
    return aliases.get(normalized, normalized)


def _subject_matches(requirement: Requirement, claim: Claim) -> bool:
    if not requirement.subject:
        return True
    normalize = lambda value: " ".join(re.sub(r"[^a-z0-9]+", " ", value.casefold()).split())
    return normalize(requirement.subject) == normalize(claim.subject)


def _field_matches(requirement: Requirement, claim: Claim) -> bool:
    required_field = _canonical_field(requirement.field)
    observed_field = _canonical_field(claim.field)
    if required_field == observed_field:
        return True

    # The existing extractor labels GB/TB values as RAM. Treat a TB value as
    # storage capacity only when its actual excerpt identifies storage or an SSD.
    if required_field == "capacity" and observed_field == "ram":
        quote = claim.evidence.quote.casefold()
        is_tb_value = bool(re.search(r"\b\d+(?:\.\d+)?\s*tb\b", claim.value, re.IGNORECASE))
        return is_tb_value and any(word in quote for word in ("storage", "capacity", "ssd"))
    return False


def _matching_claims(requirement: Requirement, claims: list[Claim]) -> list[Claim]:
    return [
        claim
        for claim in claims
        if _claim_matches_requirement(requirement, claim)
    ]


_IRRELEVANT_PRICE_CONTEXTS = {
    "upgrade_cost",
    "cloud_cost",
    "accessory_price",
    "discount_amount",
    "promotional_amount",
    "historical_price",
    "comparison_price",
    "estimated_price",
    "starting_price",
    "ambiguous_price",
}
_IRRELEVANT_SPEC_CONTEXTS = {"upgrade_option", "maximum_configuration"}


def _claim_matches_requirement(requirement: Requirement, claim: Claim) -> bool:
    if not _field_matches(requirement, claim) or not _subject_matches(requirement, claim):
        return False
    if _canonical_field(requirement.field) == "price":
        return not bool(_IRRELEVANT_PRICE_CONTEXTS.intersection(claim.context))
    if _canonical_field(requirement.field) == "ram":
        return not bool(_IRRELEVANT_SPEC_CONTEXTS.intersection(claim.context))
    return True


def map_evidence_to_requirements(
    contract: ProofContract,
    claims: list[Claim],
) -> list[EvidenceRecord]:
    records: list[EvidenceRecord] = []
    for claim in claims:
        requirement_ids = [
            requirement.id
            for requirement in contract.requirements
            if _claim_matches_requirement(requirement, claim)
        ]
        status = {
            VerificationStatus.SUPPORTED: EvidenceExtractionStatus.SUPPORTED,
            VerificationStatus.CONTRADICTED: EvidenceExtractionStatus.CONTRADICTED,
            VerificationStatus.UNVERIFIED: EvidenceExtractionStatus.UNVERIFIED,
        }.get(claim.verification_status, EvidenceExtractionStatus.EXTRACTED)
        records.append(
            EvidenceRecord(
                evidence_id=claim.id,
                subject=claim.subject,
                field=claim.field,
                value=claim.value,
                source_url=claim.evidence.source_url,
                source_domain=claim.source_domain,
                source_title=claim.evidence.source_title,
                supporting_text=claim.evidence.quote,
                observed_at=claim.evidence.timestamp,
                numeric_value=claim.numeric_value if claim.numeric_value is not None else parse_observation(claim.value, claim.field).numeric_value,
                unit=claim.unit or parse_observation(claim.value, claim.field).unit,
                currency=claim.currency or parse_observation(claim.value, claim.field).currency,
                currency_symbol=claim.currency_symbol or parse_observation(claim.value, claim.field).currency_symbol,
                context=claim.context,
                associated_requirement_ids=requirement_ids,
                extraction_status=status,
            )
        )
    return records


def _expected_is_valid(requirement: Requirement) -> bool:
    expected = requirement.expected
    operator = requirement.operator
    if operator == RequirementOperator.EXISTS:
        return expected is None
    if operator in {RequirementOperator.LTE, RequirementOperator.GTE}:
        return isinstance(expected, (int, float)) and not isinstance(expected, bool)
    if operator == RequirementOperator.CONTAINS:
        return isinstance(expected, str)
    if operator == RequirementOperator.ONE_OF:
        if not isinstance(expected, list) or not expected:
            return False
        first = expected[0]
        if isinstance(first, str):
            return all(isinstance(value, str) for value in expected)
        if isinstance(first, (int, float)) and not isinstance(first, bool):
            return all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in expected)
        return False
    return isinstance(expected, (str, int, float)) and not isinstance(expected, bool)


def _parsed_claim(claim: Claim):
    parsed = parse_observation(claim.value, claim.field)
    return {
        "numeric_value": claim.numeric_value if claim.numeric_value is not None else parsed.numeric_value,
        "unit": claim.unit or parsed.unit,
        "currency": claim.currency or parsed.currency,
        "currency_symbol": claim.currency_symbol or parsed.currency_symbol,
    }


def _normalized_observation(requirement: Requirement, claim: Claim):
    expected = requirement.expected
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        return _parsed_claim(claim)["numeric_value"]
    if isinstance(expected, list):
        if not expected:
            return None
        if isinstance(expected[0], (int, float)) and not isinstance(expected[0], bool):
            return _parsed_claim(claim)["numeric_value"]
        if all(isinstance(value, str) for value in expected):
            return claim.value.strip().casefold()
        return None
    if isinstance(expected, str):
        return claim.value.strip().casefold()
    if requirement.operator == RequirementOperator.EXISTS:
        return claim.value.strip()
    return None


def _evaluate_value(requirement: Requirement, claim: Claim) -> tuple[RequirementEvaluationStatus, str]:
    if not _expected_is_valid(requirement):
        return RequirementEvaluationStatus.INVALID_EVIDENCE, "The requirement's expected value has an incompatible type for its operator."

    expected = requirement.expected
    if requirement.operator == RequirementOperator.EXISTS:
        return RequirementEvaluationStatus.SATISFIED, "A source-backed value exists for this requirement."

    observed = _parsed_claim(claim)
    required_field = _canonical_field(requirement.field)
    is_price = required_field == "price"
    numeric_expected = isinstance(expected, (int, float)) and not isinstance(expected, bool)
    numeric_list = isinstance(expected, list) and expected and isinstance(expected[0], (int, float)) and not isinstance(expected[0], bool)

    if numeric_expected or numeric_list:
        if observed["numeric_value"] is None:
            return RequirementEvaluationStatus.INVALID_EVIDENCE, "The extracted observation is not a parseable numeric value for this requirement."
        if is_price:
            required_currency = normalize_currency(requirement.unit)
            if required_currency is None:
                return RequirementEvaluationStatus.UNVERIFIED, "The ProofContract does not specify an unambiguous price currency. No currency comparison was made."
            observed_currency = observed["currency"]
            if observed_currency is None:
                return RequirementEvaluationStatus.UNVERIFIED, "The observed price currency is missing or ambiguous. No conversion rate, source, and timestamp are available."
            if observed_currency != required_currency:
                return RequirementEvaluationStatus.UNVERIFIED, (
                    f"The observed price is {observed_currency}, but the requirement is {required_currency}; "
                    "no conversion rate, source, and timestamp are available."
                )
        elif requirement.unit:
            expected_unit = requirement.unit.casefold()
            observed_unit = (observed["unit"] or "").casefold()
            unit_aliases = {"year": "years", "yr": "years", "yrs": "years"}
            expected_unit = unit_aliases.get(expected_unit, expected_unit)
            observed_unit = unit_aliases.get(observed_unit, observed_unit)
            if expected_unit != observed_unit:
                return RequirementEvaluationStatus.UNVERIFIED, (
                    f"The observed unit {observed['unit'] or 'is missing'} does not match the required "
                    f"{requirement.unit}; no unit conversion was applied."
                )
        elif observed["unit"] or observed["currency"] or observed["currency_symbol"]:
            return RequirementEvaluationStatus.UNVERIFIED, "The observation has a unit or currency, but the requirement does not specify one."

    normalized = _normalized_observation(requirement, claim)
    if normalized is None:
        return RequirementEvaluationStatus.UNVERIFIED, "The observed value cannot be evaluated without an unsupported unit or currency assumption."

    if requirement.operator == RequirementOperator.EQ:
        target = expected if not isinstance(expected, str) else expected.strip().casefold()
        matched = normalized == target
    elif requirement.operator == RequirementOperator.LTE:
        target = expected
        matched = normalized <= target
    elif requirement.operator == RequirementOperator.GTE:
        target = expected
        matched = normalized >= target
    elif requirement.operator == RequirementOperator.CONTAINS:
        target = expected.strip().casefold()
        matched = target in normalized
    elif requirement.operator == RequirementOperator.ONE_OF:
        if isinstance(expected[0], str):
            matched = normalized in {value.strip().casefold() for value in expected}
        else:
            matched = normalized in expected
    else:
        return RequirementEvaluationStatus.INVALID_EVIDENCE, "The requirement operator is not supported."

    if matched:
        return RequirementEvaluationStatus.SATISFIED, "The verified source value satisfies the requirement."
    return RequirementEvaluationStatus.NOT_SATISFIED, "The verified source value does not satisfy the requirement."


def _claim_value_key(requirement: Requirement, claim: Claim):
    normalized = _normalized_observation(requirement, claim)
    if normalized is not None:
        parsed = _parsed_claim(claim)
        return (type(normalized).__name__, normalized, parsed["unit"], parsed["currency"])
    return ("raw", claim.value.strip().casefold())


def _evaluate_group(
    requirement: Requirement,
    claims: list[Claim],
    blocking_requirement_ids: set[str],
) -> RequirementEvaluation:
    evidence_ids = list(dict.fromkeys(claim.id for claim in claims))
    subject = claims[0].subject if claims else requirement.subject
    observed_values = list(dict.fromkeys(claim.value for claim in claims))
    observed_value = "; ".join(observed_values) if observed_values else None
    parsed_observations = [_parsed_claim(claim) for claim in claims]
    numeric_values = {item["numeric_value"] for item in parsed_observations if item["numeric_value"] is not None}
    units = {item["unit"] for item in parsed_observations if item["unit"]}
    currencies = {item["currency"] for item in parsed_observations if item["currency"]}
    currency_symbols = {item["currency_symbol"] for item in parsed_observations if item["currency_symbol"]}
    is_price = _canonical_field(requirement.field) == "price"
    required_currency = normalize_currency(requirement.unit) if is_price else None
    base = {
        "requirement_id": requirement.id,
        "requirement_description": requirement.label,
        "subject": subject,
        "expected": requirement.expected,
        "required_unit": requirement.unit if not is_price else None,
        "required_currency": required_currency,
        "observed_value": observed_value,
        "observed_numeric_value": next(iter(numeric_values)) if len(numeric_values) == 1 else None,
        "observed_unit": next(iter(units)) if len(units) == 1 else None,
        "observed_currency": next(iter(currencies)) if len(currencies) == 1 else None,
        "observed_currency_symbol": next(iter(currency_symbols)) if len(currency_symbols) == 1 else None,
        "evidence_ids": evidence_ids,
    }

    if not claims:
        return RequirementEvaluation(
            **base,
            status=RequirementEvaluationStatus.UNVERIFIED,
            reason="No extracted source evidence was mapped to this requirement.",
        )

    contradicted = [claim for claim in claims if claim.verification_status == VerificationStatus.CONTRADICTED]
    supported = [claim for claim in claims if claim.verification_status == VerificationStatus.SUPPORTED]
    if contradicted:
        return RequirementEvaluation(
            **base,
            status=RequirementEvaluationStatus.CONFLICTING_EVIDENCE,
            reason="At least one collected excerpt contradicts its extracted value.",
        )

    if not supported:
        status = (
            RequirementEvaluationStatus.INVALID_EVIDENCE
            if any(claim.verification_status != VerificationStatus.UNVERIFIED for claim in claims)
            else RequirementEvaluationStatus.UNVERIFIED
        )
        return RequirementEvaluation(
            **base,
            status=status,
            reason="Mapped evidence has not been verified against the collected source page.",
        )

    value_results = [_evaluate_value(requirement, claim) for claim in supported]
    unresolved_value = next(
        (item for item in value_results if item[0] in {RequirementEvaluationStatus.UNVERIFIED, RequirementEvaluationStatus.INVALID_EVIDENCE}),
        None,
    )
    if unresolved_value:
        return RequirementEvaluation(
            **base,
            status=unresolved_value[0],
            reason=unresolved_value[1],
        )

    value_keys = {_claim_value_key(requirement, claim) for claim in supported}
    if len(value_keys) > 1:
        return RequirementEvaluation(
            **base,
            status=RequirementEvaluationStatus.CONFLICTING_EVIDENCE,
            reason="Verified sources report different values for the same subject and requirement.",
        )

    if any(claim.verification_status == VerificationStatus.UNVERIFIED for claim in claims):
        return RequirementEvaluation(
            **base,
            status=RequirementEvaluationStatus.UNVERIFIED,
            reason="Some mapped source evidence could not be verified.",
        )

    if requirement.id in blocking_requirement_ids:
        return RequirementEvaluation(
            **base,
            status=RequirementEvaluationStatus.UNVERIFIED,
            reason="A blocking contract ambiguity prevents evaluating this requirement conclusively.",
        )

    status, reason = value_results[0]
    return RequirementEvaluation(**base, status=status, reason=reason)


def evaluate_requirements(
    contract: ProofContract,
    claims: list[Claim],
    blocking_requirement_ids: set[str] | None = None,
) -> list[RequirementEvaluation]:
    blocking_ids = blocking_requirement_ids or set()
    evaluations: list[RequirementEvaluation] = []
    for requirement in contract.requirements:
        mapped = _matching_claims(requirement, claims)
        if not mapped:
            evaluations.append(_evaluate_group(requirement, [], blocking_ids))
            continue

        groups: dict[str, list[Claim]] = defaultdict(list)
        for claim in mapped:
            groups[claim.subject.casefold().strip()].append(claim)
        for subject_claims in groups.values():
            evaluations.append(_evaluate_group(requirement, subject_claims, blocking_ids))
    return evaluations


def _completion_results(
    contract: ProofContract,
    evaluations: list[RequirementEvaluation],
    evidence: list[EvidenceRecord],
    failures: list[str],
) -> list[CompletionCriterionResult]:
    unresolved_requirements = any(
        item.status in {
            RequirementEvaluationStatus.UNVERIFIED,
            RequirementEvaluationStatus.CONFLICTING_EVIDENCE,
            RequirementEvaluationStatus.INVALID_EVIDENCE,
        }
        for item in evaluations
    )
    results = []
    for criterion in contract.completion_criteria:
        text = criterion.casefold()
        if "source" in text or "evidence" in text:
            if evidence:
                status = CompletionCriterionStatus.SATISFIED
                reason = "Source-linked evidence records were collected."
            else:
                status = CompletionCriterionStatus.UNVERIFIED
                reason = "No source-linked evidence was collected."
        elif "requirement" in text or "constraint" in text:
            evaluated_ids = {item.requirement_id for item in evaluations}
            if set(req.id for req in contract.requirements).issubset(evaluated_ids):
                status = CompletionCriterionStatus.SATISFIED
                reason = "Every contract requirement has an explicit evaluation result."
            else:
                status = CompletionCriterionStatus.UNVERIFIED
                reason = "At least one requirement has no evaluation result."
        elif any(word in text for word in ("ambiguity", "failure", "unresolved", "complete")):
            has_blocking_ambiguity = contract.clarification_required_before_research
            if has_blocking_ambiguity or failures or unresolved_requirements:
                status = CompletionCriterionStatus.NOT_SATISFIED
                reason = "A blocking ambiguity, unresolved requirement, or coverage-affecting source failure remains."
            else:
                status = CompletionCriterionStatus.SATISFIED
                reason = "No blocking ambiguity or material research failure remains."
        else:
            status = CompletionCriterionStatus.UNVERIFIED
            reason = "This completion criterion has no deterministic evaluator in this stage."
        results.append(CompletionCriterionResult(criterion=criterion, status=status, reason=reason))
    return results


def build_research_report(
    task_id: str,
    contract: ProofContract,
    claims: list[Claim],
    sources: list[SourceRecord],
    domains_rejected: list[str],
    research_failures: list[str],
    status_override: ResearchReportStatus | None = None,
    execution_status: ResearchExecutionStatus | None = None,
    source_attempts: list[SourceAttemptRecord] | None = None,
    sources_discovered: int = 0,
    sources_rejected: int = 0,
) -> ResearchReport:
    blocking_requirement_ids = {
        requirement_id
        for ambiguity in contract.ambiguities
        if ambiguity.blocking_stage in {"research", "execution"}
        for requirement_id in ambiguity.related_requirement_ids
    }
    evaluations = evaluate_requirements(contract, claims, blocking_requirement_ids)
    evidence = map_evidence_to_requirements(contract, claims)
    unresolved_ids = {
        item.requirement_id
        for item in evaluations
        if item.status in {
            RequirementEvaluationStatus.UNVERIFIED,
            RequirementEvaluationStatus.CONFLICTING_EVIDENCE,
            RequirementEvaluationStatus.INVALID_EVIDENCE,
        }
    }
    for source in sources:
        if source.failure_type is None:
            continue
        affected = set(source.affected_requirement_ids) or {item.id for item in contract.requirements}
        source.affected_requirement_ids = sorted(affected.intersection(unresolved_ids))
        source.coverage_impact = "unresolved" if source.affected_requirement_ids else "unaffected"

    coverage_failures = [
        f"{source.source_domain or source.url}: {source.failure_reason or source.blocked_reason or source.failure_type}"
        for source in sources
        if source.failure_type is not None and source.coverage_impact == "unresolved"
    ]
    completion = _completion_results(contract, evaluations, evidence, coverage_failures)

    if status_override is not None:
        status = status_override
    elif unresolved_ids or any(item.status != CompletionCriterionStatus.SATISFIED for item in completion):
        status = ResearchReportStatus.PARTIAL
    else:
        status = ResearchReportStatus.COMPLETED

    if execution_status is None:
        if status == ResearchReportStatus.BLOCKED:
            execution_status = ResearchExecutionStatus.BLOCKED
        elif status == ResearchReportStatus.FAILED:
            execution_status = ResearchExecutionStatus.FAILED
        elif research_failures:
            execution_status = ResearchExecutionStatus.COMPLETED_WITH_WARNINGS
        else:
            execution_status = ResearchExecutionStatus.COMPLETED

    attempts = list(source_attempts or [])
    page_attempts = [item for item in attempts if item.source_type == "page"]
    search_attempts = [item for item in attempts if item.source_type == "search"]
    by_source: dict[str, list[SourceAttemptRecord]] = defaultdict(list)
    for attempt in page_attempts:
        by_source[attempt.source_identifier].append(attempt)
    latest_attempts = [max(items, key=lambda item: item.attempt_number) for items in by_source.values()]
    supported_count = sum(item.status == RequirementEvaluationStatus.SATISFIED for item in evaluations)
    contradicted_count = sum(
        item.status in {RequirementEvaluationStatus.NOT_SATISFIED, RequirementEvaluationStatus.CONFLICTING_EVIDENCE}
        for item in evaluations
    )
    unresolved_count = sum(
        item.status in {
            RequirementEvaluationStatus.UNVERIFIED,
            RequirementEvaluationStatus.INVALID_EVIDENCE,
        }
        for item in evaluations
    )
    source_summary = ResearchSourceSummary(
        sources_discovered=max(0, sources_discovered),
        source_attempts=len(page_attempts),
        sources_attempted=len(by_source),
        sources_accessed=len({
            item.source_identifier for item in page_attempts
            if item.retrieval_succeeded
        }),
        sources_with_usable_evidence=len({
            item.source_identifier for item in page_attempts
            if item.evidence_extracted and item.affected_requirement_ids
        }),
        sources_failed=sum(item.failure_category != SourceFailureCategory.SUCCESS for item in latest_attempts),
        sources_rejected=max(0, sources_rejected),
        search_requests=len(search_attempts),
        search_failures=sum(item.failure_category != SourceFailureCategory.SUCCESS for item in search_attempts),
        recovery_attempts=len({
            item.recovery_operation_id for item in attempts if item.recovery_operation_id
        }),
        domains_represented=sorted({
            item.source_domain.lower()
            for item in evidence
            if item.source_domain
        }),
        requirements_supported=supported_count,
        requirements_contradicted=contradicted_count,
        requirements_unresolved=unresolved_count,
    )

    contradictions = [
        f"{item.subject + ': ' if item.subject else ''}{item.requirement_description}: {item.reason}"
        for item in evaluations
        if item.status == RequirementEvaluationStatus.CONFLICTING_EVIDENCE
    ]
    missing_information = [
        f"{item.subject + ': ' if item.subject else ''}{item.requirement_description}: {item.reason}"
        for item in evaluations
        if item.status in {
            RequirementEvaluationStatus.UNVERIFIED,
            RequirementEvaluationStatus.INVALID_EVIDENCE,
        }
    ]

    return ResearchReport(
        task_id=task_id,
        contract_version=contract.version,
        status=status,
        execution_status=execution_status,
        requirements=contract.requirements,
        evaluations=evaluations,
        evidence=evidence,
        contradictions=contradictions,
        missing_information=missing_information,
        sources_visited=sources,
        domains_rejected=sorted(set(domains_rejected)),
        completion_criteria=completion,
        unresolved_ambiguities=contract.ambiguities,
        research_failures=list(dict.fromkeys(research_failures)),
        source_attempts=attempts,
        source_summary=source_summary,
    )
