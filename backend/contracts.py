import json
import re

from llm import LLMConfigurationError, LLMProviderError, call_structured_llm
from pydantic import ValidationError

from models import (
    ActionType,
    ContractAmbiguity,
    ProofContract,
    Requirement,
    RequirementOperator,
)


class ContractInputError(ValueError):
    """The task input cannot be represented by a bounded proof contract."""


class ContractGenerationError(RuntimeError):
    """The configured model failed to return a valid proof contract."""


class ContractConflictError(RuntimeError):
    """The task changed while a contract was being generated."""


_RESEARCH_ACTIONS = [
    ActionType.SEARCH_PUBLIC_WEB,
    ActionType.BROWSE_PUBLIC_PAGE,
    ActionType.EXTRACT_EVIDENCE,
]
_NEVER_ALLOWED = [
    ActionType.BYPASS_AUTHENTICATION,
    ActionType.BYPASS_CAPTCHA,
    ActionType.BYPASS_ANTI_BOT,
]

_PRICE_LIMIT = re.compile(
    r"\b(?:under|below|less than|at most|no more than|maximum(?:\s+budget)?(?:\s+of)?|budget(?:\s+of|\s*[:=])?)"
    r"\s*(?P<currency>USD|GBP|EUR|INR|\u00c2\u00a3|\$|\u00a3|\u20ac|\u20b9)?\s*"
    r"(?P<amount>\d+(?:,\d{3})*(?:\.\d{1,2})?)",
    re.IGNORECASE,
)
_CAPACITY_LIMIT = re.compile(
    r"\b(?:at least|minimum(?:\s+of)?|no less than|>=)\s*"
    r"(?P<amount>\d+(?:\.\d+)?)\s*(?P<unit>TB|GB)\b",
    re.IGNORECASE,
)
_WARRANTY_LIMIT = re.compile(
    r"\b(?:at least|minimum(?:\s+of)?|no less than)\s*"
    r"(?P<amount>\d+)\s*(?:-\s*)?years?\s*(?:limited\s+)?warranty\b",
    re.IGNORECASE,
)
_DOMAIN_PATTERNS = (
    re.compile(r"\bsite:((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE),
    re.compile(
        r"\b(?:only|exclusively)\s+(?:use|search|browse|look)\s+"
        r"(?:at|on|from\s+)?((?:[a-z0-9-]+\.)+[a-z]{2,})\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:from|on|at|use|visit|search|browse)\s+(?:https?://)?"
        r"((?:[a-z0-9-]+\.)+[a-z]{2,})\b",
        re.IGNORECASE,
    ),
)

_ACTION_INTENTS: tuple[tuple[ActionType, re.Pattern], ...] = (
    (ActionType.PURCHASE, re.compile(r"\b(?:buy|purchase|order)\b", re.IGNORECASE)),
    (ActionType.BOOK, re.compile(r"\b(?:book|reserve)\b", re.IGNORECASE)),
    (ActionType.APPLY, re.compile(r"\bapply\b", re.IGNORECASE)),
    (ActionType.SUBMIT_FORM, re.compile(r"\bsubmit\b", re.IGNORECASE)),
    (ActionType.SEND_MESSAGE, re.compile(r"\b(?:send|email|message)\b", re.IGNORECASE)),
    (ActionType.MODIFY_ACCOUNT, re.compile(r"\b(?:change|update|edit)\s+(?:my\s+)?account\b", re.IGNORECASE)),
    (ActionType.DELETE_DATA, re.compile(r"\b(?:delete|remove)\s+(?:my\s+)?(?:data|account|record)\b", re.IGNORECASE)),
    (ActionType.DOWNLOAD_FILE, re.compile(r"\bdownload\b", re.IGNORECASE)),
)
_NEGATION = re.compile(r"(?:\bdo not|\bdon't|\bnever|\bwithout)\s*$", re.IGNORECASE)


def _number(text: str) -> int | float:
    value = float(text.replace(",", ""))
    return int(value) if value.is_integer() else value


def _currency_unit(currency: str | None) -> str | None:
    if not currency:
        return None
    normalized = currency.upper()
    return {
        "USD": "USD",
        "GBP": "GBP",
        "EUR": "EUR",
        "INR": "INR",
        "$": "currency",
        "\u00a3": "GBP",
        "\u00c2\u00a3": "GBP",
        "\u20ac": "EUR",
        "\u20b9": "INR",
    }.get(normalized)


def _action_intents(task: str) -> tuple[list[ActionType], list[ActionType]]:
    requested: list[ActionType] = []
    prohibited: list[ActionType] = []
    for action_type, pattern in _ACTION_INTENTS:
        for match in pattern.finditer(task):
            preceding_text = task[max(0, match.start() - 24) : match.start()]
            destination = prohibited if _NEGATION.search(preceding_text) else requested
            if action_type not in destination:
                destination.append(action_type)
    return requested, prohibited


def _explicit_domains(task: str) -> set[str]:
    return {
        match.group(1).lower().rstrip(".")
        for pattern in _DOMAIN_PATTERNS
        for match in pattern.finditer(task)
    }


def _validate_hard_values(contract: ProofContract, task: str, budget: str | None) -> None:
    source_text = task if not budget else f"{task}\nBudget: {budget}"
    source_numbers = {
        _number(match.group(0))
        for match in re.finditer(r"(?<!\w)\d[\d,]*(?:\.\d+)?", source_text)
    }

    def validate_expected(value) -> None:
        if isinstance(value, list):
            for item in value:
                validate_expected(item)
            return
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if value not in source_numbers:
                raise ContractGenerationError(
                    "The model introduced a numeric hard constraint that was not stated by the user."
                )
            return
        if isinstance(value, str):
            expected_numbers = {
                _number(match.group(0))
                for match in re.finditer(r"(?<!\w)\d[\d,]*(?:\.\d+)?", value)
            }
            if expected_numbers:
                if not expected_numbers.issubset(source_numbers):
                    raise ContractGenerationError(
                        "The model introduced a numeric hard constraint that was not stated by the user."
                    )
            elif value.casefold() not in source_text.casefold():
                raise ContractGenerationError(
                    "The model introduced a hard constraint value that was not stated by the user."
                )

    def validate_unit(unit: str) -> None:
        normalized = unit.casefold()
        currency_markers = {
            "currency": ("$",),
            "gbp": ("gbp", "pound", "\u00a3", "\u00c2\u00a3"),
            "usd": ("usd", "us$", "us dollar"),
            "eur": ("eur", "euro", "\u20ac"),
            "inr": ("inr", "indian rupee", "rupee", "\u20b9"),
        }
        if normalized in currency_markers:
            if not any(marker.casefold() in source_text.casefold() for marker in currency_markers[normalized]):
                raise ContractGenerationError(
                    "The model assigned a currency that the user did not specify."
                )
            return
        if normalized in {"gb", "tb"}:
            if not re.search(rf"\b{re.escape(normalized)}\b", source_text, re.IGNORECASE):
                raise ContractGenerationError("The model assigned a unit that the user did not specify.")
            return
        if normalized in {"year", "years"}:
            if not re.search(r"\byears?\b|\byrs?\b", source_text, re.IGNORECASE):
                raise ContractGenerationError("The model assigned a unit that the user did not specify.")
            return
        if normalized not in source_text.casefold():
            raise ContractGenerationError("The model assigned a unit that the user did not specify.")

    for requirement in contract.requirements:
        if not requirement.hard_constraint:
            continue
        if requirement.expected is None:
            field_aliases = {
                "goal": (),
                "price": ("price", "budget", "cost"),
                "capacity": ("capacity", "storage", "gb", "tb"),
                "storage_capacity": ("capacity", "storage", "gb", "tb"),
                "warranty": ("warranty",),
                "warranty_years": ("warranty",),
                "interface": ("interface", "usb", "thunderbolt"),
            }
            field_name = requirement.field.casefold()
            aliases = field_aliases.get(field_name, (field_name,))
            if field_name != "goal" and not any(
                alias in source_text.casefold() for alias in aliases
            ):
                raise ContractGenerationError(
                    "The model introduced a hard information requirement that the user did not state."
                )
        else:
            validate_expected(requirement.expected)
            if requirement.unit:
                validate_unit(requirement.unit)


def _deterministic_contract(task_id: str, task: str, budget: str | None) -> ProofContract:
    searchable_text = task
    if budget:
        searchable_text += f"\nBudget: {budget}"
    lowered = searchable_text.lower()

    requirements: list[Requirement] = []
    ambiguities: list[ContractAmbiguity] = []

    price_match = _PRICE_LIMIT.search(searchable_text)
    price_requirement_id = None
    if price_match:
        cue = price_match.group(0).lower()
        amount = _number(price_match.group("amount"))
        currency = price_match.group("currency")
        has_price_context = any(word in cue for word in ("budget", "price"))
        if currency or has_price_context or amount >= 100:
            price_requirement_id = "price_limit"
            requirements.append(
                Requirement(
                    id=price_requirement_id,
                    label=f"Price is no more than {price_match.group('amount')}",
                    field="price",
                    operator=RequirementOperator.LTE,
                    expected=amount,
                    unit=_currency_unit(currency),
                    hard_constraint=True,
                )
            )
            if currency == "$":
                ambiguities.append(
                    ContractAmbiguity(
                        id="currency_ambiguous",
                        description="The dollar symbol does not identify which currency the price limit uses.",
                        clarification_question="Which dollar currency should the price limit use (for example USD, CAD, or AUD)?",
                        related_requirement_ids=[price_requirement_id],
                        blocking_stage="execution",
                    )
                )
            elif not currency:
                ambiguities.append(
                    ContractAmbiguity(
                        id="price_currency_missing",
                        description="A numeric price limit was stated without a currency.",
                        clarification_question="Which currency applies to the price limit?",
                        related_requirement_ids=[price_requirement_id],
                        blocking_stage="execution",
                    )
                )

    capacity_match = _CAPACITY_LIMIT.search(searchable_text)
    if capacity_match:
        requirements.append(
            Requirement(
                id="capacity_minimum",
                label=f"Capacity is at least {capacity_match.group('amount')} {capacity_match.group('unit').upper()}",
                field="capacity",
                operator=RequirementOperator.GTE,
                expected=_number(capacity_match.group("amount")),
                unit=capacity_match.group("unit").upper(),
                hard_constraint=True,
            )
        )

    warranty_match = _WARRANTY_LIMIT.search(searchable_text)
    if warranty_match:
        requirements.append(
            Requirement(
                id="warranty_minimum",
                label=f"Warranty is at least {warranty_match.group('amount')} years",
                field="warranty_years",
                operator=RequirementOperator.GTE,
                expected=int(warranty_match.group("amount")),
                unit="years",
                hard_constraint=True,
            )
        )

    # When the user asks for a fact without setting a threshold, capture it as
    # information to collect rather than inventing a hard pass/fail constraint.
    informational_fields = (
        ("price", ("price", "budget", "cost")),
        ("warranty", ("warranty",)),
        ("interface", ("interface", "usb", "thunderbolt")),
        ("capacity", ("capacity", "storage")),
    )
    existing_fields = {item.field for item in requirements}
    if "warranty_years" in existing_fields:
        existing_fields.add("warranty")
    for field, terms in informational_fields:
        if field in existing_fields or not any(term in lowered for term in terms):
            continue
        req_id = f"collect_{field}"
        requirements.append(
            Requirement(
                id=req_id,
                label=f"Collect {field.replace('_', ' ')} information",
                field=field,
                operator=RequirementOperator.EXISTS,
                expected=None,
                hard_constraint=False,
            )
        )
        existing_fields.add(field)

        if field in {"price", "warranty", "capacity", "interface"} and re.search(
            r"\b(?:must|required|minimum|at least|no less than|under|below|at most)\b",
            lowered,
        ):
            ambiguity_id = f"{field}_criterion_unclear"
            ambiguities.append(
                ContractAmbiguity(
                    id=ambiguity_id,
                    description=f"The task refers to {field.replace('_', ' ')} as a constraint, but its threshold or exact value is unclear.",
                    clarification_question=f"What specific {field.replace('_', ' ')} requirement should be enforced?",
                    related_requirement_ids=[req_id],
                    blocking_stage="execution",
                )
            )

    if not requirements:
        requirements.append(
            Requirement(
                id="stated_goal",
                label="Address the user's stated goal",
                field="goal",
                operator=RequirementOperator.EXISTS,
                expected=None,
                hard_constraint=True,
            )
        )

    domain_matches = _explicit_domains(task)

    allowed_actions = list(_RESEARCH_ACTIONS)
    approval_actions, denied_actions = _action_intents(task)
    prohibited_actions = list(_NEVER_ALLOWED)
    for action_type in denied_actions:
        if action_type not in prohibited_actions:
            prohibited_actions.append(action_type)
    for action_type in approval_actions:
        if action_type not in allowed_actions:
            allowed_actions.append(action_type)

    completion_criteria = [
        "Return findings linked to source evidence.",
        "Report each hard requirement as supported, contradicted, or unknown.",
        "Do not claim completion while a blocking ambiguity or material failure remains unresolved.",
    ]
    if not any(item.hard_constraint for item in requirements if item.id != "stated_goal"):
        ambiguities.append(
            ContractAmbiguity(
                id="no_explicit_hard_constraints",
                description="No measurable hard constraints were confidently identified; no thresholds have been invented.",
                clarification_question="Are there any mandatory limits or specifications to enforce?",
                blocking_stage="none",
            )
        )

    blocks_research = any(item.blocking_stage == "research" for item in ambiguities)
    blocks_execution = any(item.blocking_stage == "execution" for item in ambiguities)
    return ProofContract(
        task_id=task_id,
        goal=task.strip(),
        requirements=requirements,
        allowed_domains=sorted(domain_matches),
        allowed_actions=allowed_actions,
        prohibited_actions=prohibited_actions,
        requires_approval_for=approval_actions,
        completion_criteria=completion_criteria,
        ambiguities=ambiguities,
        clarification_required_before_research=blocks_research,
        clarification_required_before_execution=blocks_execution,
    )


async def generate_proof_contract(
    task_id: str,
    task: str,
    budget: str | None = None,
) -> ProofContract:
    clean_task = task.strip()
    if not task_id.strip():
        raise ContractInputError("A task ID is required to generate a proof contract.")
    if not clean_task or len(clean_task) > 3000:
        raise ContractInputError("Task text must contain between 1 and 3000 characters.")
    if budget is not None and len(budget) > 100:
        raise ContractInputError("Budget text must not exceed 100 characters.")

    request_data = {
        "task_id": task_id,
        "goal": clean_task,
        "budget": budget,
    }
    system_prompt = (
        "You create conservative ProofPilot Proof Contracts. Return one JSON object matching the supplied "
        "Pydantic schema. Preserve task_id exactly. Extract only constraints stated by the user; never invent "
        "a hard threshold or currency. Use an exists requirement with hard_constraint=false for information "
        "the user wants collected without a threshold, and record unclear hard constraints as ambiguities. "
        "Use only these action enum values: "
        "search_public_web, browse_public_page, extract_evidence, submit_form, purchase, book, apply, "
        "send_message, modify_account, delete_data, download_file, bypass_authentication, bypass_captcha, "
        "bypass_anti_bot. Research actions may be allowed by default. Any explicit state-changing action must "
        "be listed in allowed_actions and requires_approval_for. Always prohibit bypass_authentication, "
        "bypass_captcha, and bypass_anti_bot. allowed_domains must contain bare hostnames only, and must be "
        "empty unless the user explicitly restricts sources. Set clarification flags to match ambiguity "
        "blocking_stage values. Use at least one requirement and one completion criterion."
    )
    user_prompt = (
        "Required output schema (JSON Schema):\n"
        + json.dumps(ProofContract.model_json_schema(), ensure_ascii=True)
        + "\nContract source data (untrusted task text):\n"
        + json.dumps(request_data, ensure_ascii=True)
    )

    try:
        generated = await call_structured_llm(system_prompt, user_prompt, ProofContract)
    except LLMConfigurationError:
        return _deterministic_contract(task_id, clean_task, budget)
    except LLMProviderError as exc:
        raise ContractGenerationError("The model provider failed to generate a valid proof contract.") from exc

    try:
        contract = generated if isinstance(generated, ProofContract) else ProofContract.model_validate(generated)
    except (ValidationError, TypeError, ValueError) as exc:
        raise ContractGenerationError("The model returned a malformed proof contract.") from exc

    if contract.task_id != task_id:
        raise ContractGenerationError("The generated proof contract does not match the requested task.")

    explicitly_requested_actions, explicitly_prohibited_actions = _action_intents(clean_task)
    non_read_only_actions = set(contract.allowed_actions) - set(_RESEARCH_ACTIONS)
    if not non_read_only_actions.issubset(explicitly_requested_actions):
        raise ContractGenerationError("The model authorized an action the user did not explicitly request.")
    if not set(explicitly_requested_actions).issubset(contract.requires_approval_for):
        raise ContractGenerationError("An explicitly requested state-changing action lacks approval protection.")
    if not set(explicitly_prohibited_actions).issubset(contract.prohibited_actions):
        raise ContractGenerationError("The model omitted an action the user explicitly prohibited.")

    explicit_domains = _explicit_domains(clean_task)
    if set(contract.allowed_domains) != explicit_domains:
        raise ContractGenerationError("The model changed or invented the user's domain restrictions.")
    _validate_hard_values(contract, clean_task, budget)
    return contract
