import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from models import Claim, VerificationRequest, VerificationResult, VerificationStatus


def _normalize(text: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", text.casefold()).split())


_MONEY_PATTERN = re.compile(
    r"(?<![a-z0-9.,])(?P<prefix>US\$|CA\$|AU\$|USD|GBP|EUR|INR|\$|\u00a3|\u20ac|\u20b9|\u00c2\u00a3)?\s*"
    r"(?P<number>(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{1,2})?)\s*"
    r"(?P<suffix>USD|GBP|EUR|INR)?",
    re.IGNORECASE,
)


def _canonical_number(value: str) -> str | None:
    try:
        number = Decimal(value.replace(",", ""))
    except InvalidOperation:
        return None
    normalized = format(number, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized


def _currency_code(value: str) -> str:
    return {
        "us$": "usd",
        "ca$": "cad",
        "au$": "aud",
        "usd": "usd",
        "gbp": "gbp",
        "£": "gbp",
        "\u00c2\u00a3": "gbp",
        "eur": "eur",
        "€": "eur",
        "inr": "inr",
        "₹": "inr",
        "$": "currency",
    }.get(value.casefold(), "")


def _money_values(text: str) -> set[tuple[str, str]]:
    values: set[tuple[str, str]] = set()
    for match in _MONEY_PATTERN.finditer(text):
        if not match.group("prefix") and not match.group("suffix"):
            continue
        prefix = _currency_code(match.group("prefix") or "")
        suffix = _currency_code(match.group("suffix") or "")
        if prefix and suffix and prefix != suffix:
            continue
        amount = _canonical_number(match.group("number"))
        currency = prefix or suffix
        if currency and amount is not None:
            values.add((currency, amount))
    return values


def _capacity_values(text: str) -> set[tuple[str, str]]:
    values: set[tuple[str, str]] = set()
    for number, unit in re.findall(
        r"\b(\d{1,4}(?:,\d{3})*(?:\.\d+)?)\s*(gb|tb)\b",
        text,
        flags=re.IGNORECASE,
    ):
        canonical = _canonical_number(number)
        if canonical is not None:
            values.add((canonical, unit.casefold()))
    return values


def _warranty_values(text: str) -> set[tuple[str, str]]:
    values: set[tuple[str, str]] = set()
    for number in re.findall(r"\b([1-9])[- ]years?\b", text, flags=re.IGNORECASE):
        values.add((number, "year"))
    return values


def _model_values(text: str) -> set[str]:
    matches = re.findall(
        r"\b(?:rtx|gtx)\s*\d{3,4}(?:\s*ti)?|intel(?:\s+core)?\s+(?:i\d|ultra)[\w-]*|amd\s+ryzen\s*[a-z0-9-]*",
        text,
        flags=re.IGNORECASE,
    )
    return {_normalize(match).replace(" ", "") for match in matches}


def _category_conflict(field: str, claim_value: str, quote: str) -> bool:
    field = field.casefold()
    if "price" in field:
        claimed = _money_values(claim_value)
        quoted = _money_values(quote)
        known_claimed = {item for item in claimed if item[0] != "currency"}
        known_quoted = {item for item in quoted if item[0] != "currency"}
        return bool(known_claimed and known_quoted and known_claimed.isdisjoint(known_quoted))
    if "ram" in field or "capacity" in field or "storage" in field:
        claimed = _capacity_values(claim_value)
        quoted = _capacity_values(quote)
        return bool(quoted and claimed and claimed.isdisjoint(quoted))
    if "warranty" in field:
        claimed = _warranty_values(claim_value)
        quoted = _warranty_values(quote)
        return bool(quoted and claimed and claimed.isdisjoint(quoted))
    if "gpu" in field or "processor" in field:
        claimed_values = _model_values(claim_value)
        quoted_values = _model_values(quote)
        return bool(quoted_values and claimed_values and claimed_values.isdisjoint(quoted_values))
    return False


def _value_is_negated(value: str, quote: str) -> bool:
    normalized_value = _normalize(value)
    normalized_quote = _normalize(quote)
    if not normalized_value or not normalized_quote:
        return False
    value_pattern = re.escape(normalized_value).replace(r"\ ", r"\s+")
    for match in re.finditer(rf"(?<![a-z0-9]){value_pattern}(?![a-z0-9])", normalized_quote):
        preceding = normalized_quote[max(0, match.start() - 100):match.start()]
        if re.search(r"\bnot\s+only\b", preceding):
            continue
        if re.search(
            r"\b(?:not|no|never|without|lacks?|missing|unable|cannot|can't)\b(?:\s+\w+){0,8}\s*$",
            preceding,
        ):
            return True
        following = normalized_quote[match.end():match.end() + 65]
        if re.match(
            r"\s*(?:(?:is|was|are|were|has been|have been)\s+)?(?:not|never|unconfirmed|unverified|not listed|not disclosed|not available|not confirmed)\b",
            following,
        ):
            return True
    return False


def _value_is_directly_established(field: str, value: str, quote: str) -> bool:
    field = field.casefold()
    if "price" in field:
        claimed = _money_values(value)
        quoted = _money_values(quote)
        return bool(claimed and claimed.intersection(quoted))
    if "ram" in field or "capacity" in field or "storage" in field:
        claimed = _capacity_values(value)
        quoted = _capacity_values(quote)
        return bool(claimed and claimed.intersection(quoted))
    if "warranty" in field:
        claimed = _warranty_values(value)
        quoted = _warranty_values(quote)
        return bool(claimed and claimed.intersection(quoted))
    if "gpu" in field or "processor" in field:
        claimed = _model_values(value)
        quoted = _model_values(quote)
        return bool(claimed and claimed.intersection(quoted))

    normalized_value = _normalize(value)
    normalized_quote = _normalize(quote)
    return bool(normalized_value and f" {normalized_value} " in f" {normalized_quote} ")


def verify_claim(request: VerificationRequest) -> VerificationResult:
    claim = request.claim
    evidence = claim.evidence
    extracted_text = request.extracted_text
    checked_at = datetime.now(timezone.utc)

    if not evidence.quote.strip():
        return VerificationResult(
            claim_id=claim.id,
            status=VerificationStatus.UNVERIFIED,
            reason="The claim has no supporting quotation.",
            evidence_quote=evidence.quote,
            evidence_source_url=evidence.source_url,
            evidence_timestamp=evidence.timestamp,
            checked_at=checked_at,
        )

    if not str(evidence.source_url).strip():
        return VerificationResult(
            claim_id=claim.id,
            status=VerificationStatus.UNVERIFIED,
            reason="The supporting evidence is not linked to a source URL.",
            evidence_quote=evidence.quote,
            evidence_source_url=evidence.source_url,
            evidence_timestamp=evidence.timestamp,
            checked_at=checked_at,
        )

    normalized_quote = _normalize(evidence.quote)
    normalized_content = _normalize(extracted_text)
    quote_matched = bool(normalized_quote) and f" {normalized_quote} " in f" {normalized_content} "
    if not quote_matched:
        return VerificationResult(
            claim_id=claim.id,
            status=VerificationStatus.UNVERIFIED,
            reason="The quotation could not be found in the collected webpage text.",
            evidence_quote=evidence.quote,
            evidence_source_url=evidence.source_url,
            evidence_timestamp=evidence.timestamp,
            checked_at=checked_at,
        )

    if _value_is_negated(claim.value, evidence.quote):
        return VerificationResult(
            claim_id=claim.id,
            status=VerificationStatus.CONTRADICTED,
            reason="The supporting excerpt explicitly negates the extracted value.",
            evidence_quote=evidence.quote,
            evidence_source_url=evidence.source_url,
            evidence_timestamp=evidence.timestamp,
            checked_at=checked_at,
        )

    if _category_conflict(claim.field, claim.value, evidence.quote):
        return VerificationResult(
            claim_id=claim.id,
            status=VerificationStatus.CONTRADICTED,
            reason="A different value for this claim category appears in the linked supporting excerpt.",
            evidence_quote=evidence.quote,
            evidence_source_url=evidence.source_url,
            evidence_timestamp=evidence.timestamp,
            checked_at=checked_at,
        )

    if _value_is_directly_established(claim.field, claim.value, evidence.quote):
        return VerificationResult(
            claim_id=claim.id,
            status=VerificationStatus.SUPPORTED,
            reason="The claim value and its unit are present in evidence reproduced from the collected page.",
            evidence_quote=evidence.quote,
            evidence_source_url=evidence.source_url,
            evidence_timestamp=evidence.timestamp,
            checked_at=checked_at,
        )

    return VerificationResult(
        claim_id=claim.id,
        status=VerificationStatus.UNVERIFIED,
        reason="The excerpt exists in the collected page, but it does not directly establish the claimed value and unit.",
        evidence_quote=evidence.quote,
        evidence_source_url=evidence.source_url,
        evidence_timestamp=evidence.timestamp,
        checked_at=checked_at,
    )
