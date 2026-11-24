import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from models import BrowserPageResponse, Claim, Evidence, VerificationStatus
from observation import parse_observation


PATTERNS = (
    (
        "Price",
        re.compile(
            r"(?<![\w.,])(?:[$£€]\s?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{2})?|"
            r"(?:USD|GBP|EUR)\s+(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{2})?|"
            r"(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{2})?\s?(?:USD|GBP|EUR)\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "RAM",
        re.compile(
            r"(?<![\w.,])\d{1,3}\s*(?:GB|TB)\b\s*(?:(?:of\s+)?(?:DDR\d(?:-\d+)?|RAM)\b)?",
            re.IGNORECASE,
        ),
    ),
    (
        "Processor",
        re.compile(
            r"\b(?:Intel(?:\s+Core)?(?:\s+(?:Ultra|i\d)[\w\s-]*)?|AMD\s+Ryzen\s*[\w\s-]*|Apple\s+M\d(?:\s+(?:Pro|Max|Ultra))?)",
            re.IGNORECASE,
        ),
    ),
    (
        "GPU",
        re.compile(
            r"\b(?:NVIDIA(?:\s+GeForce)?\s+(?:RTX|GTX)\s*\d{3,4}(?:\s+Ti)?|AMD\s+Radeon(?:\s+RX)?\s*[A-Za-z0-9-]+|RTX\s*\d{3,4}(?:\s+Ti)?)",
            re.IGNORECASE,
        ),
    ),
    (
        "Warranty",
        re.compile(
            r"\b(?:[1-5][- ]year(?:s)?\s+(?:limited\s+)?warranty|warranty\s+(?:of\s+)?[1-5][- ]years?)",
            re.IGNORECASE,
        ),
    ),
)

_ADDITIONAL_PRICE_PATTERN = re.compile(
    r"(?<![\w.,])(?:US\$|CA\$|AU\$|INR|CAD|AUD|\u20b9)\s?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{1,2})?|"
    r"(?<![\w.,])(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{1,2})?\s?(?:INR|CAD|AUD)\b",
    re.IGNORECASE,
)

_PRICE_CUES = re.compile(
    r"\b(?:price|priced|costs?|listed\s+at|listing\s+at|retail(?:s|\s+price)?|msrp|available\s+for|sale\s+price)\b",
    re.IGNORECASE,
)
_PRICE_EXCLUSIONS = (
    ("upgrade_cost", re.compile(r"\b(?:upgrade|upgrading|additional|extra|add-on|memory\s+option|ram\s+option)\b", re.I)),
    ("cloud_cost", re.compile(r"\b(?:cloud|compute|instance|virtual\s+machine|per\s+(?:hour|day|month))\b", re.I)),
    ("accessory_price", re.compile(r"\b(?:accessor(?:y|ies)|charger|adapter|dock|mouse|keyboard|case|bag)\b", re.I)),
    ("discount_amount", re.compile(r"\b(?:save|savings|discount|coupon|rebate)\b", re.I)),
    ("historical_price", re.compile(r"\b(?:historical|previous(?:ly)?|formerly|older|old price|original price|used to cost|was priced|last year)\b", re.I)),
    ("comparison_price", re.compile(r"\b(?:comparison price|compared with|compared to|versus|\bvs\.?\b|competitor(?:'s)? price)\b", re.I)),
    ("estimated_price", re.compile(r"\b(?:estimated|estimate|approximately|approx\.?|roughly)\b", re.I)),
    ("starting_price", re.compile(r"\b(?:starting|starts)\s+(?:at|from)\b", re.I)),
)
_PROMOTION_CUE = re.compile(r"\b(?:promotional|promotion|promo|sale|discounted)\b", re.I)
_UPGRADE_OPTION = re.compile(r"\b(?:upgrade|upgrading|additional|extra|add-on|optional|option)\b", re.I)
_MAXIMUM_ONLY = re.compile(r"\b(?:up\s+to|maximum|max(?:imum)?\s+of|supports?)\b", re.I)


def _sentences(text: str) -> list[str]:
    normalized = " ".join(text.replace("\r", " ").replace("\n", " ").split())
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9$£€])", normalized)
    return [part.strip() for part in parts if len(part.strip()) >= 20]


def _claim_quote(text: str, match: re.Match) -> str | None:
    boundaries = [text.rfind("\n", 0, match.start())]
    boundaries.extend(position for marker in ".!?" if (position := text.rfind(marker, 0, match.start())) >= 0)
    start = max(boundaries) + 1
    end_candidates = [position for marker in ("\n", "!", "?") if (position := text.find(marker, match.end())) >= 0]
    end = min(end_candidates) if end_candidates else len(text)
    period = re.search(r"\.(?=\s|$)", text[match.end():])
    if period:
        end = min(end, match.end() + period.start())
    while start < match.start() and text[start].isspace():
        start += 1
    while end > match.end() and text[end - 1].isspace():
        end -= 1
    if end - start > 2000:
        start = max(start, match.start() - 900)
        end = min(end, match.end() + 900)
    quote = " ".join(text[start:end].split())
    if not quote or len(quote) < len(match.group(0)):
        return None
    return quote[:2000]


def _price_context(text: str, match: re.Match) -> list[str]:
    boundaries = re.compile(r";|\n|(?<=[.!?])\s+")
    left_boundaries = list(boundaries.finditer(text, 0, match.start()))
    clause_start = left_boundaries[-1].end() if left_boundaries else 0
    right_boundary = boundaries.search(text, match.end())
    clause_end = right_boundary.start() if right_boundary else len(text)
    clause = text[clause_start:clause_end].casefold()
    local_index = match.start() - clause_start
    window_start = max(0, local_index - 80)
    window_end = min(len(clause), local_index + len(match.group(0)) + 80)
    window = clause[window_start:window_end]
    amount_start = local_index - window_start
    amount_end = amount_start + len(match.group(0))

    def nearest(pattern: re.Pattern) -> tuple[int, str] | None:
        matches = list(pattern.finditer(window))
        if not matches:
            return None
        def distance(item: re.Match) -> int:
            if item.end() < amount_start:
                return amount_start - item.end()
            if item.start() > amount_end:
                return item.start() - amount_end
            return 0
        cue = min(matches, key=distance)
        return distance(cue), cue.group(0)

    exclusions = []
    for context, pattern in _PRICE_EXCLUSIONS:
        match_result = nearest(pattern)
        if match_result:
            exclusions.append((match_result[0], context))
    price_cue = nearest(_PRICE_CUES)
    closest_exclusion = min(exclusions, default=None)
    if closest_exclusion and (
        price_cue is None or closest_exclusion[0] <= price_cue[0] + 20
    ):
        return [closest_exclusion[1]]
    if price_cue:
        contexts = ["advertised_price"]
        if _PROMOTION_CUE.search(window):
            contexts.append("promotional_price")
        if any(tag == "estimated_price" for _, tag in exclusions):
            contexts.append("estimated_price")
        return contexts
    if _PROMOTION_CUE.search(window):
        return ["promotional_amount"]
    return ["ambiguous_price"]


def extract_structured_claims(
    page: BrowserPageResponse,
    max_claims: int | None = None,
) -> list[Claim]:
    if max_claims is None:
        try:
            max_claims = int(os.getenv("EVIDENCE_MAX_CLAIMS", "12"))
        except ValueError:
            max_claims = 12
    max_claims = max(1, min(max_claims, 50))

    source_text = "\n".join(
        [part for part in [*page.headings, page.visible_text] if part.strip()]
    )
    if not source_text.strip():
        return []
    title = " ".join(page.title.split())[:300] or "Untitled webpage"

    claims: list[Claim] = []
    seen: set[tuple[str, str]] = set()
    timestamp = datetime.now(timezone.utc)

    for category, pattern in PATTERNS:
        matches = list(pattern.finditer(source_text))
        if category == "Price":
            matches.extend(_ADDITIONAL_PRICE_PATTERN.finditer(source_text))
            matches.sort(key=lambda item: item.start())
        for match in matches:
            value = " ".join(match.group(0).split()).strip(" ,.;")
            if not value or len(value) > 500:
                continue
            key = (category.lower(), value.lower())
            if key in seen:
                continue
            seen.add(key)

            quote = _claim_quote(source_text, match)
            if not quote:
                continue
            if category == "Price":
                context = _price_context(source_text, match)
            elif category == "RAM":
                local = quote.casefold()
                context = []
                if _UPGRADE_OPTION.search(local):
                    context.append("upgrade_option")
                if _MAXIMUM_ONLY.search(local):
                    context.append("maximum_configuration")
            else:
                context = []
            parsed = parse_observation(value, category)

            claim = Claim(
                id=f"claim_{len(claims) + 1}",
                subject=title,
                field=category,
                value=value,
                numeric_value=parsed.numeric_value,
                unit=parsed.unit,
                currency=parsed.currency,
                currency_symbol=parsed.currency_symbol,
                source_domain=urlparse(str(page.url)).hostname,
                context=context,
                evidence=Evidence(
                    quote=quote,
                    source_url=page.url,
                    source_title=title,
                    excerpt_locator=f"{category.lower()} match",
                    timestamp=timestamp,
                    confidence=0,
                ),
                verification_status=VerificationStatus.UNVERIFIED,
                verification_reason="Extracted from the source page and awaiting verification.",
            )
            claims.append(claim)
            if len(claims) >= max_claims:
                return claims
    return claims


def build_initial_claims() -> list[Claim]:
    """Mock evidence for the existing demo response."""
    now = datetime.now(timezone.utc)
    return [
        Claim(
            id="claim_1",
            subject="ASUS ProArt Studiobook 16",
            field="GPU",
            value="NVIDIA GeForce RTX 4060",
            evidence=Evidence(
                quote="NVIDIA GeForce RTX 4060 Laptop GPU, 8GB GDDR6",
                source_url="https://www.asus.com/",
                source_title="ASUS ProArt Studiobook 16",
                timestamp=now,
                confidence=0.92,
            ),
            verification_status=VerificationStatus.SUPPORTED,
            verification_reason="The extracted GPU value directly matches the manufacturer's specification.",
        ),
        Claim(
            id="claim_2",
            subject="Lenovo Legion Pro 5",
            field="RAM",
            value="32GB DDR5",
            evidence=Evidence(
                quote="Up to 32GB DDR5-5600, two SODIMM slots",
                source_url="https://www.lenovo.com/",
                source_title="Lenovo Legion Pro 5",
                timestamp=now,
                confidence=0.92,
            ),
            verification_status=VerificationStatus.SUPPORTED,
            verification_reason="The source states 32GB DDR5 as a supported configuration.",
        ),
        Claim(
            id="claim_3",
            subject="Dell G16",
            field="Price",
            value="£1,449.99",
            evidence=Evidence(
                quote="The current listing shows £1,499.99; a save £50 promotion is referenced separately.",
                source_url="https://www.dell.com/",
                source_title="Dell G16 laptop listing",
                timestamp=now,
                confidence=0.65,
            ),
            verification_status=VerificationStatus.CONTRADICTED,
            verification_reason="The quoted page price and claimed promotional price do not match.",
        ),
        Claim(
            id="claim_4",
            subject="MSI Katana 15",
            field="Warranty",
            value="2-year warranty",
            evidence=Evidence(
                quote="The listing links to limited warranty terms but does not state a duration for this configuration.",
                source_url="https://www.msi.com/",
                source_title="MSI Katana 15",
                timestamp=now,
                confidence=0.35,
            ),
            verification_status=VerificationStatus.UNVERIFIED,
            verification_reason="No direct evidence establishes the warranty duration.",
        ),
    ]
