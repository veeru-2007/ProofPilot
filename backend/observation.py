"""Small deterministic parsers for observed values and their original units."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation


_NUMBER = r"[+-]?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?"
_MONEY_VALUE = re.compile(
    rf"\s*(?:(?P<prefix>US\$|CA\$|AU\$|USD|GBP|EUR|INR|CAD|AUD|\$|\u00a3|\u20ac|\u20b9|\u00c2\u00a3)\s*)?"
    rf"(?P<number>{_NUMBER})\s*(?P<suffix>USD|GBP|EUR|INR|CAD|AUD)?\s*",
    re.IGNORECASE,
)
_QUANTITY_VALUE = re.compile(
    rf"\s*(?P<number>{_NUMBER})\s*(?P<unit>TB|GB)\b\s*(?:(?:of\s+)?(?:DDR\d(?:-\d+)?|RAM))?\s*",
    re.IGNORECASE,
)
_WARRANTY_VALUE = re.compile(
    rf"\s*(?P<number>{_NUMBER})\s*(?:-\s*)?(?P<unit>years?|yrs?)\s*(?:limited\s+)?warranty\s*",
    re.IGNORECASE,
)
_BARE_NUMBER = re.compile(rf"\s*(?P<number>{_NUMBER})\s*")

_CURRENCY_CODES = {
    "us$": "USD",
    "ca$": "CAD",
    "au$": "AUD",
    "usd": "USD",
    "gbp": "GBP",
    "eur": "EUR",
    "inr": "INR",
    "cad": "CAD",
    "aud": "AUD",
    "£": "GBP",
    "\u00a3": "GBP",
    "Â£": "GBP",
    "\u00c2\u00a3": "GBP",
    "€": "EUR",
    "\u20ac": "EUR",
    "₹": "INR",
    "\u20b9": "INR",
}


@dataclass(frozen=True)
class ParsedObservation:
    numeric_value: int | float | None
    unit: str | None = None
    currency: str | None = None
    currency_symbol: str | None = None


def normalize_currency(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip().casefold()
    return _CURRENCY_CODES.get(normalized) or next(
        (code for symbol, code in _CURRENCY_CODES.items() if symbol.casefold() == normalized),
        None,
    )


def _number(value: str) -> int | float | None:
    try:
        number = Decimal(value.replace(",", ""))
    except InvalidOperation:
        return None
    if not number.is_finite():
        return None
    return int(number) if number == number.to_integral_value() else float(number)


def parse_observation(value: str, field: str) -> ParsedObservation:
    """Parse only explicit units/currency; never infer or convert a currency."""
    normalized_field = re.sub(r"[^a-z0-9]", "", field.casefold())
    if normalized_field in {"price", "cost"}:
        match = _MONEY_VALUE.fullmatch(value)
        if not match:
            return ParsedObservation(None)
        prefix = (match.group("prefix") or "").strip()
        suffix = (match.group("suffix") or "").strip()
        prefix_code = normalize_currency(prefix)
        suffix_code = normalize_currency(suffix)
        if prefix_code and suffix_code and prefix_code != suffix_code:
            return ParsedObservation(_number(match.group("number")), currency_symbol=f"{prefix}/{suffix}")
        symbol = prefix or suffix or None
        # A bare dollar sign is not enough to identify USD, CAD, or AUD.
        currency = (prefix_code or suffix_code) if symbol else None
        return ParsedObservation(_number(match.group("number")), currency=currency, currency_symbol=symbol)

    quantity = _QUANTITY_VALUE.fullmatch(value)
    if quantity:
        return ParsedObservation(_number(quantity.group("number")), unit=quantity.group("unit").upper())

    warranty = _WARRANTY_VALUE.fullmatch(value)
    if warranty:
        return ParsedObservation(_number(warranty.group("number")), unit="years")

    bare = _BARE_NUMBER.fullmatch(value)
    if bare:
        return ParsedObservation(_number(bare.group("number")))
    return ParsedObservation(None)
