import unittest

from models import Claim, Evidence, VerificationRequest, VerificationStatus
from verifier import verify_claim


def make_claim(claim_id: str, field: str, value: str, quote: str) -> Claim:
    return Claim(
        id=claim_id,
        subject="Test laptop",
        field=field,
        value=value,
        evidence=Evidence(
            quote=quote,
            source_url="https://example.com/specs",
            source_title="Test laptop specifications",
            confidence=0.9,
        ),
        verification_status=VerificationStatus.UNVERIFIED,
        verification_reason="Initial status before evidence verification.",
    )


class VerifierTests(unittest.TestCase):
    def test_supported_claim(self):
        claim = make_claim(
            "supported-1",
            "RAM",
            "32GB DDR5",
            "This laptop has 32GB DDR5 RAM.",
        )
        result = verify_claim(
            VerificationRequest(claim=claim, extracted_text="This laptop has 32GB DDR5 RAM.")
        )
        self.assertEqual(result.status, VerificationStatus.SUPPORTED)
        self.assertIn("32GB", result.evidence_quote)
        self.assertEqual(str(result.evidence_source_url), "https://example.com/specs")

    def test_contradicted_claim(self):
        claim = make_claim(
            "contradicted-1",
            "Price",
            "GBP 1,449.99",
            "The listed price is GBP 1,499.99.",
        )
        result = verify_claim(
            VerificationRequest(claim=claim, extracted_text="The listed price is GBP 1,499.99.")
        )
        self.assertEqual(result.status, VerificationStatus.CONTRADICTED)

    def test_short_numeric_substring_does_not_support_a_price(self):
        claim = make_claim("substring-1", "Price", "12", "The listed price is 1200.")
        result = verify_claim(VerificationRequest(claim=claim, extracted_text=claim.evidence.quote))
        self.assertEqual(result.status, VerificationStatus.UNVERIFIED)

    def test_currency_mismatch_is_contradicted(self):
        claim = make_claim(
            "currency-1",
            "Price",
            "GBP 1200",
            "The listed price is USD 1200.",
        )
        result = verify_claim(VerificationRequest(claim=claim, extracted_text=claim.evidence.quote))
        self.assertEqual(result.status, VerificationStatus.CONTRADICTED)

    def test_unicode_currency_symbol_is_verified_without_encoding_loss(self):
        claim = make_claim(
            "unicode-currency-1",
            "Price",
            "\u00a31,200",
            "The listed price is \u00a31,200.",
        )
        result = verify_claim(VerificationRequest(claim=claim, extracted_text=claim.evidence.quote))
        self.assertEqual(result.status, VerificationStatus.SUPPORTED)

    def test_explicitly_negated_capacity_is_contradicted(self):
        claim = make_claim(
            "negated-1",
            "RAM",
            "32GB",
            "This model does not include 32GB RAM.",
        )
        result = verify_claim(VerificationRequest(claim=claim, extracted_text=claim.evidence.quote))
        self.assertEqual(result.status, VerificationStatus.CONTRADICTED)

    def test_example_inside_an_explicitly_negative_statement_is_not_supported(self):
        claim = make_claim(
            "example-in-negative-1",
            "Processor",
            "Intel Core i9",
            "No processor, such as Intel Core i9, has been confirmed.",
        )
        result = verify_claim(VerificationRequest(claim=claim, extracted_text=claim.evidence.quote))
        self.assertEqual(result.status, VerificationStatus.CONTRADICTED)

    def test_unverified_when_quote_missing(self):
        claim = make_claim(
            "unverified-1",
            "Warranty",
            "2-year warranty",
            "The original excerpt is no longer in the page.",
        )
        result = verify_claim(
            VerificationRequest(
                claim=claim,
                extracted_text="This page lists standard warranty terms.",
            )
        )
        self.assertEqual(result.status, VerificationStatus.UNVERIFIED)
        self.assertIn("could not be found", result.reason)

    def test_unverified_when_quote_does_not_establish_value(self):
        claim = make_claim(
            "unverified-2",
            "Processor",
            "Intel Core i7-13700H",
            "The processor was not disclosed on this page.",
        )
        result = verify_claim(
            VerificationRequest(
                claim=claim,
                extracted_text="The processor was not disclosed on this page.",
            )
        )
        self.assertEqual(result.status, VerificationStatus.UNVERIFIED)

    def test_matching_quote_prefix_does_not_prove_an_absent_value(self):
        prefix = "This listing contains the following details about this model."
        claim = make_claim("prefix-1", "RAM", "32GB", f"{prefix} It has 32GB RAM.")
        result = verify_claim(VerificationRequest(claim=claim, extracted_text=f"{prefix} It has 16GB RAM."))
        self.assertEqual(result.status, VerificationStatus.UNVERIFIED)

    def test_truncated_source_text_cannot_support_a_missing_quote(self):
        claim = make_claim(
            "truncated-1",
            "RAM",
            "32GB DDR5",
            "The laptop has 32GB DDR5 RAM in the tested configuration.",
        )
        result = verify_claim(
            VerificationRequest(claim=claim, extracted_text="The laptop has 32GB DDR5"),
        )
        self.assertEqual(result.status, VerificationStatus.UNVERIFIED)


if __name__ == "__main__":
    unittest.main()
