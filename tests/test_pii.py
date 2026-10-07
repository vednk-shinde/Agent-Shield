import pytest

from agent_shield.pii import detect_sensitive, luhn_valid, redact


def rules(text: str) -> list[str]:
    return [f.rule for f in detect_sensitive(text)]


@pytest.mark.parametrize(
    ("number", "valid"),
    [("4111111111111111", True), ("4111 1111 1111 1111", True), ("4111111111111112", False), ("12345", False)],
)
def test_luhn(number, valid):
    assert luhn_valid(number) is valid


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("contact jane.doe@example.com", "email"),
        ("call me on (415) 555-0132", "phone"),
        ("call me on 415-555-0132", "phone"),
        ("ssn 123-45-6789", "us_ssn"),
        ("card 4111 1111 1111 1111", "credit_card"),
        ("key AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
        ("token ghp_" + "a" * 36, "github_token"),
        ("xoxb-1234567890-abcdefghij", "slack_token"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key"),
        ("api_key = 'sk_live_abcdefghijklmnop1234'", "generic_secret"),
        ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk", "jwt"),
    ],
)
def test_detects_sensitive_data(text, rule):
    assert rule in rules(text)


@pytest.mark.parametrize(
    "text",
    [
        "order number 4111111111111112",  # fails Luhn
        "ssn 000-12-3456",  # invalid area
        "ssn 666-12-3456",
        "ssn 900-12-3456",
        "ssn 123-00-6789",
        "ssn 123-45-0000",
        "version 1.2.3 released on 2024-01-05",
        "nothing sensitive here",
    ],
)
def test_avoids_false_positives(text):
    assert detect_sensitive(text) == []


def test_redact_replaces_every_finding_without_shifting_offsets():
    text = "mail a@b.io then cc c@d.io, card 4111111111111111."
    redacted = redact(text, detect_sensitive(text))
    assert redacted == "mail [REDACTED:EMAIL] then cc [REDACTED:EMAIL], card [REDACTED:CREDIT_CARD]."


def test_redact_ignores_findings_without_a_location():
    from agent_shield.models import Finding, Severity

    finding = Finding(detector="x", rule="r", severity=Severity.LOW, weight=0.1)
    assert redact("unchanged", [finding]) == "unchanged"


def test_overlapping_matches_are_reported_once():
    findings = detect_sensitive("password = AKIAIOSFODNN7EXAMPLE1234")
    assert len(findings) == 1
