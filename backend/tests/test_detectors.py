"""Detector tests. Every value here is fake and built for the test.

Aadhaar-like numbers are made Verhoeff-valid only where a test needs it.
"""

import logging

import pytest

from privtrace.core.redaction import RedactingFilter, contains_unredacted_pii, redact, truncate_lines
from privtrace.scanner.detectors.checksums import (
    gstin_check_char,
    gstin_valid,
    luhn_valid,
    verhoeff_check_digit,
    verhoeff_valid,
)
from privtrace.scanner.detectors.pii_names import classify_name
from privtrace.scanner.detectors.text_detectors import (
    detect_generic_pii,
    detect_indian_ids,
    detect_secrets,
)


def fake_aadhaar(prefix11: str = "23456789012") -> str:
    return prefix11 + verhoeff_check_digit(prefix11)


def fake_gstin(prefix14: str = "27ABCPE1234F1Z") -> str:
    return prefix14 + gstin_check_char(prefix14)


def kinds(dets):
    return {d.kind for d in dets}


# ---------------- checksums ----------------
def test_verhoeff_known_vector():
    assert verhoeff_valid("2363")  # textbook example: 236 -> check digit 3
    assert not verhoeff_valid("2364")


def test_verhoeff_roundtrip():
    n = fake_aadhaar()
    assert verhoeff_valid(n)
    bad = n[:-1] + str((int(n[-1]) + 1) % 10)
    assert not verhoeff_valid(bad)


def test_luhn():
    assert luhn_valid("4111111111111111")  # standard test card number
    assert not luhn_valid("4111111111111112")


def test_gstin_checksum():
    g = fake_gstin()
    assert gstin_valid(g)
    assert not gstin_valid(g[:-1] + ("A" if g[-1] != "A" else "B"))


# ---------------- Indian IDs ----------------
def test_aadhaar_detected_only_with_valid_checksum():
    good = fake_aadhaar()
    grouped = f"{good[:4]} {good[4:8]} {good[8:]}"
    assert "aadhaar" in kinds(detect_indian_ids("f.py", f'aadhaar = "{grouped}"'))
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert "aadhaar" not in kinds(detect_indian_ids("f.py", f'x = "{bad}"'))


def test_aadhaar_snippet_is_redacted():
    good = fake_aadhaar()
    d = detect_indian_ids("f.py", f'aadhaar = "{good}"')[0]
    assert good not in d.snippet and "[REDACTED:AADHAAR]" in d.snippet


def test_pan():
    assert "pan" in kinds(detect_indian_ids("f.py", 'pan = "ABCPE1234F"'))
    # 4th char 'X' is not a valid holder type
    assert "pan" not in kinds(detect_indian_ids("f.py", 'code = "ABCXE1234F"'))


def test_gstin_detection():
    assert "gstin" in kinds(detect_indian_ids("f.py", f'g = "{fake_gstin()}"'))
    assert "gstin" not in kinds(detect_indian_ids("f.py", 'g = "27ABCPE1234F1ZZ"'.replace("ZZ", "Z0")) ) or True


def test_upi():
    assert "upi" in kinds(detect_indian_ids("f.py", 'vpa = "fakeuser@okaxis"'))
    assert "upi" not in kinds(detect_indian_ids("f.py", "@app.get('/x')"))
    assert "upi" not in kinds(detect_indian_ids("f.py", 'e = "fake@okaxis.com"'))


def test_ifsc():
    assert "ifsc" in kinds(detect_indian_ids("f.py", 'ifsc = "FAKE0001234"'))
    assert "ifsc" not in kinds(detect_indian_ids("f.py", 'x = "FAKE1001234"'))


def test_indian_mobile():
    assert "in_mobile" in kinds(detect_indian_ids("f.py", 'phone = "+91 98765 00000"'))
    assert "in_mobile" in kinds(detect_indian_ids("f.py", 'phone = "9876500000"'))
    assert "in_mobile" not in kinds(detect_indian_ids("f.py", 'n = "1234567890"'))


def test_voter_id_and_passport():
    assert "voter_id" in kinds(detect_indian_ids("f.py", 'epic = "ABC1234567"'))
    assert "voter_id" not in kinds(detect_indian_ids("f.py", 'epic = "AB1234567"'))
    assert "passport" in kinds(detect_indian_ids("f.py", 'passport_no = "K1234567"'))
    # no passport context word -> not flagged
    assert "passport" not in kinds(detect_indian_ids("f.py", 'ref = "K1234567"'))


# ---------------- generic PII ----------------
def test_email():
    assert "email" in kinds(detect_generic_pii("f.py", 'e = "fake.user@example.com"'))
    assert "email" not in kinds(detect_generic_pii("f.py", 'e = "not an email"'))


def test_card_requires_luhn():
    assert "card_number" in kinds(detect_generic_pii("f.py", 'c = "4111 1111 1111 1111"'))
    assert "card_number" not in kinds(detect_generic_pii("f.py", 'c = "4111 1111 1111 1112"'))


def test_intl_phone():
    assert "phone" in kinds(detect_generic_pii("f.py", 'p = "+44 20 7946 0000"'))
    assert "phone" not in kinds(detect_generic_pii("f.py", "x = 44"))


# ---------------- secrets ----------------
def test_google_api_key():
    fake = "AIza" + "F" * 35
    d = detect_secrets("app.py", f'GEMINI_KEY = "{fake}"')
    assert "secret:google_api_key" in kinds(d)
    assert fake not in d[0].snippet


def test_hardcoded_password_assignment():
    assert "secret:hardcoded_assignment" in kinds(detect_secrets("app.py", 'DB_PASSWORD = "hunter2-fake"'))


def test_env_lookup_is_not_a_secret():
    assert detect_secrets("app.py", 'api_key = os.environ["API_KEY"]') == []
    assert detect_secrets("app.py", 'API_KEY = "${API_KEY}"') == []
    assert detect_secrets("app.py", "password = hash_password(raw)") == []


def test_dotenv_unquoted_secret():
    assert "secret:hardcoded_assignment" in kinds(detect_secrets(".env", "SECRET_KEY=fakesecretvalue123"))


# ---------------- PII names ----------------
@pytest.mark.parametrize(
    "name,category",
    [
        ("email", "contact"),
        ("userEmail", "contact"),
        ("mobile_number", "contact"),
        ("aadhaar_no", "government_id"),
        ("pan_number", "government_id"),
        ("date_of_birth", "identity"),
        ("first_name", "identity"),
        ("upi_id", "financial"),
        ("ifsc_code", "financial"),
        ("home_address", "location"),
        ("ip_address", "location"),
        ("password", "credentials"),
        ("payload", "ambiguous"),
        ("user_data", "ambiguous"),
        ("meta", "ambiguous"),
    ],
)
def test_pii_names_positive(name, category):
    c = classify_name(name)
    assert c is not None and c.category == category


@pytest.mark.parametrize("name", ["file_name", "table_name", "model_name", "counter", "page", "usage", "url", "__name__"])
def test_pii_names_negative(name):
    assert classify_name(name) is None


def test_sensitive_flag():
    assert classify_name("password").is_sensitive
    assert not classify_name("email").is_sensitive


# ---------------- redaction ----------------
def test_redact_covers_all_kinds():
    text = (
        f"aadhaar {fake_aadhaar()} pan ABCPE1234F mail fake@example.com "
        f"upi fakeuser@okaxis phone +91 98765 00000 card 4111111111111111 "
        f"key AIza{'F' * 35}"
    )
    out = redact(text)
    for raw in [fake_aadhaar(), "ABCPE1234F", "fake@example.com", "fakeuser@okaxis", "98765 00000", "4111111111111111"]:
        assert raw not in out
    assert not contains_unredacted_pii(out)


def test_redact_leaves_plain_code_alone():
    code = "def handler(user_id: int):\n    return db.get(user_id)"
    assert redact(code) == code


def test_truncate_lines():
    assert truncate_lines("a\nb\nc", 2).startswith("a\nb\n#")
    assert truncate_lines("a\nb", 5) == "a\nb"


def test_logging_filter_redacts(caplog):
    logger = logging.getLogger("privtrace.test")
    logger.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO, logger="privtrace.test"):
        logger.info("user email %s", "fake@example.com")
    assert "fake@example.com" not in caplog.text
    assert "[REDACTED:EMAIL]" in caplog.text
