"""Classify identifier names (variables, fields, params, dict keys) as personal data.

Deterministic dictionary first. Names in AMBIGUOUS_NAMES are returned with
category 'ambiguous' so the optional Gemini classifier can look at them; Gemini
can only *add* a PII label, never remove one this module assigned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SENSITIVE_CATEGORIES = frozenset(
    {"credentials", "financial", "health", "biometric", "government_id", "children"}
)

# token -> category. Checked in priority order (first match wins).
_TOKEN_CATEGORIES: list[tuple[str, frozenset[str]]] = [
    ("credentials", frozenset({"password", "passwd", "pwd", "passcode", "otp", "mpin"})),
    ("government_id", frozenset({
        "aadhaar", "aadhar", "uid", "pan", "passport", "voter", "epic", "ssn", "gstin",
        "driving", "licence", "license", "dl", "nin", "nationalid",
    })),
    ("financial", frozenset({
        "upi", "vpa", "ifsc", "iban", "swift", "card", "cvv", "cvc", "pan_card",
        "account", "acct", "bank", "salary", "income", "credit", "debit",
    })),
    ("biometric", frozenset({"fingerprint", "biometric", "biometrics", "face", "retina", "iris", "voiceprint"})),
    ("health", frozenset({
        "health", "medical", "diagnosis", "disease", "prescription", "blood", "allergy",
        "allergies", "symptom", "symptoms", "treatment",
    })),
    ("contact", frozenset({"email", "mail", "phone", "mobile", "msisdn", "whatsapp", "telephone", "tel", "fax"})),
    ("location", frozenset({
        "address", "addr", "street", "city", "pincode", "pin_code", "zipcode", "zip",
        "postcode", "postal", "latitude", "longitude", "lat", "lng", "lon", "geo",
        "geolocation", "location", "gps", "ip", "ip_address",
    })),
    ("identity", frozenset({
        "dob", "birthdate", "birthday", "birth", "gender", "sex", "nationality",
        "religion", "caste", "surname", "firstname", "lastname", "fullname",
        "username", "photo", "selfie", "signature",
    })),
    ("children", frozenset({"age", "minor", "child", "children", "guardian", "parent", "kid"})),
]

# Whole names that are PII even though their tokens are generic.
_WHOLE_NAMES: dict[str, str] = {
    "name": "identity",
    "first_name": "identity",
    "last_name": "identity",
    "middle_name": "identity",
    "full_name": "identity",
    "user_name": "identity",
    "display_name": "identity",
    "customer_name": "identity",
    "patient_name": "identity",
    "father_name": "identity",
    "mother_name": "identity",
    "date_of_birth": "identity",
    "pan_number": "government_id",
    "account_number": "financial",
    "card_number": "financial",
    "ip_address": "location",
}

# Tokens that make a name clearly *not* personal data (file_name, model_name...).
_NEGATIVE_TOKENS = frozenset({
    "file", "filename", "table", "model", "class", "func", "function", "host",
    "hostname", "column", "field", "var", "app", "bucket", "path", "dir", "pack",
    "rule", "detector", "attr", "attribute", "module", "package", "service", "queue",
    "topic", "index", "collection", "db", "database", "schema", "type", "event",
    "tag", "label", "env", "key", "server", "smtp", "template", "domain", "url",
    "endpoint", "route", "project", "repo", "branch", "image", "container", "pod",
    "stage", "step", "job", "task", "test", "font", "color", "colour", "pandas",
})

# Generic containers that *may* carry personal data -> ask the AI classifier.
AMBIGUOUS_NAMES = frozenset({
    "meta", "metadata", "ctx", "context", "payload", "user_data", "userdata", "data",
    "info", "details", "profile", "body", "extra", "attrs", "record", "row", "doc",
    "document", "customer", "user", "person", "member", "patient", "applicant",
    "kyc", "contact", "identity", "params",
})


@dataclass(frozen=True)
class NameClassification:
    name: str
    category: str  # one of the categories above, or "ambiguous"
    confidence: float

    @property
    def is_pii(self) -> bool:
        return self.category != "ambiguous"

    @property
    def is_sensitive(self) -> bool:
        return self.category in SENSITIVE_CATEGORIES


_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def tokenize(name: str) -> list[str]:
    name = _CAMEL.sub("_", name.strip())
    return [t for t in re.split(r"[^A-Za-z0-9]+", name.lower()) if t]


def classify_name(name: str) -> NameClassification | None:
    """Return a classification, or None if the name doesn't look like personal data."""
    if name.startswith("__") and name.endswith("__"):
        return None  # dunders like __name__ are Python internals, not personal data
    tokens = tokenize(name)
    if not tokens:
        return None
    norm = "_".join(tokens)

    if norm in _WHOLE_NAMES:
        return NameClassification(name, _WHOLE_NAMES[norm], 0.9)

    # PAN as a bare token is too short to trust unless it's the whole name or 'pan_*'.
    token_set = set(tokens)
    if token_set & _NEGATIVE_TOKENS and not token_set & {"email", "phone", "mobile", "aadhaar", "aadhar", "password"}:
        return None

    for category, vocab in _TOKEN_CATEGORIES:
        hits = token_set & vocab
        if not hits:
            continue
        if hits <= {"pan", "uid", "dl", "nin", "tel", "zip", "lat", "lon", "lng", "ip", "geo", "sex", "age", "kid", "face", "mail", "account", "card", "credit", "debit", "bank", "birth", "parent"}:
            # short/generic tokens: medium confidence
            return NameClassification(name, category, 0.6)
        return NameClassification(name, category, 0.85)

    if norm in AMBIGUOUS_NAMES or (len(tokens) <= 2 and tokens[-1] in AMBIGUOUS_NAMES):
        return NameClassification(name, "ambiguous", 0.3)
    return None
