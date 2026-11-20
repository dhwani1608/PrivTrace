# Compliance packs

Each `*.yaml` file in this folder is one framework. Packs are **data, not code**: the engine loads them at runtime and validates them against `backend/privtrace/packs/schema.py`. See `docs/ADDING_A_PACK.md` for the full schema.

| File | Framework | Rules (auto / hybrid / manual) |
|---|---|---|
| `dpdp-2023.yaml` | Digital Personal Data Protection Act, 2023 + DPDP Rules, 2025 (India) | 8 / 3 / 4 |
| `it-act-spdi.yaml` | IT Act 2000 s.43A + SPDI Rules 2011 (India) | 8 / 2 / 3 |
| `certin-2022.yaml` | CERT-In Directions, 28 April 2022 (India) | 0 / 3 / 5 |
| `gdpr-subset.yaml` | GDPR (EU), code-relevant subset | 7 / 2 / 5 |
| `security-baseline.yaml` | OWASP-style security baseline | 11 / 0 / 2 |

CLI aliases: `dpdp`, `it`, `certin`, `gdpr`, `security`.

## Placeholder: "TAD"

The brief mentioned a framework called **"TAD"**. It hasn't been identified yet, so there is no pack for it. When the owner confirms which act or guideline this refers to, add `tad.yaml` here following `docs/ADDING_A_PACK.md`. Do not create rules for it until then.

## Rules for pack authors

- Every rule needs a `reference` (act + section/rule number) and a `source_url` to official text.
- If you are not certain of a section number, set `reference_verified: false` and list it in `docs/LEGAL_REVIEW_TODO.md`. Never guess.
- Statuses are `passed / failed / needs_review / not_assessable`. Never write "compliant".
