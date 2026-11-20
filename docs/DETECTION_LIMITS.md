# Detection limits

PrivTrace is deliberately simple and deterministic. Know what it does not see.

## Languages
- **Python only** in the MVP (stdlib `ast`). Other files (`.env`, YAML, JSON, SQL, CSV, fixtures) get text-level identifier/secret detection and a few config checks.
- JS/TS: the `LanguageParser` protocol in `scanner/parsers/base.py` is the slot for a tree-sitter parser.

## Personal-data sources
Something is treated as personal data when it is:
- a variable / parameter / attribute / dict key whose **name** matches the PII dictionary (`scanner/detectors/pii_names.py`),
- a parameter **annotated with a model** that has PII fields,
- a **constructor call** of such a model,
- a raw **request body** (`request.json()`, `request.form`, ...).

Generic names (`payload`, `data`, `meta`, `ctx`) are *ambiguous*: they are not tainted by name alone. The optional Gemini classifier may label them; it can only add labels.

## Flow tracking
- Within a function: assignments, f-strings, concatenation, containers, method calls on tainted values, `for` loops. Loop bodies are evaluated twice; branches are merged (flow-insensitive).
- Across functions: per-function *summaries* record which parameters reach which sinks. Calls to functions in the same file, `self.method()`, and functions imported from other repo modules (`from .llm import ask`, `import app.llm as llm`) reuse them, up to 3 levels.
- **Not tracked:** return values of repo functions beyond "result carries its arguments' taint", `**kwargs` mapping, `getattr`/dynamic dispatch, decorators that change behaviour, class attribute flows outside `self.x`, async task queues, data passed through databases and read back, ORMs configured by strings, monkey-patching.
- **Sanitizers** are recognised by name (`redact`, `mask`, `anonymise`, `hash`, `encrypt`, `bcrypt`, `argon2`, ...). PrivTrace does not verify that the sanitizer actually works.

## Sinks
Recognised APIs are listed in `scanner/flow/sinks.py`. Objects are resolved from imports and factory calls (`logging.getLogger`, `redis.Redis`, `genai.Client`, `OpenAI()`, `chromadb.Client`, ...), FastAPI-style annotations (`db: Session`), and finally naming conventions (`logger`, `db`, `cache`, `r`). Wrapper libraries not in the catalogue are missed.

## Erasure / retention
- A *delete handler* is a `DELETE` route or a function named like `delete_user`, `erase_account`, `forget_me`.
- Its coverage is the set of store kinds (DB, vector store, cache, files) it deletes from, directly or through repo helpers. This is compared against the store kinds that receive personal data anywhere in the code. Table-level matching is best-effort.
- Retention is detected from Redis TTLs, `TimedRotatingFileHandler` settings, `*LOG*RETENTION*` settings, functions named `purge_*`/`cleanup_*`, and time-based `DELETE` statements. Retention configured in infrastructure (Cloud Logging buckets, DB policies) is invisible, so those rules fall back to "needs review" or the manual checklist.

## Heuristic rules never fail on their own
Consent capture, minimisation and children's data are heuristics. They produce **needs review**, never **failed**.
