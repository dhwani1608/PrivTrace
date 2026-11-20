"""Facts the scanner extracts from a codebase. Rules evaluate these; they never re-parse code."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from privtrace.models.detection import Detection


class SinkKind(StrEnum):
    db_write = "db_write"
    log = "log"
    llm = "llm"                 # third-party AI call (chat, generate, embeddings API)
    vector_store = "vector_store"
    cache = "cache"
    http = "http"               # third-party HTTP API
    file_write = "file_write"
    analytics = "analytics"


# Stores that *hold* personal data and therefore need erasure + retention.
STORAGE_SINKS = frozenset({SinkKind.db_write, SinkKind.vector_store, SinkKind.cache, SinkKind.file_write})
# Sinks that send data to a third party.
THIRD_PARTY_SINKS = frozenset({SinkKind.llm, SinkKind.http, SinkKind.analytics})


class Location(BaseModel):
    file: str
    line: int
    snippet: str = ""  # always redacted


class Taint(BaseModel):
    """One piece of personal data reaching a point in the code."""

    category: str  # contact, government_id, ..., request_body, model
    name: str      # field/variable name it came from, e.g. "email"

    model_config = {"frozen": True}


class SinkEvent(BaseModel):
    kind: SinkKind
    api: str = Field(description="Resolved call, e.g. 'logger.info', 'genai_client.models.generate_content'.")
    location: Location
    function: str = Field(description="Enclosing function qualname ('<module>' at top level).")
    taints: list[Taint] = Field(default_factory=list)
    sanitized: bool = Field(default=False, description="A redaction/hash function was applied on the path.")
    has_ttl: bool | None = Field(default=None, description="Cache writes only: TTL set on write.")
    store: str | None = Field(default=None, description="Table / collection / key prefix if known.")
    via: list[Location] = Field(default_factory=list, description="Call sites, for cross-function flows.")

    @property
    def carries_pii(self) -> bool:
        return bool(self.taints)


class DeleteOp(BaseModel):
    kind: SinkKind  # which store kind the delete targets
    api: str
    location: Location
    function: str
    store: str | None = None


class PiiField(BaseModel):
    name: str
    category: str
    sensitive: bool
    line: int


class PiiModel(BaseModel):
    name: str
    file: str
    line: int
    model_kind: str  # pydantic | sqlalchemy | dataclass | django
    table: str | None = None
    is_vector: bool = False
    fields: list[PiiField] = Field(default_factory=list)
    all_field_names: list[str] = Field(default_factory=list)
    ambiguous_fields: list[str] = Field(default_factory=list)

    @property
    def categories(self) -> set[str]:
        return {f.category for f in self.fields}


class FunctionInfo(BaseModel):
    qualname: str
    file: str
    line: int
    route_method: str | None = None
    route_path: str | None = None
    is_delete_handler: bool = False
    deletes: set[SinkKind] = Field(default_factory=set, description="Store kinds deleted (transitive).")
    calls: list[str] = Field(default_factory=list)


class ConfigFact(BaseModel):
    """A security/config observation, e.g. debug on, CORS '*', verify=False."""

    kind: str
    location: Location
    detail: str = ""
    value: str | None = None


class CodeFacts(BaseModel):
    root_name: str = ""
    files_scanned: int = 0
    python_files: int = 0
    parse_errors: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    detections: list[Detection] = Field(default_factory=list)
    models: list[PiiModel] = Field(default_factory=list)
    sinks: list[SinkEvent] = Field(default_factory=list)
    deletes: list[DeleteOp] = Field(default_factory=list)
    functions: list[FunctionInfo] = Field(default_factory=list)
    config: list[ConfigFact] = Field(default_factory=list)
    ambiguous_names: list[Location] = Field(default_factory=list)

    # ---- convenience queries used by rule checks ----
    def sinks_of(self, *kinds: SinkKind, pii_only: bool = False) -> list[SinkEvent]:
        return [s for s in self.sinks if s.kind in kinds and (s.carries_pii or not pii_only)]

    def config_of(self, *kinds: str) -> list[ConfigFact]:
        return [c for c in self.config if c.kind in kinds]

    def pii_store_kinds(self) -> set[SinkKind]:
        return {s.kind for s in self.sinks if s.kind in STORAGE_SINKS and s.carries_pii}

    @property
    def delete_handlers(self) -> list[FunctionInfo]:
        return [f for f in self.functions if f.is_delete_handler]
