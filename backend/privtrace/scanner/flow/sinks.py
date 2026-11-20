"""Sink catalogue: maps a resolved call chain to a sink kind.

A call like `client.models.generate_content(...)` is resolved to a *chain*
string by `Resolver` (see taint.py): the root name is replaced by its import
target (`requests`, `logging`) or by an object *kind* inferred from how it was
created (`genai_client`, `redis`, `db_session`). Patterns below match chains.
"""

from __future__ import annotations

import re

from privtrace.scanner.facts import SinkKind

# Calls that create objects of a known kind: resolved callee -> kind.
FACTORIES: dict[str, str] = {
    "logging.getLogger": "logger",
    "structlog.get_logger": "logger",
    "structlog.getLogger": "logger",
    "loguru.logger": "logger",
    "redis.Redis": "redis",
    "redis.StrictRedis": "redis",
    "redis.from_url": "redis",
    "redis.Redis.from_url": "redis",
    "redis.asyncio.Redis": "redis",
    "redis.asyncio.from_url": "redis",
    "redis.asyncio.Redis.from_url": "redis",
    "google.genai.Client": "genai_client",
    "google.generativeai.GenerativeModel": "genai_model",
    "vertexai.generative_models.GenerativeModel": "genai_model",
    "openai.OpenAI": "openai",
    "openai.AsyncOpenAI": "openai",
    "openai.AzureOpenAI": "openai",
    "anthropic.Anthropic": "anthropic",
    "anthropic.AsyncAnthropic": "anthropic",
    "langchain_openai.ChatOpenAI": "langchain_llm",
    "langchain_google_genai.ChatGoogleGenerativeAI": "langchain_llm",
    "langchain_anthropic.ChatAnthropic": "langchain_llm",
    "langchain_google_vertexai.ChatVertexAI": "langchain_llm",
    "langchain_openai.OpenAIEmbeddings": "embedder",
    "langchain_google_genai.GoogleGenerativeAIEmbeddings": "embedder",
    "chromadb.Client": "chroma",
    "chromadb.PersistentClient": "chroma",
    "chromadb.HttpClient": "chroma",
    "pinecone.Pinecone": "pinecone",
    "httpx.Client": "http_client",
    "httpx.AsyncClient": "http_client",
    "requests.Session": "http_client",
    "requests.session": "http_client",
    "aiohttp.ClientSession": "http_client",
    "psycopg.connect": "dbconn",
    "psycopg2.connect": "dbconn",
    "sqlite3.connect": "dbconn",
    "asyncpg.connect": "dbconn",
    "sqlalchemy.create_engine": "engine",
    "sqlalchemy.orm.sessionmaker": "session_factory",
    "sqlalchemy.orm.Session": "db_session",
    "posthog.Posthog": "posthog",
    "mixpanel.Mixpanel": "mixpanel",
}

# Method calls on a known kind that produce another kind.
DERIVED: dict[tuple[str, str], str] = {
    ("chroma", "get_or_create_collection"): "chroma_collection",
    ("chroma", "get_collection"): "chroma_collection",
    ("chroma", "create_collection"): "chroma_collection",
    ("pinecone", "Index"): "vector_index",
    ("dbconn", "cursor"): "dbcursor",
    ("engine", "connect"): "dbconn",
    ("engine", "begin"): "dbconn",
    ("session_factory", "__call__"): "db_session",
    ("redis", "pipeline"): "redis",
}

# Parameter / variable annotations that imply a kind.
ANNOTATION_KINDS: dict[str, str] = {
    "Session": "db_session",
    "AsyncSession": "db_session",
    "sqlalchemy.orm.Session": "db_session",
    "sqlalchemy.ext.asyncio.AsyncSession": "db_session",
    "redis.Redis": "redis",
    "Redis": "redis",
    "redis.asyncio.Redis": "redis",
    "logging.Logger": "logger",
    "Logger": "logger",
}

# Naming conventions used when the object's origin can't be resolved.
NAME_HINTS: dict[str, str] = {
    "logger": "logger", "log": "logger", "_logger": "logger", "LOGGER": "logger", "_log": "logger",
    "redis": "redis", "redis_client": "redis", "rds": "redis", "cache": "redis", "r": "redis",
    "session": "db_session", "db": "db_session", "db_session": "db_session",
    "cursor": "dbcursor", "cur": "dbcursor", "conn": "dbconn", "connection": "dbconn",
    "collection": "chroma_collection", "index": "vector_index",
    "llm": "langchain_llm", "chat_model": "langchain_llm",
    "embeddings": "embedder", "embedder": "embedder",
    "http": "http_client", "client_http": "http_client",
}

_LOG_METHODS = r"(debug|info|warning|warn|error|exception|critical|fatal|log|msg)"
_REDIS_WRITE = r"(set|setex|psetex|setnx|mset|hset|hmset|hsetnx|lpush|rpush|sadd|zadd|append|xadd|json\(\)\.set)"
_HTTP = r"(get|post|put|patch|delete|request|head|options|send|stream)"

SINK_PATTERNS: list[tuple[re.Pattern[str], SinkKind]] = [
    (re.compile(p), k)
    for p, k in [
        # logging
        (rf"logger\.{_LOG_METHODS}", SinkKind.log),
        (rf"logging\.{_LOG_METHODS}", SinkKind.log),
        (r"print", SinkKind.log),
        (rf"loguru\.logger\.{_LOG_METHODS}", SinkKind.log),
        # LLM / AI APIs (embedding APIs also send data to the provider)
        (r"genai_client\.(aio\.)?models\.(generate_content(_stream)?|embed_content|count_tokens)", SinkKind.llm),
        (r"genai_client\.(aio\.)?chats\.create(\(\))?\.send_message(_stream)?", SinkKind.llm),
        (r"genai_model\.(generate_content|send_message|start_chat\(\)\.send_message)(_async)?", SinkKind.llm),
        (r"google\.generativeai\.(embed_content|generate_text|chat)", SinkKind.llm),
        (r"openai\.(chat\.completions|completions|responses|embeddings)\.create", SinkKind.llm),
        (r"openai\.(ChatCompletion|Completion|Embedding)\.create", SinkKind.llm),
        (r"anthropic\.messages\.(create|stream)", SinkKind.llm),
        (r"langchain_llm\.(invoke|ainvoke|predict|stream|astream|batch|generate|__call__)", SinkKind.llm),
        (r"embedder\.(embed_documents|embed_query|aembed_documents|aembed_query)", SinkKind.llm),
        # vector stores
        (r"chroma_collection\.(add|upsert|update)", SinkKind.vector_store),
        (r"vector_index\.(upsert|add|update)", SinkKind.vector_store),
        (r"faiss\..*\.add|faiss_index\.add", SinkKind.vector_store),
        (r".*\.(add_texts|add_documents|aadd_texts|aadd_documents)", SinkKind.vector_store),
        # cache
        (rf"redis\.{_REDIS_WRITE}", SinkKind.cache),
        # third-party HTTP
        (rf"(requests|httpx)\.{_HTTP}", SinkKind.http),
        (rf"http_client\.{_HTTP}", SinkKind.http),
        (r"urllib\.request\.urlopen", SinkKind.http),
        # database writes
        (r"db_session\.(add|add_all|merge|execute|bulk_save_objects|bulk_insert_mappings)", SinkKind.db_write),
        (r"(dbcursor|dbconn|engine)\.(execute|executemany)", SinkKind.db_write),
        (r"\w+\.objects\.(create|update_or_create|get_or_create|bulk_create)", SinkKind.db_write),
        # file writes
        (r"file_w\.(write|writelines|writerow|writerows)", SinkKind.file_write),
        (r".*\.write_text", SinkKind.file_write),
        (r"json\.dump", SinkKind.file_write),
        # analytics
        (r"(posthog)\.(capture|identify|alias)", SinkKind.analytics),
        (r"(mixpanel)\.(track|people_set|people_set_once|alias)", SinkKind.analytics),
        (r"analytics\.(track|identify|page|group)", SinkKind.analytics),
        (r"segment\.analytics\.(track|identify|page)", SinkKind.analytics),
        (r"sentry_sdk\.set_user", SinkKind.analytics),
        (r"amplitude\..*\.track", SinkKind.analytics),
    ]
]

DELETE_PATTERNS: list[tuple[re.Pattern[str], SinkKind]] = [
    (re.compile(p), k)
    for p, k in [
        (r"redis\.(delete|unlink|hdel|getdel|expire|pexpire|expireat|flushdb|flushall)", SinkKind.cache),
        (r"chroma_collection\.delete", SinkKind.vector_store),
        (r"vector_index\.delete", SinkKind.vector_store),
        (r".*\.delete_documents|faiss.*\.remove_ids|.*vectorstore\.delete", SinkKind.vector_store),
        (r"db_session\.delete", SinkKind.db_write),
        (r"db_session\.query\(\)(\.\w+\(\))*\.delete", SinkKind.db_write),
        (r"\w+\.objects(\.\w+\(\))*\.delete", SinkKind.db_write),
        (r"sqlalchemy\.delete", SinkKind.db_write),
        (r"os\.(remove|unlink)|shutil\.rmtree|.*\.unlink", SinkKind.file_write),
    ]
]

# Function names that transform data so it's no longer raw PII (redaction / hashing).
SANITIZER_NAME = re.compile(
    r"(redact|mask|anonymi[sz]|pseudonymi[sz]|scrub|sanitiz|encrypt|hash|strip_pii|remove_pii|"
    r"deidentif|tokeni[sz]e_pii|hashpw|generate_password_hash|bcrypt|argon2)",
    re.IGNORECASE,
)

# Calls that read the raw request body.
REQUEST_BODY = re.compile(
    r"(request|req)\.(json|form|body|get_json|data|values|stream|args)(\(\))?$"
)

SQL_WRITE = re.compile(r"^\s*(insert\s+into|update|upsert|merge\s+into|replace\s+into)\s+([\w.\"]+)", re.I)
SQL_DELETE = re.compile(r"^\s*(delete\s+from|truncate(\s+table)?)\s+([\w.\"]+)", re.I)
SQL_VECTOR_HINT = re.compile(r"(::vector|<->|<=>|<#>|\bembedding|\bvector\b)", re.I)


def match_sink(chain: str) -> SinkKind | None:
    for pat, kind in SINK_PATTERNS:
        if pat.fullmatch(chain):
            return kind
    return None


def match_delete(chain: str) -> SinkKind | None:
    for pat, kind in DELETE_PATTERNS:
        if pat.fullmatch(chain):
            return kind
    return None
