# demo-app-fixed — the demo chatbot with PrivTrace's fixes applied

Same app as `../demo-app`, changed so each PrivTrace finding is addressed:

| Finding in demo-app | Fix here |
|---|---|
| PII in Gemini prompts / embeddings | `redact_pii()` before every model call (`app/llm.py`) |
| Request bodies and PII in logs | middleware logs method/path/status only; redacting log filter |
| Redis profile without TTL | `ex=CACHE_TTL_SECONDS`, and only the display name is cached |
| Delete only removed the DB row | `delete_user()` erases memories (pgvector), the user row and the Redis profile |
| Hardcoded key, committed `.env` | settings from the environment; only `.env.example` committed |
| Plaintext passwords | bcrypt via passlib (`hash_password`) |
| debug, CORS `*`, f-string SQL | env-driven debug, explicit origins, bound parameters |
| No consent captured | `consent_given` + `consent_notice_version` required at signup |
| PAN collected for a chatbot | removed (minimisation) |
| No retention | `purge_old_memories()` + 180-day log rotation |
| Unauthenticated delete | `Depends(get_current_user)` + ownership check |

Organisational items (processor contracts, breach process, grievance contact) can't be fixed in code; answer them in the PrivTrace checklist.
