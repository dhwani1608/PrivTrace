# demo-app — deliberately non-compliant RAG chatbot

**Do not deploy.** This FastAPI app exists so PrivTrace has something realistic to find.
All keys, users and identifiers are fake (`@example.com`, `98765 0000x`, test card `4111…`).

What's wrong with it (on purpose):

| Problem | Where |
|---|---|
| Chat messages + user email/phone sent straight into a Gemini prompt | `app/main.py` `chat()` |
| Full request bodies (incl. passwords, PAN) logged | `app/main.py` `log_requests()` |
| Signup logs email / phone / PAN | `app/main.py` `signup()` |
| Embeddings of personal data stored in pgvector | `Memory` model, `chat()` |
| User profiles cached in Redis with no TTL | `app/cache.py` |
| `DELETE /users/{id}` only deletes the Postgres row | `app/main.py` `delete_user()` |
| Hardcoded API key, committed `.env` | `app/config.py`, `.env` |
| Plaintext passwords | `User.password` |
| `debug=True`, CORS `*`, SQL built with an f-string | `app/main.py` |
| Fake identifiers in fixtures | `fixtures/seed_users.json` |

See `../demo-app-fixed/` for the same app with fixes applied.

```bash
privtrace scan ../demo-app --packs dpdp,security --out demo.html
privtrace scan ../demo-app-fixed --packs dpdp,security --out fixed.html --baseline demo.json
```
