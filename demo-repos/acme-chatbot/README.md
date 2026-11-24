# Acme Chatbot (PrivTrace CI demo repository)

A small FastAPI + Gemini RAG chatbot used to demo the **PrivTrace CI compliance gate**. It starts
from `demo-app-fixed` (every PrivTrace finding already addressed) and adds:

- `.privtrace.yml`: Acme's choice of frameworks (DPDP + CERT-In + security baseline), its
  checklist answers, one rule turned off with a reason, and the gate (`min_score: 75`,
  DPDP at least 75, fail on any new high or critical finding).
- `.github/workflows/privtrace.yml`: the workflow that runs the gate on every PR to `main`.

All names, numbers and keys in this repository are fake.

Run the whole story locally (no GitHub needed) from the PrivTrace repository root:

```bash
bash scripts/demo_ci.sh
```

It creates a throw-away git repository from this folder and runs `privtrace ci --base main` on
three branches:

| Branch | Change | Gate |
|---|---|---|
| `feature/good-change` | adds a `/health` endpoint | ✅ passes, score unchanged |
| `feature/risky-change` | logs the signup payload and sends the user's phone number to Gemini | ❌ fails: new high / critical findings, DPDP score drops |
| `feature/risky-change` + fix | applies the fix from the AI fix prompt | ✅ passes again |

See `docs/DEMO_SCRIPT_CI.md` for the 2-minute script.
