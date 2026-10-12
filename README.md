# AI Security Platform

A firewall for AI apps. It sits between a chatbot and the language model and protects it.

**Live demo:** _add your Vercel link here_ · **API docs:** _your Render URL_/docs

## What it does

| Part | What it does | OWASP LLM Top 10 (2025) |
|---|---|---|
| **LLM Gateway** | Scores every prompt for injection attempts and blocks risky ones. Hides emails, phone numbers, Aadhaar, PAN, cards and API keys. Scans the model's answer for leaks. Rate limits and logs everything. | LLM01, LLM02 |
| **Red-team scanner** | Fires 20 known attack prompts at a demo bot and reports a security score, with protection off and on. | LLM01, LLM02, LLM07 |
| **Agent permission layer** | Before an AI agent runs a tool, it asks for a decision: allow, deny, or require human approval. Unknown tools are denied by default. Dangerous arguments (`rm -rf`, `DROP TABLE`, `../`) are always denied. | LLM06 |

## How it works

```
Your app / chatbox ──▶  FastAPI gateway  ──▶  Gemini
                          │  1. score the prompt (injection rules)
                          │  2. hide sensitive data
                          │  3. block, or forward to the model
                          │  4. scan the answer, hide leaks
                          ▼
                       Supabase (Postgres): logs, scans, policies, tool calls
                          ▲
Dashboard (Vercel) ───────┘  reads everything through the backend API
```

The Supabase secret key lives only in the backend. The browser never talks to the database directly, and Row Level Security is on with no public policies.

## Tech

Python 3.12+, FastAPI, httpx, Pydantic, pytest · Supabase (Postgres) · Google Gemini · plain HTML/CSS/JS dashboard · Render (backend) + Vercel (frontend)

## Where the API keys go

You need three things. Copy `.env.example` to `backend/.env` for local use, and enter the same names in Render for the live site.

| Variable | Where to get it | Where to put it |
|---|---|---|
| `GEMINI_API_KEY` | https://aistudio.google.com/apikey | `backend/.env` locally, Render env vars when deployed |
| `SUPABASE_URL` | Supabase → Project Settings → API → Project URL | same places |
| `SUPABASE_SERVICE_KEY` | Supabase → Project Settings → API → **service_role** (secret) | same places. Backend only, never in `frontend/` |
| `ADMIN_API_KEY` (optional) | Make up a long random string | Render. Protects changing policies and approving tool calls |
| `ALLOWED_ORIGINS` | Your Vercel URL, e.g. `https://my-app.vercel.app` | Render |

The frontend needs **no keys at all**. It only needs the backend's address, which goes in `frontend/config.js` as `window.API_BASE`.

Without keys, everything still runs: with no Gemini key the app uses a fake "mock mode" model, and with no Supabase keys it keeps data in memory. Mock mode is for testing only. Its model is deliberately easy to trick, so scanner scores in mock mode are not real results. Add a Gemini key to see real behaviour.

## Run it on your Mac

```bash
# 1. Database: in Supabase open SQL Editor, paste supabase/schema.sql, click Run

# 2. Backend
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env        # then open .env and paste your keys
uvicorn app.main:app --reload  # http://localhost:8000/docs

# 3. Tests
pytest

# 4. Dashboard (second terminal)
cd frontend
python3 -m http.server 5173    # open http://localhost:5173
```

## Deploy

**Backend on Render:** New → Web Service → connect this repo. Render reads `render.yaml`. In the dashboard, fill in the environment variables from the table above. The free plan sleeps after inactivity, so the first request can take about 30 seconds.

**Frontend on Vercel:** New Project → import this repo → set **Root Directory** to `frontend` → Framework preset **Other** → Deploy. Before that, edit `frontend/config.js` so `window.API_BASE` is your Render URL, then set `ALLOWED_ORIGINS` on Render to your Vercel URL.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/chat` | Protected chat. Body: `{"message": "...", "system": "optional"}` |
| POST | `/v1/chat/completions` | OpenAI-compatible. Point any OpenAI-style client's base URL here |
| POST | `/v1/demo/chat` | Public playground, with a protection on/off switch |
| GET | `/v1/logs`, `/v1/stats` | Request log and statistics |
| POST | `/v1/scans` | Run the red-team scan. Body: `{"protect": true}` |
| GET | `/v1/scans`, `/v1/scans/{id}` | Past scans and their results |
| POST | `/v1/agents/check` | Ask permission for a tool call |
| GET/PUT | `/v1/agents/policies` | List or change policies (PUT needs the admin key if set) |
| POST | `/v1/agents/tool-calls/{id}/approve` or `/reject` | Resolve a pending call (admin key if set) |

Connect your own app by sending it to the gateway instead of the model:

```bash
curl -X POST https://YOUR-BACKEND/v1/chat \
  -H "Content-Type: application/json" -H "x-gateway-key: YOUR_KEY" \
  -d '{"message": "How do I reset my card PIN?"}'
```

## Honest limitations

- Injection detection is rule based. Obfuscated attacks (for example leetspeak) can pass the input check. That is why the output is scanned too, and the scanner reports such cases as `contained` rather than `blocked`.
- Rate limits and the scan cooldown are kept in memory, so they reset on restart and apply per server instance.
- PII patterns target common Indian and international formats and will miss unusual ones.
- This is a learning and portfolio project, not a certified security product.

## Ideas to extend

Semantic (embedding based) injection detection · per-tenant API keys stored in Supabase · Supabase Auth for the dashboard · streaming responses · an attack library loaded from a file.
