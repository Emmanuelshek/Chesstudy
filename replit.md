# Chesstudy

A browser-based chess platform with public landing page, accounts, plans, and six features.

## Pages
- `/` — Public marketing landing page (no sidebar). Topbar swaps to "Open app" if signed in.
- `/auth` — Sign in / Create account (email + password, plus Google Sign-In if `GOOGLE_CLIENT_ID` is set).
- `/subscribe` — Plan picker. Secret access code unlocks paid plans for free.
- `/play` — Play vs Bot (Stockfish + 6 personality bots). All plans.
- `/openings` — 5 opening courses (Italian, Sicilian free; French, London, Ruy Lopez paid). Learn / Practice modes.
- `/classroom` — Multi-user rooms with WebRTC + chat. All plans.
- `/groups` — Persistent group messaging (text, photos, videos). All plans.
- `/review` — PGN game review with Stockfish move classification. **Unlimited+**.
- `/ai` — Chess AI coach chat (OpenAI). **Super Unlimited only**.

## Plans
| Plan | Price | Includes |
|---|---|---|
| Free | £0 | Play vs Bot, 2 openings, Classroom, Groups |
| Unlimited | £4/mo | Free + all 5 openings + Game Review |
| Super Unlimited | £7/mo | Unlimited + Chess AI Coach |

Payments aren't connected yet. The site owner's secret code **`2014`** unlocks any paid plan instantly (`/subscribe` modal).

## Stack
- **Backend:** Node.js 20, Express, `ws`, `nanoid`, `multer`, `bcryptjs`, `cookie-parser`, `google-auth-library`. See `server.js`.
- **Auth:** email/password (bcrypt) + Google Identity Services (server verifies the ID token). Sessions are random tokens stored in `data/sessions.json` and an httpOnly `cs_session` cookie.
- **Persistence:** plain JSON files in `data/` — `users.json`, `sessions.json`, `groups.json` (all written atomically via `tmp` + `rename`).
- **Plan-gating:** server-side route middleware (`requireAuth("unlimited"|"super")`) + client-side sidebar lock badges in `chess-core.js`.
- **AI:** `POST /api/ai/chat` calls **Pollinations.ai** (`https://text.pollinations.ai/openai`), a free, no-key OpenAI-compatible chat endpoint.
- **WebSocket routing:** single `server.on("upgrade")` handler dispatches `/ws` (classroom) and `/ws-groups` (groups) to `noServer:true` `WebSocketServer` instances. Groups WS requires the auth cookie at upgrade time and uses the session's user id as the group identity.
- **Groups persistence:** every mutation calls `persistGroups()`. Empty groups are **never** auto-deleted, so the host can return any time.

## Optional secrets (set in Replit Secrets)
- `GOOGLE_CLIENT_ID` — enables the "Continue with Google" button on `/auth`. Get one at https://console.cloud.google.com/apis/credentials → OAuth client ID (Web application). Add your Replit domain to Authorized JavaScript origins.

The AI coach uses **Pollinations.ai** (free, no API key required).

## Files
- `server.js` — Express + WS + auth + uploads + AI + persistence.
- `public/home.html` — public landing page.
- `public/auth.html` — sign in / sign up + Google button.
- `public/subscribe.html` — pricing page with secret-code modal.
- `public/index.html` — Play vs Bot.
- `public/openings.html` — Openings trainer (gates 3 courses for free users).
- `public/classroom.html` — Multi-user classroom.
- `public/groups.html` — Group messaging.
- `public/review.html` — Game Review.
- `public/ai.html` — Chess AI chat.
- `public/shared.css`, `public/chess-core.js` — shared sidebar (plan-aware), styles, piece sprites.
- `public/uploads/` — user-uploaded media.
- `data/` — JSON persistence (users, sessions, groups).

## Run
Workflow `Start application` runs `node server.js` on port 5000.
