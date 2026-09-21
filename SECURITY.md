# RentManager — Security guide

What the application enforces, how to configure it, and what is **not** covered.

## 1. Input validation (`validators.py`)

| Threat | Control |
|---|---|
| SQL injection | All queries use the SQLAlchemy ORM (bound parameters). The only raw SQL is start-up migrations built from constants. Tests send classic payloads and assert they are stored literally. |
| XSS | (a) Every value is parsed/rejected server-side (`clean_text` strips control/bidi chars, rejects `<` `>` in single-line fields, enforces length). (b) **Output encoding is the primary defence**: Jinja autoescape, `|tojson` for data inside `<script>`, an `esc()` helper for `innerHTML`, `data-*` attributes instead of interpolating text into inline JS. Tests insert hostile data straight into the DB to prove output encoding holds on its own. |
| Type / range abuse | `parse_money` (strict ASCII grammar; rejects NaN, inf, negatives, `1e300`), `parse_int`, `parse_date`, `choice()` allow-lists for status/method/channel/role/scope. |
| Command injection | No `subprocess`/`os.system`/`eval`/`pickle` anywhere (verified by grep + bandit). |
| Unsafe uploads (`uploads.py`) | Extension allow-list **and** content sniffing; images decoded + re-encoded with Pillow (kills polyglots, strips EXIF/GPS); PDFs must start `%PDF-` and are screened for JavaScript/Launch; size, pixel and file-count caps; random server-side names (`<owner>/<uuid>.<ext>`); stored **outside** `static/`; served only via `/files/<key>` after login + ownership check; `nosniff` + restrictive CSP; files are deleted when the record is deleted. |
| Spreadsheet import | `.xlsx` only, magic-byte + zip-bomb check, 8 MB / 5 000-rows-per-sheet caps, strict numeric parsing, enum coercion, no raw error text. |
| Formula injection | Excel and CSV exports prefix `'` to cells starting with `= + - @`. |

## 2. Abuse & bot protection (`security.py`)

Central table `LIMITS` (Flask-Limiter, keyed by account when signed in, else IP):
login 10/min · sign-up 5/h · forgot-password / resend 5/h per IP **and** 3/h per target email ·
OCR 10/min · reminders 20/h + 10-min per-tenant cooldown + 60/day cap · Excel import 10/h, export 20/h ·
API 60/min · destructive actions 5/h · default 300/min. 429 responses are JSON for `/api/*`.
Plus: hidden honeypot field on login/sign-up/forgot forms, DB-backed account lockout
(5 failures → 15 min), `robots.txt` + `X-Robots-Tag: noindex`, everything behind login.

> **Multi-worker note:** the default limiter storage is per-process memory, so with N gunicorn
> workers the effective limit is up to N×. Set `RATELIMIT_STORAGE_URI=redis://…` for exact shared
> limits. Account lockout is stored in the database and is exact regardless.

There are **no LLM/"AI generation" endpoints** in this app. The closest cost-bearing calls
(third-party OCR, WhatsApp, SMS) carry the limits above. Not implemented: CAPTCHA — add
Cloudflare Turnstile/hCaptcha on `/signup` if you open registration publicly.

## 3. Secrets

* No secrets are committed. `render.yaml` uses `sync: false` (you enter them in the dashboard);
  `.env`, databases, uploads and keys are git-ignored.
* `SECRET_KEY` is **mandatory** in production (≥32 chars, placeholders rejected — the app refuses to boot).
* No default admin password: `ADMIN_PASSWORD` is validated; otherwise a random one-time password is
  generated and the account must change it at first login. Existing deployments still using
  `admin123` are detected at start-up and forced to change it (all sessions revoked).
* Templates never read `os.environ`/config; the Supabase service key is used only server-side.
* Logs mask phone numbers and never contain OCR text, passwords or tokens.
* ⚠️ **If this repo was ever pushed publicly**, secrets in Git history stay there — rotate anything that was
  real (WhatsApp token, Fast2SMS, Supabase key, DB password). Two personal email addresses that were in the
  old README were removed; they remain in history.

## 4. Deployment & monitoring

* **HTTPS:** HTTP→HTTPS redirect (308) in production, `Strict-Transport-Security`, `Secure` cookies,
  `upgrade-insecure-requests`. Requires the reverse proxy to send `X-Forwarded-Proto`
  (`TRUSTED_PROXIES=1`, the default in production). Redirect loop? Check `TRUSTED_PROXIES`, or set `FORCE_HTTPS=false`.
* **Headers:** CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP,
  `Cache-Control: no-store` on all authenticated pages.
  *CSP limitation:* `script-src` still allows `'unsafe-inline'` because the UI relies on ~110 inline handlers
  and inline scripts. Everything else is locked down; a nonce-based CSP is a larger refactor.
* **Database:** TLS forced (`sslmode=require`) for remote PostgreSQL. Use your provider's *private/internal*
  connection string and, on Supabase, enable *Network Restrictions*, keep the bucket **private**, and
  ensure RLS is on (`docs/supabase_lockdown.sql`; the app also applies it at start-up).
  Network-level restriction itself is provider configuration — this code cannot do it for you.
* **Logging:** one JSON line per event on logger `security`:
  `login_success/failed`, `account_locked`, `login_blocked_locked`, `password_changed/reset_*`,
  `email_verified`, `csrf_failure`, `rate_limited`, `request_rejected`, `file_access_denied`,
  `scanner_probe`, `suspicious_traffic` (≥30 4xx/min from one IP), `server_error`, admin actions, data resets.
  Every response carries `X-Request-ID`; unhandled errors show users only that reference, never a stack trace.
  Alert on: bursts of `login_failed`, any `account_locked`, `csrf_failure`, `suspicious_traffic`, `file_access_denied`.
* The Werkzeug debugger is only enabled with `APP_ENV=development` **and** loopback binding.
* Scheduler: only one process per host runs the jobs (file lock) so tenants don't get duplicate reminders.

## 5. Authentication

* scrypt password hashes (old hashes upgraded transparently at login); policy: 10–128 chars, common-password
  blocklist, no username/email inside, repetition check (NIST 800-63B style).
* Sessions: HttpOnly + SameSite=Lax + Secure cookies, 8 h absolute lifetime, 60 min idle timeout,
  **server-side revocation** via `session_version` (password change/reset/disable signs out every device),
  role and `is_active` re-checked from the DB on every request, session id renewed at login.
* Email verification (24 h link) required before sign-in; password reset links expire in **1 hour**,
  work **once** (bound to the current password hash) and are sent with `Referrer-Policy: no-referrer`.
  Responses never reveal whether an email/username exists; unknown users cost the same time as wrong passwords.
  Links use `PUBLIC_BASE_URL` (or Render's URL), never the request `Host` header (host-header poisoning).
* Logout is POST + CSRF. Admin-created accounts get a temporary password that must be changed at first login.
* Registration is **closed by default in production** (`SIGNUP_MODE=closed|invite|open`) because every account
  shares the deployment's WhatsApp/SMS credentials.
* Recovery: `flask --app app set-password <username>`.

## Environment variables

See `.env.example`. Security-relevant: `APP_ENV`, `SECRET_KEY`, `ADMIN_PASSWORD`, `SIGNUP_MODE`,
`SIGNUP_INVITE_CODE`, `REQUIRE_EMAIL_VERIFICATION`, `PUBLIC_BASE_URL`, `SMTP_*`, `TRUSTED_PROXIES`, `FORCE_HTTPS`,
`RATELIMIT_STORAGE_URI`, `SESSION_LIFETIME_HOURS`, `SESSION_IDLE_MINUTES`, `DB_SSLMODE`, `DB_ENABLE_RLS`, `UPLOAD_DIR`.

## Known limitations / recommended next steps

1. Tenant documents and payment screenshots are personal data. Payment screenshots are sent to OCR.space —
   use your own key, or self-host Tesseract if that is unacceptable.
2. Shared WhatsApp/SMS credentials across accounts (per-account credentials would remove the abuse vector).
3. Supabase storage code was written against the current `storage3` API and unit-tested with mocks,
   **not** against a live project — test an upload/download once after deploying.
4. Old objects already in a *public* Supabase bucket stay public until you make the bucket private and re-upload/migrate.
5. Add 2FA (TOTP) for the super-admin, dependency scanning in CI (`pip-audit`, `bandit`), and off-site encrypted backups.
6. The `/api/trigger-reminders` and `/api/trigger-sms` endpoints called by the Dashboard/Reminders buttons do not exist
   in the codebase (pre-existing bug); the buttons will show an error.
