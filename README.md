# GROUP 12 – Secure QR Authentication System

A PHP web app that protects registration with **QR-based two-factor authentication (TOTP)** and OTP verification.
Backend: PHP 8.4 + PDO · Database: Neon PostgreSQL · Hosting: Vercel (Docker + FrankenPHP) · UI: Bootstrap 5.

> ⚠️ **Differences from the original assignment (PHP 7 + MySQL)** – get written/verbal approval from your lecturer:
> PHP 8.4 instead of PHP 7, and PostgreSQL (Neon) instead of MySQL. The code is plain PHP + PDO and the SQL is
> standard, so it is easy to explain. Vercel's container runtime for PHP is documented by Vercel
> (https://vercel.com/kb/guide/deploy-php-on-vercel-with-docker); FrankenPHP is an official PHP app server built on Caddy.

## 1. Objectives
Hide registration secrets in a QR code · two-factor authentication · generate/verify OTP · activate account only after OTP · validate every form.

## 2. Folder structure
```
public/      only folder exposed to the web (pages + assets)
app/         bootstrap.php (all logic helpers), layout.php (navbar/footer)
database/    migrations/001_init.sql
scripts/     create-admin.php (run on your computer only)
tests/       run_tests.php (offline unit tests)
Dockerfile.vercel, Caddyfile, vercel.json   deployment
```

## 3. How it works (explain this in your demo)
1. **Register** (`register.php`) – validated in browser (`validate.js`) *and* PHP (`validate_registration`). `password_hash()` hashes the password; user row is saved as `PENDING` inside a **transaction** with a random 160-bit TOTP secret, encrypted with libsodium (`encrypt_secret`).
2. **QR code** (`setup-2fa.php`) – builds the URI `otpauth://totp/...?secret=...` and renders it as a QR. It contains **only** the secret and a label – never the password or personal data.
3. **OTP** (`verify-otp.php`) – the app and the server both compute `HMAC-SHA1(secret, floor(time/30))` → 6 digits (RFC 6238, function `totp_code`). The server accepts the current and ±1 time step. The accepted step is saved in `last_used_time_step`, so the same code **cannot be reused** (replay protection). 5 wrong tries in 15 min lock the account temporarily.
4. **Activation** – correct OTP → `PENDING → ACTIVE`, `verified_at` saved, 8 one-time **recovery codes** created (stored hashed, shown once).
5. **Login** – email + password (`password_verify`) → then OTP (or a recovery code) → session ID regenerated → dashboard.
6. **Admin** (`admin.php`) – list/search users, deactivate, view audit logs. Never sees passwords/secrets/codes.

Security summary: prepared statements everywhere (`q()` helper), CSRF tokens, output escaping `e()` (XSS), HttpOnly/Secure/SameSite cookies, 30-minute idle timeout, DB-stored sessions, CSP headers, generic login errors, secrets only in environment variables.

Beyond the spec: extra columns `users.role` and `users.last_login_at`, a `sessions` table, and status `DEACTIVATED`.

## 4. Run on your computer (step by step)
1. Install PHP 8.2+ (with `pdo_pgsql`, `sodium`) and Composer 2.
2. `composer install` (this also creates `composer.lock` – commit it).
3. Create a free project at https://neon.tech → copy the connection string.
4. In Neon's **SQL Editor** paste and run `database/migrations/001_init.sql`.
5. Copy `.env.example` to `.env` and fill it in. Generate the key:
   `php -r "echo base64_encode(random_bytes(32));"` → `TOTP_ENCRYPTION_KEY`. **Back it up – losing it makes all 2FA secrets unreadable.**
6. `php -S localhost:8000 -t public` → open http://localhost:8000
7. Create the admin: `php scripts/create-admin.php you@mail.com "Your Name" "Str0ng#Pass1"` and add the printed key to your authenticator.

## 5. Deploy to Vercel (step by step)
1. Run `composer install` locally and commit `composer.lock`.
2. Push to GitHub (you do this yourself – nothing here modifies your repository).
3. On vercel.com: **Add New → Project →** import `QUICKLYBESTONE/group12-qr-auth`. Vercel detects `Dockerfile.vercel`.
4. **Settings → Environment Variables**: add `DATABASE_URL`, `APP_ENV=production`, `APP_KEY`, `TOTP_ENCRYPTION_KEY`.
5. Deploy, then open the URL and test registration.

**Vercel limitations:** the container disk is not persistent (so data and sessions are in Neon); no cron/background workers; cold starts after idle; the admin script must be run from your own computer.

## 6. Testing
- Automated (no DB): `TOTP_ENCRYPTION_KEY=$(php -r 'echo base64_encode(random_bytes(32));') php tests/run_tests.php` – checks TOTP against the RFC 6238 vector, expiry, encryption, validation.
- Manual checklist: valid/invalid registration · duplicate email · password mismatch · weak password · QR shows · correct OTP activates · wrong OTP rejected · same OTP twice rejected (replay) · login before activation blocked · wrong password · 5 wrong OTPs lock · logout · visiting `/dashboard.php` logged out → 403 page · unknown URL → 404 page · check rows in Neon.

## 7. Status
Code written but **not yet executed** by its author (no PHP in the authoring environment). Run the tests above and fix anything that appears before presenting. Not deployed.
