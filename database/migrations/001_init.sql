-- Group 12 QR Auth - PostgreSQL (Neon) schema. Paste into the Neon SQL Editor.
BEGIN;

CREATE TABLE users (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),  -- unique user ID
    full_name      VARCHAR(120) NOT NULL,
    email          VARCHAR(190) NOT NULL,
    phone          VARCHAR(20)  NOT NULL,
    password_hash  VARCHAR(255) NOT NULL,
    account_status VARCHAR(12)  NOT NULL DEFAULT 'PENDING'
                   CHECK (account_status IN ('PENDING','ACTIVE','DEACTIVATED')),
    role           VARCHAR(10)  NOT NULL DEFAULT 'USER' CHECK (role IN ('USER','ADMIN')), -- extra column
    last_login_at  TIMESTAMPTZ,                                                            -- extra column
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_unique ON users (lower(email));  -- case-insensitive unique email

CREATE TABLE two_factor_auth (
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id               UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    encrypted_totp_secret TEXT NOT NULL,
    is_enabled            BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_time_step   BIGINT,          -- replay protection
    verified_at           TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE recovery_codes (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  VARCHAR(255) NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id);

CREATE TABLE login_attempts (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    attempt_status VARCHAR(30) NOT NULL,   -- SUCCESS, FAILED_PASSWORD, FAILED_OTP
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX login_attempts_user_time_idx ON login_attempts (user_id, created_at DESC);

CREATE TABLE audit_logs (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    action      VARCHAR(60) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_time_idx ON audit_logs (created_at DESC);

-- Sessions live in the database because Vercel containers have no durable disk
-- and several instances may serve one user.
CREATE TABLE sessions (
    id         VARCHAR(128) PRIMARY KEY,
    data       TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

COMMIT;
