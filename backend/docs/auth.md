# Auth subsystem — design notes

## Overview

- JWTs: short-lived access tokens (issued at login/refresh). Used with `Authorization: Bearer <jwt>` for protected API calls.
- Refresh tokens: long-lived, stored on server (hashed) and held by client. Used to obtain new JWTs when the access token expires. Implemented with rotation: each refresh replaces the previous, and old tokens are revoked.

## Why both?

- JWTs are stateless and efficient for API auth; short lifetime reduces risk if leaked.
- Refresh tokens allow short JWT lifetimes without frequent logins and permit server-side revocation and device/session management.

## How refresh is implemented in this project

- On login: server generates a secure random refresh token string, stores only its SHA-256 hash in DB (prevents reuse if DB leaked), returns the plain token to the client.
- On refresh: client sends refresh token; server hashes it, finds the stored token, ensures it is not revoked and not expired. Server issues a new JWT and a new refresh token, revokes the old token (rotation), and stores the new token's hash.
- Logout/revoke: server marks the refresh token revoked.

## Note on [Authorize]

- `[Authorize]` and the JWT bearer handler validate the JWT (access token). Refresh tokens are not bearer tokens for API endpoints — they are only presented to the `api/auth/refresh` endpoint and validated against the persisted (hashed) store.

## 2FA / Phone in current stage (mock)

- Current implementation exposes endpoints that generate and return verification codes (stored in in-memory cache) for:
  - enabling 2FA (mock challenge)
  - adding and verifying phone numbers
- For production:
  - Use a reliable SMS provider (Twilio, AWS SNS, etc.)
  - Persist verification attempts and rate-limit attempts
  - Use authenticator apps (TOTP) or hardware keys for stronger 2FA
  - Store 2FA secret keys encrypted and use Identity's authenticator token APIs

## Next-hardening steps

- Add persistent store for verification attempts (so restarts don't lose state).
- Use an SMS gateway and do phone number canonicalization.
- Add device identifiers, session names, and an endpoint to revoke all sessions.
- Instrument auth events (success/fail, suspicious activity) and alert on anomalies.
