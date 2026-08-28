# Changelog

## 0.8.1 — 2026-08-28

### Fixed

- **Unauthenticated traffic can no longer drive outbound JWKS fetches.** An
  unknown `kid` still refetches the JWKS to absorb key rotation, but the
  refetch is now gated to at most one per `:jwks_unknown_kid_cooldown` seconds
  (default 10) per `jwks_uri`; inside the window an unknown `kid` fails with
  `:unknown_signing_key` and no HTTP call. Previously each junk JWT carrying a
  made-up `kid` bought one fetch (two, with the single retry). That was safe
  while verification was only reachable after a successful token exchange, but
  apps now call `TokenVerifier.verify/4` directly from unauthenticated
  bearer-token plugs. The exposure was not bandwidth: Req shares one Finch
  instance whose pools are per host and default to 50 connections, and
  discovery, token exchange and JWKS all live on the issuer's host — so a few
  junk requests per second could saturate that pool and time out *login's*
  token exchange on checkout.

  The gate has its own `:persistent_term` key and never touches the JWKS cache
  entry's timestamp, so this traffic cannot extend the `jwks_max_stale` window
  a revoked signing key falls out of. Trade-off, deliberate and short: during a
  genuine rotation a token signed by a brand-new `kid` is refused until the
  gate opens or the 300s TTL refresh lands. Set `jwks_unknown_kid_cooldown` to
  tune it; `0` restores the previous behaviour and is not recommended for any
  app that verifies tokens on unauthenticated requests.

## 0.8.0 — 2026-08-27

### Added

- **Generic OIDC provider.** Authentication is now routed through a
  `SbAuthEx.Provider` behaviour with two implementations selected by config.
  Apps that set nothing keep the WorkOS AuthKit path unchanged; internal tools
  authenticating against a shared issuer set:

  ```elixir
  config :sb_auth_ex,
    provider: :oidc,
    oidc: [issuer: ..., client_id: ..., client_secret: ..., redirect_uri: ..., audience: ...]
  ```

  The OIDC provider runs authorization code + PKCE with `state`/`nonce`,
  resolves endpoints via OIDC discovery (with explicit overrides available,
  cached with a TTL and a bounded stale-on-error fallback), and verifies the
  access token against the issuer JWKS with an explicit asymmetric algorithm
  allowlist, exact issuer, exact audience (`audience` is required — it is the
  replay control on a shared issuer, sent as the RFC 8707 `resource` param on
  both the authorization and token requests) and expiry. When `openid` is in
  the scopes (the default), the token response must carry an `id_token`,
  verified with `aud` = `client_id` and a matching `nonce`. Identities are
  keyed on the verified `sub`; email comes from the verified id_token / access
  token claims or the userinfo endpoint. JWKS is refetched once on an unknown
  `kid` to absorb key rotation.
  For OIDC, logout is local-only and account deletion skips the provider step
  (the upstream identity belongs to the identity provider); `on_delete_account`
  and local identity deletion still run.

### Changed

- Routes, plugs, hooks, lifecycle callbacks, the state/PKCE cookie, the
  login-CSRF check, `return_to` and the `Identity` schema are shared across
  providers and unchanged. The oauth cookie now also carries the `nonce` for
  providers that use one; cookies minted by 0.7 remain redeemable during a
  rolling upgrade.
- Authentication failures that carry internal detail (discovery/JWKS/userinfo
  transport errors, malformed provider responses, non-WorkOS exceptions) are
  now logged server-side and shown to the user as a generic message instead of
  an `inspect/1` dump. A discovery outage at login time redirects with a flash
  instead of a 500.
- OIDC HTTP calls carry bounded timeouts (5s receive, 3s connect) and a single
  retry instead of Req's defaults, so a failing issuer cannot pin
  unauthenticated `/auth/login` requests for a minute each.
- An email claim explicitly marked `email_verified: false` is never used;
  `require_verified_email: true` additionally demands an affirmative
  `email_verified: true`.
- Multi-audience id_tokens require `azp` to equal the client_id
  (OIDC Core §3.1.3.7); `exp`/`nbf` accept fractional NumericDates; the
  issuer must be https (localhost excepted); `scopes` and `allowed_algs`
  are shape-validated at login.
- Stale-on-error serving is bounded per kind: 24h for discovery metadata,
  30 minutes (configurable via `jwks_max_stale`) for JWKS, so an
  emergency-revoked signing key falls out promptly.
- **Provider switch caveat:** account deletion goes through the currently
  configured provider — after moving an app from WorkOS to `provider: :oidc`,
  deleting a WorkOS-era identity no longer deletes the WorkOS user upstream.
  Drain pending deletions before switching, or clean up in
  `on_delete_account`.
- New deps: `jose ~> 1.11` (pulled in for every consumer, including
  WorkOS-only apps) and `req` (already present transitively) as a direct
  dependency.

## 0.7.1 — 2026-08-26

### Fixed

- Account deletion now requires WorkOS confirmation before application cleanup
  runs. Failures return `502` while retaining app data, the local identity, and
  the session for retry. A `404` counts as confirmation only when the structured
  WorkOS response identifies the exact requested user as already absent.
- The deletion callback is explicitly idempotent and runs only after WorkOS
  confirmation. The endpoint documentation no longer claims that repeated HTTP
  deletion requests return the same success response after the session is gone.

## 0.7.0 — 2026-08-20

### Security

- **Login CSRF fix.** `login` now mints a random OAuth `state` plus a PKCE
  code verifier/challenge (via `WorkOS.AuthKit.get_pkce_authorization_url/2`),
  stores them in a short-lived encrypted `HttpOnly` cookie, and `callback`
  refuses to exchange the authorization code unless the returned `state`
  matches (`Plug.Crypto.secure_compare/2`). Previously no `state` was sent, so
  an attacker could hand a victim their own `?code=` and bind the victim's
  session to the attacker's account.

### Changed (breaking)

- WorkOS SDK upgraded from `~> 1.1` to `~> 3.0` (explicit-client API). Requires
  Elixir 1.18+.
- WorkOS credentials are now read from `config :sb_auth_ex, workos: [api_key:,
  client_id:, redirect_uri:]` (new `SbAuthEx.WorkOSClient`). The 1.x shape
  `config :workos, WorkOS.Client, ...` is still honoured as a fallback, as are
  the `WORKOS_API_KEY` / `WORKOS_CLIENT_ID` environment variables.
- Logout redirects through `WorkOS.UserManagement.get_logout_url/2` (a local
  URL build) instead of a hand-rolled authenticated `Req.get` against the
  logout endpoint.
- Account deletion calls `WorkOS.UserManagement.delete_user/3`; a `404` from
  WorkOS is treated as already deleted.
- Dropped the direct `req` dependency (still present transitively via the SDK).
  `hackney` and `tesla` are no longer in the dependency tree.
- `callback` now surfaces WorkOS provider errors
  (`?error=...&error_description=...`) as a flash instead of "missing
  authorization code".

### Dependencies

- phoenix 1.8.11, phoenix_live_view 1.2.9, plug 1.20, ecto 3.14, ecto_sql 3.14,
  req 0.7, ex_doc 0.40 (dev), postgrex 0.22 (test).

## 0.6.1

- Public `SbAuthEx.delete_account/2`.

## 0.6.0

- Account deletion (`DELETE /auth/account`, `on_delete_account` callback).

## 0.5.0

- `on_logout` / `on_register` callbacks, `return_to` support on login.
