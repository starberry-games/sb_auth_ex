# Changelog

## 0.8.1 — 2026-08-28

### Fixed

- **Unauthenticated traffic can no longer turn request rate into outbound JWKS
  or discovery request rate.** Token verification is reachable from
  unauthenticated bearer-token plugs, not only from the login callback, and
  `/auth/login` resolves discovery before anything is authenticated. Every
  outbound request those paths can cause is now paced per key:

    * an unknown `kid` refetches the JWKS at most once per
      `:jwks_refetch_cooldown` seconds (default 10) per `jwks_uri`. Previously
      every junk JWT carrying a made-up `kid` bought a fetch (two, with the
      single retry).
    * a **stale** cache entry refreshes at most once per that same window,
      sharing one budget with the refetch above. Previously a stale entry
      re-attempted the fetch on *every* request for the whole `max_stale`
      window, so a failing issuer made this a 1:1 amplifier with no junk `kid`
      needed. Denied callers serve the stale value, so this costs nothing.
    * a **cold** entry has nothing to serve, so its fetch is not refused on the
      way in — that would fail requests at cold start against a healthy issuer.
      It is paced on the way out instead: a failure is remembered for one
      window and replayed with no HTTP call.

  Discovery is paced by the same three mechanisms, on a fixed 10-second window
  (not configurable, like its `max_stale`).

  The exposure was never bandwidth: Req shares one Finch instance whose pools
  are per host and default to 50 connections, and discovery, token exchange and
  JWKS all live on the issuer's host — so a few junk requests per second could
  saturate that pool and time out *login's* token exchange on checkout.

  Scope, stated honestly: once an entry or a failure has landed, this is
  roughly one outbound request per window per key. It is *roughly* because the
  gate's check and write are not atomic, so callers that read an open gate in
  the gap between them all proceed. On a cold cache, before any result has
  landed, concurrent callers all fetch — bounded by instantaneous concurrency
  rather than by request rate. Closing either fully needs a process to
  serialize on, and SbAuthEx deliberately has no supervision tree.

  The pacing state lives under its own `:persistent_term` keys and never
  touches a cache entry's timestamp, so this traffic cannot extend the
  `jwks_max_stale` window a revoked signing key falls out of.

### Changed

- **`verify/4` error surface.** A refusal to look up a key is now
  `{:error, :signing_key_unavailable}`, distinct from
  `{:error, :unknown_signing_key}`, which continues to mean a refetch happened
  and the issuer does not have that `kid`. Consumers matching on
  `:unknown_signing_key` to build a 401 should match both. Relatedly, a JWKS or
  discovery failure replayed from the negative cache returns the *original*
  error term (`{:jwks_fetch_failed, reason}` / `{:discovery_failed, reason}`),
  so the term may describe a call made up to a cooldown window earlier.
- **Availability trade-offs, both bounded by the cooldown.** During a genuine
  key rotation a token signed by a brand-new `kid` is refused until the gate
  opens or the TTL refresh lands. After an issuer outage ends, the cached
  failure can still be replayed briefly before requests recover.
- Cache and gate durations are validated at config time: a non-integer
  `:discovery_cache_ttl`, `:jwks_cache_ttl`, `:jwks_max_stale`,
  `:jwks_refetch_cooldown` or `:leeway_seconds` now raises with a clear
  message. Erlang term ordering sorts atoms and binaries above every integer,
  so a `nil` from an unset `System.get_env/1` — or the binary from a set one —
  would previously not crash: it would silently make an entry immortal or wedge
  the refetch gate shut for the life of the node.
- `ex_doc`'s `source_ref` no longer prefixes the version with `v`; this repo's
  tags are unprefixed, so every source link in the generated docs pointed at a
  ref that does not exist.

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
