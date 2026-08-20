# Changelog

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
