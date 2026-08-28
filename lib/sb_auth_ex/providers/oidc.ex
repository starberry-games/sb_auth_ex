defmodule SbAuthEx.Providers.OIDC do
  @moduledoc """
  Generic OIDC / OAuth 2.1 `SbAuthEx.Provider`: authorization code + PKCE with
  `state`/`nonce`, token exchange, and JWT verification against the issuer's
  JWKS. Built for issuers that mint JWT access tokens bound to a resource
  audience — a WorkOS Connect environment, for example — but not specific to
  any of them.

  ## Configuration

      config :sb_auth_ex,
        provider: :oidc,
        oidc: [
          issuer: "https://issuer.example.com",
          client_id: "client_...",
          client_secret: "...",              # optional — omit (or leave "") for a public client
          redirect_uri: "https://myapp.example/auth/callback",
          audience: "https://myapp.example"  # required, see below
        ]

  Required: `:issuer`, `:client_id`, `:redirect_uri`, `:audience`. The issuer
  must be `https` (`http` is allowed only for localhost).

  `:audience` is this app's own resource indicator. It is sent as the
  `resource` parameter on both the authorization and token requests (RFC 8707)
  and the returned access token's `aud` claim must contain it exactly. This is deliberately not
  optional: without audience binding, any valid token from a shared issuer —
  including one minted for a *different* tool — would be accepted here. If your
  issuer has no resource indicators and binds tokens to the client instead, set
  `audience` to the value your tokens actually carry (often the `client_id`).

  Optional keys:

    * `:scopes` — list or string, default `["openid", "profile", "email"]`
    * `:authorization_endpoint`, `:token_endpoint`, `:jwks_uri`,
      `:userinfo_endpoint` — explicit endpoints. When all of the first three
      are set, OIDC discovery (`/.well-known/openid-configuration`) is never
      fetched; otherwise discovery fills the gaps.
    * `:token_auth_method` — `:client_secret_basic` (default) or
      `:client_secret_post`; ignored without a `:client_secret`
    * `:allowed_algs` — JWT signature algorithm allowlist, default
      `["RS256", "ES256"]`. Keep it asymmetric.
    * `:leeway_seconds` — clock skew tolerance for `exp`/`nbf`, default 60
    * `:require_verified_email` — when `true`, an email claim is only used when
      the same claim set carries `email_verified: true`. Default `false`: an
      absent `email_verified` is accepted, but an explicit
      `email_verified: false` is always rejected.
    * `:authorize_params` — extra query params for the authorization request
      (e.g. `[prompt: "select_account"]`)
    * `:discovery_cache_ttl` / `:jwks_cache_ttl` — seconds, default 3600 / 300
    * `:jwks_max_stale` — how long an expired JWKS may keep serving when
      refreshing it fails, default 1800 seconds (stale discovery metadata is
      bounded at 24h)
    * `:jwks_refetch_cooldown` — seconds between outbound JWKS requests once a
      fresh cache entry cannot answer, default 10. It paces the refetch an
      unknown `kid` triggers and the cache's own refresh of a stale key set —
      which share one budget per `jwks_uri` — and it is also how long a failed
      fetch is replayed for before another is attempted. Token verification is reachable
      from unauthenticated traffic (a bearer-token plug verifying an inbound
      access token), so this is what stops made-up `kid`s — or a failing
      issuer — from turning request rate into outbound request rate and
      exhausting the HTTP connection pool that login's token exchange shares.
      The trade-off is that a genuinely rotated key may be refused for up to
      that long. `0` disables all JWKS fetch pacing; do not, if anything
      unauthenticated verifies tokens.
    * `:req_options` — passed verbatim to `Req` (tests inject a `Req.Test` plug)

  ## What a login verifies

  The access token returned by the token endpoint is the credential: its
  signature must verify against the issuer JWKS with an allowlisted asymmetric
  algorithm, `iss` must equal the configured issuer exactly, `aud` must contain
  the configured audience exactly, and `exp` (plus `nbf` when present) must
  hold. The identity is keyed on the verified `sub` — never on email — and
  `sub` lands in `SbAuthEx.Identity.sb_id` exactly where a WorkOS `user_...`
  id does today.

  When the `openid` scope is requested (it is in the default scopes), the token
  response must carry an `id_token` and it is verified too (same checks, with
  `aud` = `client_id`), its `nonce` must match the one minted at login, and its
  `sub` must match the access token's — a missing `id_token` fails the login,
  because accepting it would silently skip the nonce check. Configure `:scopes`
  without `openid` for plain OAuth 2 issuers that mint JWT access tokens but no
  id_token. Email comes from the first of: verified id_token claims, verified
  access token claims, the userinfo endpoint (whose `sub` must also match).

  ## Logout and account deletion

  `logout_url/2` returns `:none`: logging out clears the local session but does
  not end the session at the issuer (typical for SSO — the identity is owned by
  the upstream identity provider, not this app). `delete_user/1` is a no-op
  `:ok` for the same reason; `on_delete_account` and local identity deletion
  still run.
  """

  @behaviour SbAuthEx.Provider

  alias SbAuthEx.Providers.OIDC.Cache
  alias SbAuthEx.Providers.OIDC.HTTP
  alias SbAuthEx.Providers.OIDC.Metadata
  alias SbAuthEx.Providers.OIDC.TokenVerifier

  @default_scope "openid profile email"

  @impl true
  def authorize do
    config = config!()

    with {:ok, meta} <- Metadata.endpoints(config) do
      state = random_urlsafe()
      nonce = random_urlsafe()
      code_verifier = random_urlsafe()
      code_challenge = Base.url_encode64(:crypto.hash(:sha256, code_verifier), padding: false)

      params =
        [
          {"response_type", "code"},
          {"client_id", required!(config, :client_id)},
          {"redirect_uri", required!(config, :redirect_uri)},
          {"scope", scope(config)},
          {"state", state},
          {"nonce", nonce},
          {"code_challenge", code_challenge},
          {"code_challenge_method", "S256"},
          {"resource", required!(config, :audience)}
        ] ++ extra_authorize_params(config)

      {:ok,
       %{
         url: append_query(meta.authorization_endpoint, params),
         state: state,
         code_verifier: code_verifier,
         nonce: nonce
       }}
    end
  end

  @impl true
  def exchange_code(code, ctx) do
    config = config!()

    with {:ok, meta} <- Metadata.endpoints(config),
         {:ok, tokens} <- request_tokens(config, meta, code, ctx.code_verifier),
         {:ok, claims} <-
           TokenVerifier.verify(
             tokens["access_token"],
             config,
             meta.jwks_uri,
             required!(config, :audience)
           ),
         {:ok, sb_id} <- fetch_sub(claims),
         {:ok, id_claims} <-
           maybe_verify_id_token(config, meta, tokens["id_token"], ctx[:nonce], sb_id),
         {:ok, email} <- resolve_email(config, meta, tokens, id_claims, claims, sb_id) do
      {:ok,
       %SbAuthEx.Auth{sb_id: sb_id, email: email, session_id: session_id(claims), claims: claims}}
    end
  end

  @impl true
  def logout_url(_session_id, _return_to), do: :none

  @impl true
  def delete_user(_sb_id), do: :ok

  @doc """
  Clears cached discovery metadata, JWKS and the unknown-`kid` refetch gate.

  Useful in tests and after config changes; production code never needs it —
  caches expire on their own and JWKS refetches on unknown `kid`.
  """
  def reset_cache, do: Cache.reset()

  # ---------------------------------------------------------------------------
  # Token exchange
  # ---------------------------------------------------------------------------

  defp request_tokens(config, meta, code, code_verifier) do
    form = %{
      "grant_type" => "authorization_code",
      "code" => code,
      "redirect_uri" => required!(config, :redirect_uri),
      "code_verifier" => code_verifier,
      "client_id" => required!(config, :client_id),
      # RFC 8707 §2.2: repeat the resource indicator on the token request, so
      # issuers that bind the audience at exchange time (not at authorization
      # time) still mint a token our audience check accepts.
      "resource" => required!(config, :audience)
    }

    {form, auth_opts} = apply_client_auth(form, config)

    req_opts =
      HTTP.default_options() ++
        [
          url: meta.token_endpoint,
          method: :post,
          form: form,
          headers: [{"accept", "application/json"}]
        ] ++ auth_opts ++ HTTP.req_options(config)

    case Req.request(req_opts) do
      {:ok, %Req.Response{status: 200, body: %{"access_token" => token} = body}}
      when is_binary(token) and token != "" ->
        {:ok, body}

      {:ok, %Req.Response{status: 200}} ->
        {:error, :invalid_token_response}

      {:ok, %Req.Response{status: status, body: body}} ->
        {:error, {:token_endpoint_error, status, body}}

      {:error, exception} ->
        {:error, exception}
    end
  end

  defp apply_client_auth(form, config) do
    case {config[:client_secret], Keyword.get(config, :token_auth_method, :client_secret_basic)} do
      # An empty string (e.g. an unset env var read with System.get_env/1)
      # means "no secret", not "Basic auth with an empty password".
      {secret, _method} when secret in [nil, ""] ->
        {form, []}

      {secret, :client_secret_post} ->
        {Map.put(form, "client_secret", secret), []}

      {secret, :client_secret_basic} ->
        # RFC 6749 §2.3.1: id and secret are form-urlencoded inside the Basic value.
        client_id = URI.encode_www_form(required!(config, :client_id))
        {form, [auth: {:basic, client_id <> ":" <> URI.encode_www_form(secret)}]}
    end
  end

  # ---------------------------------------------------------------------------
  # Claims → identity
  # ---------------------------------------------------------------------------

  defp fetch_sub(%{"sub" => sub}) when is_binary(sub) and sub != "", do: {:ok, sub}
  defp fetch_sub(_claims), do: {:error, :missing_subject}

  defp session_id(%{"sid" => sid}) when is_binary(sid) and sid != "", do: sid
  defp session_id(_claims), do: nil

  # OIDC Core §3.1.3.3: when `openid` was requested, the token response MUST
  # carry an id_token. Accepting its absence would silently skip the nonce
  # check, so it is a hard failure; only non-OIDC scope configurations may run
  # on the access token alone.
  defp maybe_verify_id_token(config, _meta, nil, _nonce, _sub) do
    if openid_scope?(config), do: {:error, :missing_id_token}, else: {:ok, nil}
  end

  defp maybe_verify_id_token(config, meta, id_token, nonce, sub) do
    client_id = required!(config, :client_id)

    with {:ok, claims} <- TokenVerifier.verify(id_token, config, meta.jwks_uri, client_id),
         :ok <- check_azp(claims, client_id),
         :ok <- check_nonce(claims["nonce"], nonce),
         :ok <- check_sub_match(claims["sub"], sub) do
      {:ok, claims}
    end
  end

  # OIDC Core §3.1.3.7: an id_token with more than one audience must name this
  # client as the authorized party — otherwise an id_token minted for another
  # client at the same issuer would pass the membership check above.
  defp check_azp(%{"aud" => [_, _ | _]} = claims, client_id) do
    if claims["azp"] == client_id, do: :ok, else: {:error, :invalid_audience}
  end

  defp check_azp(_claims, _client_id), do: :ok

  defp check_nonce(claim, sent) when is_binary(claim) and is_binary(sent) do
    if Plug.Crypto.secure_compare(claim, sent), do: :ok, else: {:error, :invalid_nonce}
  end

  defp check_nonce(_claim, _sent), do: {:error, :invalid_nonce}

  defp check_sub_match(sub, sub) when is_binary(sub), do: :ok
  defp check_sub_match(_id_sub, _access_sub), do: {:error, :subject_mismatch}

  defp resolve_email(config, meta, tokens, id_claims, access_claims, sb_id) do
    require_verified = Keyword.get(config, :require_verified_email, false)

    case first_email([id_claims, access_claims], require_verified) do
      {:ok, email} -> {:ok, email}
      :error -> userinfo_email(config, meta, tokens["access_token"], sb_id, require_verified)
    end
  end

  defp first_email(claim_sets, require_verified) do
    Enum.find_value(claim_sets, :error, &usable_email(&1, require_verified))
  end

  # An email lands in the unique `sb_identities.email` column, so an address
  # the issuer marks unverified is never used — an attacker could otherwise
  # claim someone else's address at a lax issuer. With `require_verified_email`
  # the claim must be affirmatively true; by default an absent claim is
  # accepted (some issuers never emit it).
  defp usable_email(%{"email" => email} = claims, require_verified)
       when is_binary(email) and email != "" do
    case {claims["email_verified"], require_verified} do
      {false, _} -> nil
      {true, _} -> {:ok, email}
      {_, true} -> nil
      {_, false} -> {:ok, email}
    end
  end

  defp usable_email(_claims, _require_verified), do: nil

  defp userinfo_email(_config, %{userinfo_endpoint: nil}, _access_token, _sb_id, _verified),
    do: {:error, :missing_email}

  defp userinfo_email(config, meta, access_token, sb_id, require_verified) do
    headers = [{"authorization", "Bearer " <> access_token}]

    case HTTP.get_json(meta.userinfo_endpoint, config, headers: headers) do
      {:ok, %{"sub" => ^sb_id} = body} ->
        case usable_email(body, require_verified) do
          {:ok, email} -> {:ok, email}
          nil -> {:error, :missing_email}
        end

      {:ok, _body} ->
        {:error, :userinfo_subject_mismatch}

      {:error, reason} ->
        {:error, {:userinfo_failed, reason}}
    end
  end

  # ---------------------------------------------------------------------------
  # Config
  # ---------------------------------------------------------------------------

  defp config do
    Application.get_env(:sb_auth_ex, :oidc) || []
  end

  defp config! do
    config = config()

    for key <- [:issuer, :client_id, :redirect_uri, :audience], do: required!(config, key)

    validate_issuer_scheme!(config)
    validate_token_auth_method!(config)
    validate_scopes!(config)
    validate_allowed_algs!(config)
    validate_seconds!(config)

    config
  end

  defp validate_issuer_scheme!(config) do
    issuer = required!(config, :issuer)
    uri = URI.parse(issuer)

    # Plain http would run discovery, the code exchange (carrying the client
    # secret) and the JWKS fetch in cleartext. Loopback is exempt for dev.
    unless uri.scheme == "https" or
             (uri.scheme == "http" and uri.host in ["localhost", "127.0.0.1", "::1"]) do
      raise ArgumentError,
            "SbAuthEx: OIDC issuer must be https (got #{inspect(issuer)}); " <>
              "http is allowed only for localhost"
    end
  end

  defp validate_token_auth_method!(config) do
    case Keyword.get(config, :token_auth_method, :client_secret_basic) do
      method when method in [:client_secret_basic, :client_secret_post] ->
        :ok

      other ->
        raise ArgumentError,
              "SbAuthEx: unsupported OIDC token_auth_method #{inspect(other)} — " <>
                "use :client_secret_basic or :client_secret_post"
    end
  end

  defp validate_scopes!(config) do
    case config[:scopes] do
      nil ->
        :ok

      scope when is_binary(scope) ->
        :ok

      scopes when is_list(scopes) ->
        unless Enum.all?(scopes, &is_binary/1) do
          raise ArgumentError,
                "SbAuthEx: OIDC scopes must be a string or a list of strings — got #{inspect(scopes)}"
        end

        :ok

      other ->
        raise ArgumentError,
              "SbAuthEx: OIDC scopes must be a string or a list of strings — got #{inspect(other)}"
    end
  end

  defp validate_allowed_algs!(config) do
    case config[:allowed_algs] do
      nil ->
        :ok

      [_ | _] = algs ->
        unless Enum.all?(algs, &is_binary/1) do
          raise ArgumentError,
                "SbAuthEx: OIDC allowed_algs must be a non-empty list of strings — got #{inspect(algs)}"
        end

        :ok

      other ->
        raise ArgumentError,
              "SbAuthEx: OIDC allowed_algs must be a non-empty list of strings — got #{inspect(other)}"
    end
  end

  # Erlang term ordering sorts atoms and binaries above every integer, so a
  # `nil` from an unset `System.get_env/1` — or the binary from a set one —
  # would not crash: it would silently make a cache entry immortal or wedge the
  # refetch gate shut for the life of the node. Fail loudly at config time
  # instead.
  defp validate_seconds!(config) do
    for key <- [
          :discovery_cache_ttl,
          :jwks_cache_ttl,
          :jwks_max_stale,
          :jwks_refetch_cooldown,
          :leeway_seconds
        ] do
      case config[key] do
        nil ->
          :ok

        seconds when is_integer(seconds) and seconds >= 0 ->
          :ok

        other ->
          raise ArgumentError,
                "SbAuthEx: OIDC #{key} must be a non-negative integer number of seconds — " <>
                  "got #{inspect(other)}"
      end
    end

    :ok
  end

  defp required!(config, key) do
    case config[key] do
      value when is_binary(value) and value != "" ->
        value

      _ ->
        raise ArgumentError,
              "SbAuthEx: missing OIDC #{key}. Set `config :sb_auth_ex, oidc: [#{key}: ...]`."
    end
  end

  defp scope(config) do
    case config[:scopes] do
      nil -> @default_scope
      scope when is_binary(scope) -> scope
      scopes when is_list(scopes) -> Enum.join(scopes, " ")
    end
  end

  defp openid_scope?(config) do
    "openid" in String.split(scope(config), " ", trim: true)
  end

  defp extra_authorize_params(config) do
    for {key, value} <- Keyword.get(config, :authorize_params, []), do: {to_string(key), value}
  end

  defp append_query(url, params) do
    separator = if String.contains?(url, "?"), do: "&", else: "?"
    url <> separator <> URI.encode_query(params)
  end

  defp random_urlsafe do
    Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
  end
end
