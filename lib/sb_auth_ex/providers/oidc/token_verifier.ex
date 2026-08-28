defmodule SbAuthEx.Providers.OIDC.TokenVerifier do
  @moduledoc false
  # Verifies a JWT against the provider's JWKS:
  #
  #   - the header `alg` must be on the explicit asymmetric allowlist — this is
  #     checked before any key material is touched, so `none` and HMAC
  #     downgrades die first
  #   - the signature must verify (`JOSE.JWT.verify_strict/3`, pinned to the
  #     single header alg)
  #   - `iss` must equal the configured issuer exactly
  #   - `aud` must contain the expected audience exactly
  #   - `exp` is required and enforced; `nbf` is enforced when present
  #
  # JWKS is cached with a TTL; an unknown `kid` triggers a refetch to pick up
  # key rotation, gated to at most one refetch per `:jwks_refetch_cooldown`
  # seconds (default 10) per jwks_uri. That gate is shared with the cache's own
  # stale refresh (see Cache), so a warm jwks_uri causes at most ~one outbound
  # JWKS request per window whatever the cause.
  #
  # The gate is not an optimisation. `verify/4` is called directly from
  # unauthenticated bearer-token plugs, not only from the login callback, so
  # without it anyone can drive one outbound JWKS fetch per junk JWT (two, with
  # HTTP's `max_retries: 1`) just by making up a `kid`. The damage is not
  # bandwidth: Req shares a single Finch instance, its pools are per host and
  # default to 50 connections, and discovery, token exchange and JWKS are all
  # the same host — so a few junk requests a second saturate that pool and the
  # *login* token exchange starts timing out on checkout. Inside the cooldown
  # an unknown kid returns {:error, :signing_key_unavailable} with no HTTP call
  # at all — distinct from {:error, :unknown_signing_key}, which means a real
  # refetch happened and the issuer does not have that key.
  #
  # The cost of the gate is bounded and deliberate: during a genuine key
  # rotation, a token signed by a kid we have never seen is refused until the
  # gate opens or the TTL refresh lands.

  require Logger

  alias SbAuthEx.Providers.OIDC.Cache
  alias SbAuthEx.Providers.OIDC.HTTP

  @default_algs ["RS256", "ES256"]
  @default_leeway 60
  @default_jwks_ttl 300
  # A revoked signing key must stop verifying promptly, so stale JWKS serves
  # for far less time than stale discovery metadata.
  @default_jwks_max_stale 1800
  # Short on purpose: this is the window a genuinely rotated key can be
  # refused for, traded against how cheap unknown-kid traffic is to serve.
  @default_refetch_cooldown 10

  def verify(token, config, jwks_uri, expected_aud) when is_binary(token) do
    with {:ok, header} <- peek_header(token),
         {:ok, alg} <- check_alg(header, config),
         {:ok, key} <- signing_key(header, config, jwks_uri),
         {:ok, claims} <- verify_signature(key, alg, token),
         :ok <- check_issuer(claims, config),
         :ok <- check_audience(claims, expected_aud),
         :ok <- check_time(claims, config) do
      {:ok, claims}
    end
  end

  def verify(_token, _config, _jwks_uri, _expected_aud), do: {:error, :malformed_token}

  # ---------------------------------------------------------------------------

  defp peek_header(token) do
    with [header, _payload, _signature] <- String.split(token, "."),
         {:ok, json} <- Base.url_decode64(header, padding: false),
         {:ok, %{} = decoded} <- Jason.decode(json) do
      {:ok, decoded}
    else
      _ -> {:error, :malformed_token}
    end
  end

  defp check_alg(header, config) do
    allowed = Keyword.get(config, :allowed_algs, @default_algs)

    case header["alg"] do
      alg when is_binary(alg) ->
        if alg in allowed, do: {:ok, alg}, else: {:error, {:disallowed_alg, alg}}

      _ ->
        {:error, :malformed_token}
    end
  end

  defp signing_key(header, config, jwks_uri) do
    with {:ok, keys} <- cached_jwks(config, jwks_uri) do
      case find_key(keys, header) do
        {:ok, key} -> {:ok, key}
        # Unknown kid — the environment may have rotated its keys, or this is
        # an attacker naming a key that never existed. Both look identical
        # here, so the refetch is rate limited rather than trusted.
        :error -> refetch_for_unknown_kid(header, config, jwks_uri, keys)
      end
    end
  end

  defp refetch_for_unknown_kid(header, config, jwks_uri, keys) do
    cooldown = refetch_cooldown(config)

    # The gate is claimed *before* the fetch and only when it was open, so it
    # costs one write per cooldown window and the race window is the gap
    # between the read and the write rather than the whole fetch. Requests
    # that read the open gate inside that gap all fetch; closing that off
    # completely needs a process to serialize on, and SbAuthEx deliberately
    # ships without a supervision tree (see the Cache moduledoc). The residual
    # race is bounded by concurrency, not by attacker request rate, so it is
    # left as is.
    if Cache.claim(:jwks, jwks_uri, cooldown) do
      # A failed fetch deliberately burns the rest of the window: releasing the
      # gate on failure would hand an attacker an unbounded fetch budget for
      # exactly as long as the issuer is unhealthy.
      with {:ok, fresh} <- fetch_jwks(config, jwks_uri) do
        # Cache only when the key set actually changed: a refetch that
        # still lacks the kid (misconfigured issuer) would otherwise
        # rewrite :persistent_term — a VM-wide GC scan — on every login.
        if fresh != keys, do: Cache.put(:jwks, jwks_uri, fresh)

        case find_key(fresh, header) do
          {:ok, key} -> {:ok, key}
          :error -> {:error, :unknown_signing_key}
        end
      end
    else
      Logger.debug(
        "SbAuthEx: not refetching JWKS for unknown kid #{inspect(header["kid"])} — " <>
          "within the #{cooldown}s refetch cooldown"
      )

      {:error, :signing_key_unavailable}
    end
  end

  defp cached_jwks(config, jwks_uri) do
    opts = [
      ttl: Cache.seconds(config[:jwks_cache_ttl], @default_jwks_ttl),
      max_stale: Cache.seconds(config[:jwks_max_stale], @default_jwks_max_stale),
      cooldown: refetch_cooldown(config)
    ]

    Cache.fetch(:jwks, jwks_uri, opts, fn -> fetch_jwks(config, jwks_uri) end)
  end

  defp refetch_cooldown(config),
    do: Cache.seconds(config[:jwks_refetch_cooldown], @default_refetch_cooldown)

  defp fetch_jwks(config, jwks_uri) do
    case HTTP.get_json(jwks_uri, config) do
      {:ok, %{"keys" => keys}} when is_list(keys) -> {:ok, keys}
      {:ok, _body} -> {:error, :invalid_jwks}
      {:error, reason} -> {:error, {:jwks_fetch_failed, reason}}
    end
  end

  defp find_key(keys, %{"kid" => kid}) when is_binary(kid) do
    case Enum.find(keys, &(&1["kid"] == kid)) do
      nil -> :error
      key -> {:ok, key}
    end
  end

  # No kid in the header: unambiguous only when the JWKS has a single key.
  defp find_key([key], _header), do: {:ok, key}
  defp find_key(_keys, _header), do: :error

  defp verify_signature(key_map, alg, token) do
    jwk = JOSE.JWK.from_map(key_map)

    case JOSE.JWT.verify_strict(jwk, [alg], token) do
      {true, %JOSE.JWT{fields: claims}, _jws} -> {:ok, claims}
      {false, _jwt, _jws} -> {:error, :invalid_signature}
    end
  rescue
    # Malformed key material or token internals — same trust decision.
    _ -> {:error, :invalid_signature}
  end

  defp check_issuer(claims, config) do
    if claims["iss"] == Keyword.fetch!(config, :issuer) do
      :ok
    else
      {:error, :invalid_issuer}
    end
  end

  defp check_audience(claims, expected) do
    case claims["aud"] do
      aud when is_binary(aud) ->
        if aud == expected, do: :ok, else: {:error, :invalid_audience}

      auds when is_list(auds) ->
        if expected in auds, do: :ok, else: {:error, :invalid_audience}

      _ ->
        {:error, :invalid_audience}
    end
  end

  defp check_time(claims, config) do
    leeway = Keyword.get(config, :leeway_seconds, @default_leeway)
    now = System.system_time(:second)
    exp = claims["exp"]
    nbf = claims["nbf"]

    # RFC 7519 NumericDate is any JSON number — fractional seconds included.
    cond do
      not is_number(exp) -> {:error, :missing_expiry}
      now >= trunc(exp) + leeway -> {:error, :token_expired}
      is_number(nbf) and now < trunc(nbf) - leeway -> {:error, :token_not_yet_valid}
      true -> :ok
    end
  end
end
