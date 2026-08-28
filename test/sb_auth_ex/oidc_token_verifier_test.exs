defmodule SbAuthEx.Providers.OIDC.TokenVerifierTest do
  @moduledoc """
  Direct tests for `TokenVerifier.verify/4` — the entry point consumers also
  call from unauthenticated bearer-token plugs — covering the rate-limit gate
  on the unknown-`kid` JWKS refetch.

  The gate stores *when* it was last claimed and reads the cooldown from config
  on each check, so shrinking `:jwks_unknown_kid_cooldown` between calls is
  exactly equivalent to waiting the window out, and no test sleeps.
  """
  use ExUnit.Case, async: false

  alias SbAuthEx.Providers.OIDC
  alias SbAuthEx.Providers.OIDC.TokenVerifier

  @issuer "https://issuer.example.test"
  @jwks_uri @issuer <> "/oauth2/jwks"
  @audience "https://studio.example.test"
  @kid "test-key-1"
  @rotated_kid "test-key-2"
  @sub "sub_" <> String.duplicate("a", 43)

  setup_all do
    %{jwk: JOSE.JWK.generate_key({:rsa, 2048}), rotated_jwk: JOSE.JWK.generate_key({:rsa, 2048})}
  end

  setup do
    OIDC.reset_cache()
    on_exit(&OIDC.reset_cache/0)
    :ok
  end

  describe "unknown-kid refetch gate" do
    test "an unknown kid refetches the JWKS exactly once", %{jwk: jwk} do
      fetches = stub_jwks(fn _n -> jwks_for(jwk, @kid) end)

      # Priming fetch: the cache is cold and the known kid verifies.
      assert {:ok, %{"sub" => @sub}} = verify(sign(jwk, claims()))
      assert fetched(fetches) == 1

      assert {:error, :unknown_signing_key} = verify(sign(jwk, claims(), kid: "junk-1"))
      assert fetched(fetches) == 2
    end

    test "a second unknown kid inside the cooldown makes no HTTP call at all", %{jwk: jwk} do
      fetches = stub_jwks(fn _n -> jwks_for(jwk, @kid) end)

      assert {:ok, _claims} = verify(sign(jwk, claims()))
      assert {:error, :unknown_signing_key} = verify(sign(jwk, claims(), kid: "junk-1"))
      assert fetched(fetches) == 2

      # The whole point: junk kids past the first are served from the cache.
      for n <- 2..10 do
        assert {:error, :unknown_signing_key} = verify(sign(jwk, claims(), kid: "junk-#{n}"))
      end

      assert fetched(fetches) == 2
    end

    test "an unknown kid refetches again once the cooldown has elapsed", %{jwk: jwk} do
      fetches = stub_jwks(fn _n -> jwks_for(jwk, @kid) end)

      assert {:ok, _claims} = verify(sign(jwk, claims()))
      assert {:error, :unknown_signing_key} = verify(sign(jwk, claims(), kid: "junk-1"))
      assert {:error, :unknown_signing_key} = verify(sign(jwk, claims(), kid: "junk-2"))
      assert fetched(fetches) == 2

      assert {:error, :unknown_signing_key} =
               verify(sign(jwk, claims(), kid: "junk-3"), jwks_unknown_kid_cooldown: 0)

      assert fetched(fetches) == 3
    end

    test "a genuine rotation still resolves on the refetch", %{jwk: jwk, rotated_jwk: rotated} do
      fetches =
        stub_jwks(fn
          1 -> jwks_for(jwk, @kid)
          _ -> jwks_for(rotated, @rotated_kid)
        end)

      assert {:ok, _claims} = verify(sign(jwk, claims()))

      assert {:ok, %{"sub" => @sub}} =
               verify(sign(rotated, claims(), kid: @rotated_kid))

      assert fetched(fetches) == 2

      # The rotated key set replaced the cached one, so the next token signed
      # by it verifies without another fetch.
      assert {:ok, _claims} = verify(sign(rotated, claims(), kid: @rotated_kid))
      assert fetched(fetches) == 2
    end

    test "a rotation that lands inside the cooldown is refused until the gate opens",
         %{jwk: jwk, rotated_jwk: rotated} do
      # The issuer only rotates after the junk request has burned the window,
      # so the refetch it triggered could not have picked the new key up.
      fetches =
        stub_jwks(fn
          n when n <= 2 -> jwks_for(jwk, @kid)
          _ -> jwks_for(rotated, @rotated_kid)
        end)

      assert {:ok, _claims} = verify(sign(jwk, claims()))
      # Junk traffic burns the window...
      assert {:error, :unknown_signing_key} = verify(sign(jwk, claims(), kid: "junk-1"))
      # ...so a real rotation waits it out. This is the accepted cost of the gate.
      assert {:error, :unknown_signing_key} = verify(sign(rotated, claims(), kid: @rotated_kid))
      assert fetched(fetches) == 2

      assert {:ok, %{"sub" => @sub}} =
               verify(sign(rotated, claims(), kid: @rotated_kid),
                 jwks_unknown_kid_cooldown: 0
               )

      assert fetched(fetches) == 3
    end

    test "the gate never extends the JWKS staleness window", %{jwk: jwk} do
      # Claiming the gate must not touch the cache entry's fetched_at: an
      # attacker could otherwise keep a revoked key alive past jwks_max_stale.
      fetches = stub_jwks(fn _n -> jwks_for(jwk, @kid) end)

      assert {:ok, _claims} = verify(sign(jwk, claims()))
      assert {:error, :unknown_signing_key} = verify(sign(jwk, claims(), kid: "junk-1"))
      assert fetched(fetches) == 2

      {cached_at, _keys} = :persistent_term.get({OIDC, :jwks, @jwks_uri})
      assert cached_at <= System.system_time(:second)

      # A zero TTL makes every read a refresh: the cache entry is still dated
      # from its own fetch, not from the gate claim.
      assert {:ok, _claims} = verify(sign(jwk, claims()), jwks_cache_ttl: 0)
      assert fetched(fetches) == 3
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp verify(token, config_overrides \\ []) do
    TokenVerifier.verify(token, config(config_overrides), @jwks_uri, @audience)
  end

  defp config(overrides) do
    Keyword.merge(
      [
        issuer: @issuer,
        client_id: "client_oidc_123",
        redirect_uri: "http://localhost/auth/callback",
        audience: @audience,
        req_options: [plug: {Req.Test, SbAuthEx.OIDCStub}]
      ],
      overrides
    )
  end

  # Serves the JWKS built by `keys_fun.(fetch_number)` and counts every fetch.
  defp stub_jwks(keys_fun) do
    fetches = :counters.new(1, [])

    Req.Test.stub(SbAuthEx.OIDCStub, fn conn ->
      case {conn.method, conn.request_path} do
        {"GET", "/oauth2/jwks"} ->
          :counters.add(fetches, 1, 1)
          Req.Test.json(conn, keys_fun.(:counters.get(fetches, 1)))

        _other ->
          Req.Test.json(Plug.Conn.put_status(conn, 500), %{"error" => "unexpected"})
      end
    end)

    fetches
  end

  defp fetched(counter), do: :counters.get(counter, 1)

  defp jwks_for(jwk, kid) do
    {_meta, public_map} = JOSE.JWK.to_public_map(jwk)
    %{"keys" => [Map.put(public_map, "kid", kid)]}
  end

  defp claims(overrides \\ %{}) do
    Map.merge(
      %{
        "iss" => @issuer,
        "sub" => @sub,
        "aud" => @audience,
        "exp" => System.system_time(:second) + 300
      },
      overrides
    )
  end

  defp sign(jwk, claims, opts \\ []) do
    jws = %{"alg" => "RS256", "kid" => Keyword.get(opts, :kid, @kid)}
    {_meta, token} = jwk |> JOSE.JWT.sign(jws, claims) |> JOSE.JWS.compact()
    token
  end
end
