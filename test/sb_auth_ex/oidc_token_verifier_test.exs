defmodule SbAuthEx.Providers.OIDC.TokenVerifierTest do
  @moduledoc """
  Direct tests for `TokenVerifier.verify/4` — the entry point consumers also
  call from unauthenticated bearer-token plugs — covering how outbound JWKS
  requests are paced: the gate on the unknown-`kid` refetch, the same gate on
  the cache's stale refresh, and the short negative cache on a cold fetch.

  Elapsed time is simulated by rewinding the gate's own `:persistent_term`
  entry (`age_gate/1`), which is what the production clock does to it — no test
  sleeps, and none of them lower the cooldown to fake expiry, because that
  takes a different branch than a window actually elapsing.
  """
  use ExUnit.Case, async: false

  # The gate logs a debug line when it refuses, and Cache warns when a stale
  # refresh fails; neither is asserted on here.
  @moduletag capture_log: true

  alias SbAuthEx.Providers.OIDC
  alias SbAuthEx.Providers.OIDC.TokenVerifier

  @issuer "https://issuer.example.test"
  @jwks_uri @issuer <> "/oauth2/jwks"
  @audience "https://studio.example.test"
  @kid "test-key-1"
  @rotated_kid "test-key-2"
  @sub "sub_" <> String.duplicate("a", 43)

  # Mirrors the shapes Cache builds, so the tests fail loudly if a key shape
  # drifts out from under `Cache.reset/0`.
  @cache_key {OIDC, :jwks, @jwks_uri}
  @gate_key {OIDC, {:gate, :jwks}, @jwks_uri}
  @cold_gate_key {OIDC, {:gate, {:cold, :jwks}}, @jwks_uri}
  @failure_key {OIDC, {:failure, :jwks}, @jwks_uri}

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

      # The whole point: junk kids past the first are refused from cache, and
      # with an error that says we declined to look rather than that the issuer
      # does not have the key.
      for n <- 2..10 do
        assert {:error, :signing_key_unavailable} = verify(sign(jwk, claims(), kid: "junk-#{n}"))
      end

      assert fetched(fetches) == 2
    end

    test "an unknown kid refetches again once the cooldown has elapsed", %{jwk: jwk} do
      fetches = stub_jwks(fn _n -> jwks_for(jwk, @kid) end)

      assert {:ok, _claims} = verify(sign(jwk, claims()))
      assert {:error, :unknown_signing_key} = verify(sign(jwk, claims(), kid: "junk-1"))
      assert {:error, :signing_key_unavailable} = verify(sign(jwk, claims(), kid: "junk-2"))
      assert fetched(fetches) == 2

      age_gate(60)

      assert {:error, :unknown_signing_key} = verify(sign(jwk, claims(), kid: "junk-3"))
      assert fetched(fetches) == 3

      # The gate must re-arm on that claim. Without this assertion a gate that
      # arms once and never again passes every other test in this file.
      assert {:error, :signing_key_unavailable} = verify(sign(jwk, claims(), kid: "junk-4"))
      assert fetched(fetches) == 3
    end

    test "a genuine rotation still resolves on the refetch", %{jwk: jwk, rotated_jwk: rotated} do
      fetches =
        stub_jwks(fn
          1 -> jwks_for(jwk, @kid)
          _ -> jwks_for(rotated, @rotated_kid)
        end)

      assert {:ok, _claims} = verify(sign(jwk, claims()))
      assert {:ok, %{"sub" => @sub}} = verify(sign(rotated, claims(), kid: @rotated_kid))
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
      assert {:error, :signing_key_unavailable} =
               verify(sign(rotated, claims(), kid: @rotated_kid))

      assert fetched(fetches) == 2

      age_gate(60)

      assert {:ok, %{"sub" => @sub}} = verify(sign(rotated, claims(), kid: @rotated_kid))
      assert fetched(fetches) == 3
    end

    test "claiming the gate never moves the JWKS entry's timestamp", %{jwk: jwk} do
      # The gate lives under its own key precisely so that traffic cannot push
      # `fetched_at` forward: that would hold a revoked key inside max_stale.
      stub_jwks(fn _n -> jwks_for(jwk, @kid) end)

      assert {:ok, _claims} = verify(sign(jwk, claims()))
      assert {fetched_at, _keys} = :persistent_term.get(@cache_key)

      assert {:error, :unknown_signing_key} = verify(sign(jwk, claims(), kid: "junk-1"))

      # The refetch returned an identical key set, so the entry was not
      # rewritten at all — and the gate claim landed somewhere else entirely.
      assert {^fetched_at, _keys} = :persistent_term.get(@cache_key)
      assert is_integer(:persistent_term.get(@gate_key))
    end
  end

  describe "fetch pacing" do
    test "a stale key set refreshes once per cooldown while the issuer is failing",
         %{jwk: jwk} do
      fetches =
        stub_jwks(fn
          1 -> jwks_for(jwk, @kid)
          _ -> {:status, 503}
        end)

      assert {:ok, _claims} = verify(sign(jwk, claims()))
      assert fetched(fetches) == 1

      # ttl: 0 makes every read take the stale branch. Without the gate this is
      # one outbound request per inbound request for the whole max_stale window.
      for _ <- 1..10 do
        assert {:ok, %{"sub" => @sub}} = verify(sign(jwk, claims()), jwks_cache_ttl: 0)
      end

      assert fetched(fetches) == 2
    end

    test "a cold cache with a failing issuer fetches once per cooldown, not once per request" do
      fetches = stub_failing_jwks()
      token = sign(JOSE.JWK.generate_key({:rsa, 2048}), claims())

      errors = for _ <- 1..10, do: verify(token)

      assert fetched(fetches) == 1
      assert Enum.all?(errors, &match?({:error, {:jwks_fetch_failed, {:http_status, 503}}}, &1))
      # All ten got the same answer: nine of them replayed it from the marker.
      assert Enum.uniq(errors) == [{:error, {:jwks_fetch_failed, {:http_status, 503}}}]
    end

    test "the failure marker expires, and one write covers the whole window" do
      fetches = stub_failing_jwks()
      token = sign(JOSE.JWK.generate_key({:rsa, 2048}), claims())

      assert {:error, _reason} = verify(token)
      assert {recorded_at, _reason} = :persistent_term.get(@failure_key)
      assert is_integer(recorded_at)

      assert {:error, _reason} = verify(token)
      # The replay must not rewrite the marker — that would be a VM-wide GC
      # scan per request, the cost this pacing exists to avoid.
      assert {^recorded_at, _reason} = :persistent_term.get(@failure_key)
      assert fetched(fetches) == 1

      # Both windows opened on the same request, so the clock retires them
      # together: the marker stops the replay, the cold gate stops the refetch.
      :persistent_term.put(@failure_key, {System.monotonic_time(:second) - 60, :stale})
      :persistent_term.put(@cold_gate_key, System.monotonic_time(:second) - 60)

      assert {:error, _reason} = verify(token)
      assert fetched(fetches) == 2
    end

    test "the stale refresh and the unknown-kid refetch share one budget", %{jwk: jwk} do
      fetches = stub_jwks(fn _n -> jwks_for(jwk, @kid) end)

      assert {:ok, _claims} = verify(sign(jwk, claims()))
      assert fetched(fetches) == 1

      # A stale refresh claims the gate...
      assert {:ok, _claims} = verify(sign(jwk, claims()), jwks_cache_ttl: 0)
      assert fetched(fetches) == 2

      # ...so an unknown kid is refused rather than buying a second fetch.
      # Separate budgets would double the outbound allowance for one jwks_uri.
      assert {:error, :signing_key_unavailable} = verify(sign(jwk, claims(), kid: "junk-1"))
      assert fetched(fetches) == 2
    end
  end

  describe "config hygiene" do
    test "a non-integer cooldown falls back to the default instead of wedging the gate",
         %{jwk: jwk} do
      # `jwks_refetch_cooldown: System.get_env("...")` yields nil unset. Erlang
      # term ordering would make `now - claimed_at < nil` true forever, closing
      # the gate for the life of the node.
      fetches = stub_jwks(fn _n -> jwks_for(jwk, @kid) end)

      assert {:ok, _claims} = verify(sign(jwk, claims()), jwks_refetch_cooldown: nil)

      assert {:error, :unknown_signing_key} =
               verify(sign(jwk, claims(), kid: "junk-1"), jwks_refetch_cooldown: nil)

      assert {:error, :signing_key_unavailable} =
               verify(sign(jwk, claims(), kid: "junk-2"), jwks_refetch_cooldown: nil)

      assert fetched(fetches) == 2

      age_gate(60)

      assert {:error, :unknown_signing_key} =
               verify(sign(jwk, claims(), kid: "junk-3"), jwks_refetch_cooldown: nil)

      assert fetched(fetches) == 3
    end

    test "a cooldown of 0 disables pacing without writing persistent_term per request" do
      fetches = stub_failing_jwks()
      token = sign(JOSE.JWK.generate_key({:rsa, 2048}), claims())

      for _ <- 1..3 do
        assert {:error, {:jwks_fetch_failed, _reason}} = verify(token, jwks_refetch_cooldown: 0)
      end

      # The documented escape hatch: every request goes out again...
      assert fetched(fetches) == 3

      # ...but nothing is recorded per request. A persistent_term write per
      # request is a VM-wide GC scan — worse than the fetch it would be pacing.
      assert :persistent_term.get(@gate_key, :absent) == :absent
      assert :persistent_term.get(@failure_key, :absent) == :absent
    end

    test "a nil leeway falls back to the default instead of raising", %{jwk: jwk} do
      # `Keyword.get/3` hands back the nil, not the default, and `trunc(exp) +
      # nil` would 500 a bearer plug that should have returned a clean 401.
      stub_jwks(fn _n -> jwks_for(jwk, @kid) end)

      assert {:ok, %{"sub" => @sub}} = verify(sign(jwk, claims()), leeway_seconds: nil)
    end

    test "reset_cache clears the gate and the failure marker too", %{jwk: jwk} do
      # Both use monotonic time, which does not reset between tests: a key
      # shape that drifted out of Cache.reset/0's match would silently poison
      # every following test for a full cooldown window.
      stub_jwks(fn _n -> jwks_for(jwk, @kid) end)

      assert {:ok, _claims} = verify(sign(jwk, claims()))
      assert {:error, :unknown_signing_key} = verify(sign(jwk, claims(), kid: "junk-1"))
      assert is_integer(:persistent_term.get(@gate_key))

      stub_failing_jwks()
      OIDC.reset_cache()
      assert {:error, _reason} = verify(sign(jwk, claims()))
      assert {_recorded_at, _reason} = :persistent_term.get(@failure_key)

      OIDC.reset_cache()

      assert :persistent_term.get(@cache_key, :absent) == :absent
      assert :persistent_term.get(@gate_key, :absent) == :absent
      assert :persistent_term.get(@cold_gate_key, :absent) == :absent
      assert :persistent_term.get(@failure_key, :absent) == :absent
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
        # `retry: false` so one logical fetch is one counted request; the
        # library's own `max_retries: 1` would otherwise double every failure.
        req_options: [plug: {Req.Test, SbAuthEx.OIDCStub}, retry: false]
      ],
      overrides
    )
  end

  # Rewinds the gate as the clock would, so an elapsed window is exercised on
  # the same branch production takes.
  defp age_gate(seconds) do
    :persistent_term.put(@gate_key, System.monotonic_time(:second) - seconds)
  end

  # Serves what `keys_fun.(fetch_number)` returns — a key set, or `{:status, s}`
  # for an issuer that is failing — and counts every fetch.
  defp stub_jwks(keys_fun) do
    fetches = :counters.new(1, [])

    Req.Test.stub(SbAuthEx.OIDCStub, fn conn ->
      case {conn.method, conn.request_path} do
        {"GET", "/oauth2/jwks"} ->
          :counters.add(fetches, 1, 1)

          case keys_fun.(:counters.get(fetches, 1)) do
            {:status, status} ->
              Req.Test.json(Plug.Conn.put_status(conn, status), %{"error" => "unavailable"})

            keys ->
              Req.Test.json(conn, keys)
          end

        _other ->
          Req.Test.json(Plug.Conn.put_status(conn, 500), %{"error" => "unexpected"})
      end
    end)

    fetches
  end

  defp stub_failing_jwks, do: stub_jwks(fn _n -> {:status, 503} end)

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
