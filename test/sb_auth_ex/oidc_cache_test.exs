defmodule SbAuthEx.Providers.OIDC.CacheTest do
  @moduledoc """
  Tests for the cold-fetch path of the OIDC cache — the one that runs when
  there is no servable entry at all, so the fetch cannot be refused outright.

  These drive `Cache.fetch/4` directly with a plain function rather than
  through `Req`, because what matters here is *when* a fetch is still running,
  and a stubbed HTTP call that returns instantly cannot express that.
  """
  use ExUnit.Case, async: false

  alias SbAuthEx.Providers.OIDC.Cache

  @key "https://issuer.example.test/oauth2/jwks"

  setup do
    Cache.reset()
    on_exit(&Cache.reset/0)
    :ok
  end

  describe "cold fetch" do
    test "requests arriving while a fetch is in flight do not each start one" do
      # The regression this guards. The failure marker can only be written once
      # the fetch returns — ~11s against a hanging issuer — so pacing on the
      # marker alone leaves that whole window open and outbound concurrency
      # becomes inbound request rate times 11s.
      {fetches, fun} = counted(fn -> Process.sleep(300) && {:error, :issuer_hanging} end)

      results =
        for _ <- 1..20 do
          Process.sleep(10)
          Task.async(fn -> Cache.fetch(:jwks, @key, opts(), fun) end)
        end
        |> Task.await_many(5_000)

      assert count(fetches) == 1
      assert Enum.uniq(results) == [{:error, :issuer_hanging}]
    end

    test "callers arriving during a fetch wait for it rather than failing" do
      {fetches, fun} = counted(fn -> Process.sleep(150) && {:ok, :the_keys} end)

      # Arrivals are staggered past the claim's write. A burst landing inside
      # the gate's non-atomic check-and-write still races it and all fetch —
      # that residual is bounded by instantaneous concurrency, and closing it
      # needs a process to serialize on.
      results =
        for _ <- 1..10 do
          Process.sleep(10)
          Task.async(fn -> Cache.fetch(:jwks, @key, opts(), fun) end)
        end
        |> Task.await_many(5_000)

      # Waiting rather than refusing: this path also serves bearer-token plugs,
      # where refusing would 401 valid tokens for a whole fetch after a restart.
      assert Enum.uniq(results) == [{:ok, :the_keys}]
      assert count(fetches) == 1
    end

    test "a caller gives up with a clean error when the winner never returns" do
      {fetches, fun} = counted(fn -> Process.sleep(400) && {:ok, :too_late} end)

      first = Task.async(fn -> Cache.fetch(:jwks, @key, opts(), fun) end)
      Process.sleep(20)

      assert Cache.fetch(:jwks, @key, opts(wait_ms: 100), fun) ==
               {:error, {:fetch_unavailable, :jwks}}

      assert Task.await(first, 5_000) == {:ok, :too_late}
      assert count(fetches) == 1
    end

    test "a waiting caller is never served the hard-stale entry it displaced" do
      # A revoked signing key must fall out at max_stale, so a caller waiting on
      # the winner must not settle for the entry that just aged out.
      Cache.put(:jwks, @key, :ancient)
      {_at, :ancient} = :persistent_term.get({SbAuthEx.Providers.OIDC, :jwks, @key})
      :persistent_term.put({SbAuthEx.Providers.OIDC, :jwks, @key}, {0, :ancient})

      {fetches, fun} = counted(fn -> Process.sleep(300) && {:ok, :fresh_keys} end)

      first = Task.async(fn -> Cache.fetch(:jwks, @key, opts(), fun) end)
      Process.sleep(20)

      assert Cache.fetch(:jwks, @key, opts(), fun) == {:ok, :fresh_keys}
      assert Task.await(first, 5_000) == {:ok, :fresh_keys}
      assert count(fetches) == 1
    end

    test "a failure is replayed for the rest of the window, then retried" do
      {fetches, fun} = counted(fn -> {:error, :boom} end)

      for _ <- 1..5, do: assert(Cache.fetch(:jwks, @key, opts(), fun) == {:error, :boom})
      assert count(fetches) == 1

      age_pacing(60)

      assert Cache.fetch(:jwks, @key, opts(), fun) == {:error, :boom}
      assert count(fetches) == 2
    end
  end

  # ---------------------------------------------------------------------------

  defp opts(overrides \\ []) do
    Keyword.merge([ttl: 300, max_stale: 1800, cooldown: 10], overrides)
  end

  defp counted(fun) do
    fetches = :counters.new(1, [])

    {fetches,
     fn ->
       :counters.add(fetches, 1, 1)
       fun.()
     end}
  end

  defp count(counter), do: :counters.get(counter, 1)

  # Rewinds every pacing window as the clock would; in production they all
  # opened on the same request.
  defp age_pacing(seconds) do
    now = System.monotonic_time(:second)
    root = SbAuthEx.Providers.OIDC

    :persistent_term.put({root, {:gate, :jwks}, @key}, now - seconds)
    :persistent_term.put({root, {:gate, {:cold, :jwks}}, @key}, now - seconds)

    case :persistent_term.get({root, {:failure, :jwks}, @key}, nil) do
      {_at, reason} ->
        :persistent_term.put({root, {:failure, :jwks}, @key}, {now - seconds, reason})

      nil ->
        :ok
    end
  end
end
