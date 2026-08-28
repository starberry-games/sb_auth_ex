defmodule SbAuthEx.Providers.OIDC.Cache do
  @moduledoc false
  # TTL cache for OIDC discovery metadata and JWKS, backed by :persistent_term.
  # Reads are free and writes are rare (one per TTL window per issuer), which is
  # exactly the persistent_term trade-off — and it needs no supervision tree,
  # which SbAuthEx does not have.

  require Logger

  @root SbAuthEx.Providers.OIDC

  # `max_stale` bounds how long an expired entry may keep serving when
  # refreshing it fails, so a transient issuer outage at a TTL boundary does
  # not fail every login. Callers pick it per kind: discovery documents change
  # on the order of weeks, but a revoked signing key must fall out of the JWKS
  # promptly, so its window is much shorter.
  def fetch(kind, key, ttl, max_stale, fun) do
    now = System.system_time(:second)

    case :persistent_term.get({@root, kind, key}, nil) do
      {fetched_at, value} when now - fetched_at < ttl ->
        {:ok, value}

      {fetched_at, value} when now - fetched_at < max_stale ->
        case refresh(kind, key, fun) do
          {:ok, fresh} ->
            {:ok, fresh}

          {:error, reason} ->
            Logger.warning(
              "SbAuthEx: refreshing OIDC #{kind} failed (#{inspect(reason)}); serving cached value"
            )

            {:ok, value}
        end

      _ ->
        refresh(kind, key, fun)
    end
  end

  def refresh(kind, key, fun) do
    with {:ok, value} <- fun.() do
      put(kind, key, value)
      {:ok, value}
    end
  end

  # A rate-limit gate, kept under its own key so claiming it can never extend
  # a cached entry's freshness window. `claim/3` hands out at most one claim
  # per `cooldown` seconds per key, and writes only when it does — at most one
  # persistent_term write per window, the same write frequency as a normal TTL
  # refresh, rather than one per request.
  #
  # Monotonic time: a wall-clock correction must not hold a gate shut.
  def claim(kind, key, cooldown) do
    now = System.monotonic_time(:second)

    case :persistent_term.get({@root, kind, key}, nil) do
      claimed_at when is_integer(claimed_at) and now - claimed_at < cooldown ->
        false

      _ ->
        # A cooldown of 0 disables the gate. Recording the claim anyway would
        # put a VM-wide GC scan on every request — worse than whatever the
        # gate was pacing.
        if cooldown > 0, do: :persistent_term.put({@root, kind, key}, now)
        true
    end
  end

  def put(kind, key, value) do
    :persistent_term.put({@root, kind, key}, {System.system_time(:second), value})
    :ok
  end

  def reset do
    for {key, _value} <- :persistent_term.get(), match?({@root, _, _}, key) do
      :persistent_term.erase(key)
    end

    :ok
  end
end
