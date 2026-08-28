defmodule SbAuthEx.Providers.OIDC.Cache do
  @moduledoc false
  # TTL cache for OIDC discovery metadata and JWKS, backed by :persistent_term.
  # Reads are free and writes are rare (one per TTL window per issuer), which is
  # exactly the persistent_term trade-off — and it needs no supervision tree,
  # which SbAuthEx does not have.
  #
  # Both callers sit on unauthenticated request paths (`/auth/login` resolves
  # discovery; token verification runs in bearer-token plugs), so every
  # outbound fetch this module can cause is paced:
  #
  #   - an entry inside its TTL answers with no HTTP at all
  #   - a stale entry refreshes at most once per cooldown window. Denied
  #     callers serve the stale value, so pacing costs nothing here — this is
  #     what stops a failing issuer from turning inbound request rate into
  #     outbound request rate for the whole `max_stale` window
  #   - a cold (or hard-stale) entry has nothing to serve, so its fetch is
  #     *not* paced on the way in: denying it would fail requests at cold start
  #     against a perfectly healthy issuer. It is paced on the way out instead
  #     — a failure is remembered for one cooldown window and replayed with no
  #     HTTP call
  #
  # One hole is left open deliberately. Between a cold fetch starting and the
  # first failure landing (up to ~15s against a black-holed issuer, given
  # HTTP's timeouts and single retry) concurrent callers all fetch, because
  # there is no marker yet. Closing that needs a process to serialize on, and
  # SbAuthEx deliberately has no supervision tree. So the pacing guarantee is
  # honest only once an entry (or a failure) has landed: warm, at most ~one
  # outbound request per cooldown window per key; cold, bounded by instantaneous
  # concurrency rather than by request rate.

  require Logger

  @root SbAuthEx.Providers.OIDC

  # `opts` are `:ttl`, `:max_stale` and `:cooldown`, all in seconds.
  #
  # `max_stale` bounds how long an expired entry may keep serving when
  # refreshing it fails, so a transient issuer outage at a TTL boundary does
  # not fail every login. Callers pick it per kind: discovery documents change
  # on the order of weeks, but a revoked signing key must fall out of the JWKS
  # promptly, so its window is much shorter.
  def fetch(kind, key, opts, fun) do
    ttl = Keyword.fetch!(opts, :ttl)
    max_stale = Keyword.fetch!(opts, :max_stale)
    cooldown = Keyword.fetch!(opts, :cooldown)
    now = System.system_time(:second)

    case :persistent_term.get({@root, kind, key}, nil) do
      {fetched_at, value} when now - fetched_at < ttl ->
        {:ok, value}

      {fetched_at, value} when now - fetched_at < max_stale ->
        refresh_stale(kind, key, value, cooldown, fun)

      _ ->
        cold_fetch(kind, key, cooldown, fun)
    end
  end

  def refresh(kind, key, fun) do
    with {:ok, value} <- fun.() do
      put(kind, key, value)
      {:ok, value}
    end
  end

  # A rate-limit gate, kept under its own key so claiming it can never extend
  # a cached entry's freshness window — letting traffic push `fetched_at`
  # forward would keep a revoked signing key inside `max_stale`.
  #
  # `claim/3` hands out at most one claim per `cooldown` seconds per key, and
  # writes only when it does: at most one persistent_term write per window, the
  # same write frequency as a normal TTL refresh, rather than one per request.
  #
  # The check and the write are not atomic, so callers that read an open gate
  # in the gap between them all win. That race is bounded by instantaneous
  # concurrency, not by request rate; closing it needs a process to serialize
  # on, which this library does not have.
  #
  # Monotonic time: a wall-clock correction must not hold a gate shut.
  def claim(kind, key, cooldown) do
    now = System.monotonic_time(:second)
    gate = {@root, {:gate, kind}, key}

    case :persistent_term.get(gate, nil) do
      claimed_at when is_integer(claimed_at) and now - claimed_at < cooldown ->
        false

      _ ->
        # A cooldown of 0 disables the gate. Recording the claim anyway would
        # put a VM-wide GC scan on every request — worse than whatever the
        # gate was pacing.
        if cooldown > 0, do: :persistent_term.put(gate, now)
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

  # Seconds arrive from host application config, where a value can easily show
  # up as `nil` or a binary (an unset or unparsed `System.get_env/1`). Erlang
  # term ordering sorts every atom and binary *above* every integer, so such a
  # value would silently make an entry immortal or wedge a gate shut forever —
  # no crash, no log. `SbAuthEx.Providers.OIDC.config!/0` raises on these at
  # login time; this is the backstop for configs built by hand.
  def seconds(value, _default) when is_integer(value) and value >= 0, do: value
  def seconds(_value, default), do: default

  # ---------------------------------------------------------------------------

  defp refresh_stale(kind, key, value, cooldown, fun) do
    if claim(kind, key, cooldown) do
      case refresh(kind, key, fun) do
        {:ok, fresh} ->
          {:ok, fresh}

        {:error, reason} ->
          Logger.warning(
            "SbAuthEx: refreshing OIDC #{kind} failed (#{inspect(reason)}); serving cached value"
          )

          {:ok, value}
      end
    else
      # Still inside `max_stale`, so this is the same answer the refresh would
      # have produced in all but the rotation case — at no HTTP cost.
      {:ok, value}
    end
  end

  defp cold_fetch(kind, key, cooldown, fun) do
    case recent_failure(kind, key, cooldown) do
      {:error, _reason} = replay ->
        replay

      nil ->
        case refresh(kind, key, fun) do
          {:ok, value} ->
            {:ok, value}

          {:error, reason} = error ->
            record_failure(kind, key, reason, cooldown)
            error
        end
    end
  end

  defp recent_failure(kind, key, cooldown) do
    now = System.monotonic_time(:second)

    case :persistent_term.get({@root, {:failure, kind}, key}, nil) do
      {recorded_at, reason} when is_integer(recorded_at) and now - recorded_at < cooldown ->
        {:error, reason}

      _ ->
        nil
    end
  end

  # A successful fetch never clears the marker, and does not need to: while a
  # marker is live no path can produce a success for this key at all. The cold
  # branch replays without fetching; the stale branch needs an entry inside
  # `max_stale`, which cannot exist (markers are only written when the entry is
  # absent or hard-stale, and `fetched_at` never moves backwards). So the
  # marker is unreachable by the time it could be wrong, and it self-expires.
  defp record_failure(kind, key, reason, cooldown) do
    # Read before writing. A burst of concurrent cold fetches fails at roughly
    # the same moment and one marker is enough for all of them; writing per
    # failure would schedule a VM-wide GC scan per request, which is the cost
    # this whole module exists to avoid.
    if cooldown > 0 and is_nil(recent_failure(kind, key, cooldown)) do
      :persistent_term.put(
        {@root, {:failure, kind}, key},
        {System.monotonic_time(:second), reason}
      )
    end

    :ok
  end
end
