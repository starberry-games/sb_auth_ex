defmodule SbAuthEx.WorkOSClient do
  @moduledoc """
  Builds the `WorkOS.Client` used by SbAuthEx.

  The WorkOS SDK (3.x) has no global configuration: every API call takes an
  explicit client. SbAuthEx builds that client from application config, with
  the following precedence (first non-empty value wins):

  1. `config :sb_auth_ex, workos: [api_key: ..., client_id: ...]`
  2. `config :workos, WorkOS.Client, api_key: ..., client_id: ...`
     (the 1.x SDK config shape — still honoured so existing apps keep working)
  3. the `WORKOS_API_KEY` / `WORKOS_CLIENT_ID` environment variables
     (handled by `WorkOS.Client.new/1` itself)

  Additional `WorkOS.Client.new/1` options (`:base_url`, `:timeout`,
  `:max_retries`, `:req_options`) can be set under `config :sb_auth_ex, :workos`
  and are passed through verbatim — `:req_options` is what tests use to inject
  a `Req.Test` plug.
  """

  @client_opts [:api_key, :client_id, :base_url, :timeout, :max_retries, :req_options]

  @doc """
  Returns a `WorkOS.Client` configured for this app.

  Raises `WorkOS.ConfigurationError` when no API key can be found and
  `ArgumentError` when no client ID can be found — both are required for the
  AuthKit flow, so failing loudly at the first request beats a confusing
  redirect loop.
  """
  @spec client() :: WorkOS.Client.t()
  def client do
    opts =
      config()
      |> Keyword.take(@client_opts)
      |> Keyword.put_new_lazy(:api_key, fn -> legacy_config()[:api_key] end)
      |> Keyword.put_new_lazy(:client_id, fn -> legacy_config()[:client_id] end)
      |> Enum.reject(fn {_k, v} -> blank?(v) end)

    client = WorkOS.client(opts)

    if blank?(client.client_id) do
      raise ArgumentError,
            "SbAuthEx: missing WorkOS client ID. Set `config :sb_auth_ex, workos: [client_id: ...]` " <>
              "or the WORKOS_CLIENT_ID environment variable."
    end

    client
  end

  @doc """
  Returns the configured OAuth redirect URI (`config :sb_auth_ex, workos: [redirect_uri: ...]`).

  Raises `ArgumentError` when it is not configured.
  """
  @spec redirect_uri() :: String.t()
  def redirect_uri do
    case config()[:redirect_uri] do
      uri when is_binary(uri) and uri != "" ->
        uri

      _ ->
        raise ArgumentError,
              "SbAuthEx: missing WorkOS redirect URI. Set `config :sb_auth_ex, workos: [redirect_uri: ...]`."
    end
  end

  defp config, do: Application.get_env(:sb_auth_ex, :workos) || []

  defp legacy_config, do: Application.get_env(:workos, WorkOS.Client) || []

  defp blank?(nil), do: true
  defp blank?(""), do: true
  defp blank?(_), do: false
end
