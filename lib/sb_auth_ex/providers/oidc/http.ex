defmodule SbAuthEx.Providers.OIDC.HTTP do
  @moduledoc false
  # Minimal Req wrapper for the OIDC provider's GET requests (discovery, JWKS,
  # userinfo). `:req_options` from the oidc config are passed through verbatim —
  # that is what tests use to inject a `Req.Test` plug.

  # Bounded timeouts and a single retry: these run inside unauthenticated
  # request cycles (/auth/login resolves discovery), so Req's defaults
  # (15s receive timeout, 3 retries with backoff) would let a failing issuer
  # pin request processes for a minute and amplify traffic 4x. Callers'
  # `:req_options` still override (later keys win).
  @default_options [receive_timeout: 5_000, connect_options: [timeout: 3_000], max_retries: 1]

  def default_options, do: @default_options

  def get_json(url, config, opts \\ []) do
    req_opts =
      @default_options ++
        [
          url: url,
          method: :get,
          headers: [{"accept", "application/json"}] ++ Keyword.get(opts, :headers, [])
        ] ++ req_options(config)

    case Req.request(req_opts) do
      {:ok, %Req.Response{status: 200, body: %{} = body}} -> {:ok, body}
      {:ok, %Req.Response{status: 200}} -> {:error, :invalid_json_response}
      {:ok, %Req.Response{status: status}} -> {:error, {:http_status, status}}
      {:error, exception} -> {:error, exception}
    end
  end

  def req_options(config), do: Keyword.get(config, :req_options, [])
end
