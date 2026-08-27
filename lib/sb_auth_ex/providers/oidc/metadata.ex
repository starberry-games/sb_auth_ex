defmodule SbAuthEx.Providers.OIDC.Metadata do
  @moduledoc false
  # Resolves the provider endpoints, either from explicit config overrides
  # (`:authorization_endpoint`, `:token_endpoint`, `:jwks_uri`,
  # `:userinfo_endpoint`) or from cached OIDC discovery
  # (`{issuer}/.well-known/openid-configuration`).
  #
  # Per the OIDC Discovery spec, the `issuer` in the discovery document must be
  # byte-identical to the issuer the document was fetched for; a mismatch is a
  # misconfiguration or an attack, and fails the login.

  alias SbAuthEx.Providers.OIDC.Cache
  alias SbAuthEx.Providers.OIDC.HTTP

  @endpoint_keys [:authorization_endpoint, :token_endpoint, :jwks_uri, :userinfo_endpoint]
  @required_keys [:authorization_endpoint, :token_endpoint, :jwks_uri]

  @default_discovery_ttl 3600
  @discovery_max_stale 86_400

  @doc """
  Returns `{:ok, %{authorization_endpoint:, token_endpoint:, jwks_uri:, userinfo_endpoint:}}`.

  Discovery is skipped entirely when all three required endpoints are
  configured explicitly; `userinfo_endpoint` is optional and may be `nil`.
  """
  def endpoints(config) do
    overrides =
      for key <- @endpoint_keys, url = config[key], is_binary(url) and url != "", into: %{} do
        {key, url}
      end

    if Enum.all?(@required_keys, &Map.has_key?(overrides, &1)) do
      {:ok, Map.put_new(overrides, :userinfo_endpoint, nil)}
    else
      with {:ok, doc} <- discover(config) do
        %{
          authorization_endpoint: doc["authorization_endpoint"],
          token_endpoint: doc["token_endpoint"],
          jwks_uri: doc["jwks_uri"],
          userinfo_endpoint: doc["userinfo_endpoint"]
        }
        |> Map.merge(overrides)
        |> validate_required()
      end
    end
  end

  defp validate_required(endpoints) do
    case Enum.find(@required_keys, fn key ->
           not (is_binary(endpoints[key]) and endpoints[key] != "")
         end) do
      nil -> {:ok, endpoints}
      key -> {:error, {:discovery_missing_endpoint, key}}
    end
  end

  defp discover(config) do
    issuer = Keyword.fetch!(config, :issuer)
    ttl = Keyword.get(config, :discovery_cache_ttl, @default_discovery_ttl)

    Cache.fetch(:discovery, issuer, ttl, @discovery_max_stale, fn ->
      url = String.trim_trailing(issuer, "/") <> "/.well-known/openid-configuration"

      case HTTP.get_json(url, config) do
        {:ok, %{"issuer" => ^issuer} = doc} -> {:ok, doc}
        {:ok, %{"issuer" => other}} -> {:error, {:discovery_issuer_mismatch, other}}
        {:ok, _doc} -> {:error, :discovery_document_invalid}
        {:error, reason} -> {:error, {:discovery_failed, reason}}
      end
    end)
  end
end
