defmodule SbAuthEx.Provider do
  @moduledoc """
  Behaviour implemented by SbAuthEx authentication providers.

  A provider owns the protocol-specific half of the login flow — building the
  authorization URL, exchanging the callback code for a verified identity, and
  the provider side of logout and account deletion. Everything else (routes,
  plugs, hooks, the state/PKCE cookie, the login-CSRF check, `return_to`,
  session handling, the `sb_identities` data layer) is shared and identical
  across providers.

  ## Selection

  The active provider is chosen by config; apps that set nothing keep the
  WorkOS AuthKit path unchanged:

      # default — WorkOS AuthKit
      config :sb_auth_ex, workos: [api_key: ..., client_id: ..., redirect_uri: ...]

      # generic OIDC (e.g. a shared company-wide issuer)
      config :sb_auth_ex,
        provider: :oidc,
        oidc: [issuer: ..., client_id: ..., client_secret: ..., redirect_uri: ..., audience: ...]

  `provider:` also accepts any module implementing this behaviour.
  One provider per app; nothing needs both at once.
  """

  @builtin %{
    workos: SbAuthEx.Providers.WorkOS,
    oidc: SbAuthEx.Providers.OIDC
  }

  @typedoc """
  Everything `login/2` needs to redirect the browser and arm the callback:
  the authorization URL plus the values parked in the encrypted oauth cookie.
  `nonce` is `nil` for providers that do not use one.
  """
  @type authorization :: %{
          url: String.t(),
          state: String.t(),
          code_verifier: String.t(),
          nonce: String.t() | nil
        }

  @typedoc "Values recovered from the oauth cookie, passed back at code exchange."
  @type callback_context :: %{code_verifier: String.t(), nonce: String.t() | nil}

  @doc """
  Builds the authorization redirect for a fresh login attempt.

  Returns `{:error, reason}` for runtime failures the login page should absorb
  gracefully (e.g. the issuer's discovery endpoint being unreachable);
  configuration errors should raise.
  """
  @callback authorize() :: {:ok, authorization()} | {:error, term()}

  @doc """
  Exchanges the callback `code` for a verified identity.

  Must perform all provider-side verification (token exchange, signature /
  issuer / audience / expiry checks where applicable) and return a normalized
  `SbAuthEx.Auth` on success.
  """
  @callback exchange_code(code :: String.t(), ctx :: callback_context()) ::
              {:ok, SbAuthEx.Auth.t()} | {:error, term()}

  @doc """
  Returns the provider logout URL to send the browser through, or `:none`
  when the provider has no session to end (logout is then local only).
  """
  @callback logout_url(session_id :: String.t() | nil, return_to :: String.t()) ::
              {:ok, String.t()} | :none

  @doc """
  Deletes the identity on the provider side, if the provider owns the account.

  Providers that do not own the upstream account (OIDC against a corporate
  IdP) return `:ok` without doing anything; local cleanup still runs.
  """
  @callback delete_user(sb_id :: String.t()) :: :ok | {:error, term()}

  @doc """
  Returns the active provider module (`config :sb_auth_ex, :provider`,
  default `:workos`).
  """
  @spec current() :: module()
  def current do
    case Application.get_env(:sb_auth_ex, :provider, :workos) do
      key when is_map_key(@builtin, key) ->
        Map.fetch!(@builtin, key)

      module when is_atom(module) ->
        if Code.ensure_loaded?(module) and implements_provider?(module) do
          module
        else
          raise ArgumentError,
                "SbAuthEx: `config :sb_auth_ex, provider:` must be :workos, :oidc, or a module " <>
                  "implementing SbAuthEx.Provider — got #{inspect(module)}"
        end

      other ->
        raise ArgumentError,
              "SbAuthEx: `config :sb_auth_ex, provider:` must be :workos, :oidc, or a module " <>
                "implementing SbAuthEx.Provider — got #{inspect(other)}"
    end
  end

  defp implements_provider?(module) do
    Enum.all?(
      [authorize: 0, exchange_code: 2, logout_url: 2, delete_user: 1],
      fn {fun, arity} -> function_exported?(module, fun, arity) end
    )
  end
end
