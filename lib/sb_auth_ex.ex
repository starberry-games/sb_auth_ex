defmodule SbAuthEx do
  @moduledoc """
  SbAuthEx - Authentication package for Elixir/Phoenix apps, using WorkOS
  AuthKit (default) or any OIDC provider.

  ## Features

  - OAuth authentication flow (PKCE + `state`, login-CSRF safe) against a
    configurable `SbAuthEx.Provider`: WorkOS AuthKit or generic OIDC
  - Session-based authentication with plugs and LiveView hooks

  ## Installation

  Add to your dependencies:

      {:sb_auth_ex, "~> 0.8.0"}

  Run the install task:

      mix sb_auth_ex.install

  ## Configuration

      config :sb_auth_ex,
        repo: MyApp.Repo,
        endpoint: MyAppWeb.Endpoint,
        workos: [
          api_key: System.get_env("WORKOS_API_KEY"),
          client_id: System.get_env("WORKOS_CLIENT_ID"),
          redirect_uri: System.get_env("WORKOS_REDIRECT_URI")
        ]

  See `SbAuthEx.WorkOSClient` for how the WorkOS client is built (including the
  legacy `config :workos, WorkOS.Client` fallback).

  Internal tools authenticating against a shared OIDC issuer configure the
  OIDC provider instead (see `SbAuthEx.Providers.OIDC` for all options):

      config :sb_auth_ex,
        provider: :oidc,
        oidc: [
          issuer: System.get_env("OIDC_ISSUER"),
          client_id: System.get_env("OIDC_CLIENT_ID"),
          client_secret: System.get_env("OIDC_CLIENT_SECRET"),
          redirect_uri: System.get_env("OIDC_REDIRECT_URI"),
          audience: System.get_env("OIDC_AUDIENCE")
        ]

  Apps that set no `provider:` keep the WorkOS AuthKit path unchanged.

  ## Usage

  In your router:

      import SbAuthEx.Router

      pipeline :browser do
        plug SbAuthEx.Plugs.FetchCurrentIdentity
      end

      sb_auth_routes()

  ## Callbacks

      config :sb_auth_ex,
        on_login: {MyApp.AuthCallbacks, :on_login},
        on_register: {MyApp.AuthCallbacks, :on_register},
        on_logout: {MyApp.AuthCallbacks, :on_logout},
        on_delete_account: {MyApp.AuthCallbacks, :on_delete_account}

  The `on_delete_account` callback fires after WorkOS confirms the user is gone
  and before the local identity is deleted. It must be idempotent so cleanup can
  be retried safely when a later deletion step fails.
  """

  @doc """
  Returns the configured repository module.
  """
  def repo do
    Application.get_env(:sb_auth_ex, :repo) ||
      raise "SbAuthEx requires :repo to be configured"
  end

  @doc """
  Returns the configured login path.
  """
  def login_path do
    Application.get_env(:sb_auth_ex, :login_path, "/auth/login")
  end

  @doc """
  Returns the configured logout path.
  """
  def logout_path do
    Application.get_env(:sb_auth_ex, :logout_path, "/auth/logout")
  end

  @doc """
  Returns the path to redirect to after login.
  """
  def after_login_path do
    Application.get_env(:sb_auth_ex, :after_login_path, "/")
  end

  @doc """
  Returns the path to redirect to after logout.
  """
  def after_logout_path do
    Application.get_env(:sb_auth_ex, :after_logout_path, "/")
  end

  @doc """
  Deletes a user's account by deleting the user on the provider side, firing
  the `on_delete_account` callback, and then deleting the local identity.

  The provider must confirm deletion before the callback can run. The WorkOS
  provider deletes the WorkOS user; the OIDC provider does not own the
  upstream account (it lives at the IdP) and confirms immediately. The
  callback should be idempotent because it can run again when a later step
  fails. Return `:ok` to proceed or `{:error, reason}` to retain the local
  identity and session for retry.

  Returns `{:ok, :deleted}` on success or `{:error, reason}` on failure.

  ## Example

      case SbAuthEx.delete_account(identity, conn) do
        {:ok, :deleted} -> # success
        {:error, {:cleanup_failed, reason}} -> # callback aborted
        {:error, {:workos_delete_failed, reason}} -> # provider deletion failed
        {:error, reason} -> # identity deletion failed
      end
  """
  def delete_account(%SbAuthEx.Identity{} = identity, conn) do
    case SbAuthEx.Provider.current().delete_user(identity.sb_id) do
      :ok ->
        case fire_on_delete_account(identity, conn) do
          {:error, reason} ->
            {:error, {:cleanup_failed, reason}}

          _ ->
            case SbAuthEx.Accounts.delete_identity(identity) do
              {:ok, _deleted} -> {:ok, :deleted}
              {:error, :already_deleted} -> {:ok, :deleted}
              {:error, reason} -> {:error, reason}
            end
        end

      {:error, reason} ->
        {:error, {:workos_delete_failed, reason}}
    end
  end

  defp fire_on_delete_account(identity, conn) do
    case Application.get_env(:sb_auth_ex, :on_delete_account) do
      nil -> :ok
      {module, function} -> apply(module, function, [identity, conn])
      fun when is_function(fun, 2) -> fun.(identity, conn)
    end
  end
end
