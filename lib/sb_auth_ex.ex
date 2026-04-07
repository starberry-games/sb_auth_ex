defmodule SbAuthEx do
  @moduledoc """
  SbAuthEx - Authentication package for Elixir/Phoenix apps using WorkOS AuthKit.

  ## Features

  - OAuth authentication flow with WorkOS AuthKit
  - Session-based authentication with plugs and LiveView hooks

  ## Installation

  Add to your dependencies:

      {:sb_auth_ex, "~> 0.1.0"}

  Run the install task:

      mix sb_auth_ex.install

  ## Configuration

      config :sb_auth_ex,
        repo: MyApp.Repo,
        provider: :workos,
        workos: [
          client_id: System.get_env("WORKOS_CLIENT_ID"),
          api_key: System.get_env("WORKOS_API_KEY"),
          redirect_uri: System.get_env("WORKOS_REDIRECT_URI")
        ]

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

  The `on_delete_account` callback fires before the identity is deleted,
  allowing the consuming app to clean up associated data.
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
  Deletes a user's account: fires the `on_delete_account` callback,
  deletes the WorkOS user (best-effort), and deletes the local identity.

  The callback should return `:ok` to proceed or `{:error, reason}` to abort.
  The operation is idempotent — if the identity was already removed, it returns
  `{:ok, :deleted}`.

  Returns `{:ok, :deleted}` on success or `{:error, reason}` on failure.

  ## Example

      case SbAuthEx.delete_account(identity, conn) do
        {:ok, :deleted} -> # success
        {:error, {:cleanup_failed, reason}} -> # callback aborted
        {:error, reason} -> # identity deletion failed
      end
  """
  def delete_account(%SbAuthEx.Identity{} = identity, conn) do
    case fire_on_delete_account(identity, conn) do
      {:error, reason} ->
        {:error, {:cleanup_failed, reason}}

      _ ->
        delete_workos_user(identity.sb_id)

        case SbAuthEx.Accounts.delete_identity(identity) do
          {:ok, _deleted} -> {:ok, :deleted}
          {:error, :already_deleted} -> {:ok, :deleted}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp fire_on_delete_account(identity, conn) do
    case Application.get_env(:sb_auth_ex, :on_delete_account) do
      nil -> :ok
      {module, function} -> apply(module, function, [identity, conn])
      fun when is_function(fun, 2) -> fun.(identity, conn)
    end
  end

  defp delete_workos_user(workos_user_id) do
    config = Application.get_env(:workos, WorkOS.Client)
    api_key = config[:api_key]

    url = "https://api.workos.com/user_management/users/#{workos_user_id}"

    case Req.delete(url,
           headers: [{"Authorization", "Bearer #{api_key}"}]
         ) do
      {:ok, %{status: status}} when status in [200, 204] ->
        :ok

      {:ok, %{status: status, body: body}} ->
        require Logger
        Logger.warning("Failed to delete WorkOS user #{workos_user_id}: HTTP #{status} #{inspect(body)}")
        {:error, {:http_error, status, body}}

      {:error, reason} ->
        require Logger
        Logger.warning("Failed to delete WorkOS user #{workos_user_id}: #{inspect(reason)}")
        {:error, reason}
    end
  end
end
