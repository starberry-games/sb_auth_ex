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
end
