defmodule SbAuthEx.Router do
  @moduledoc """
  Router macros for mounting SbAuthEx routes.

  ## Usage

  In your router:

      import SbAuthEx.Router

      scope "/" do
        pipe_through :browser
        sb_auth_routes()
      end

  ## Options

  - `:scope` - The path prefix for auth routes (default: "/auth")
  - `:settings` - Whether to include settings route (default: true)
  - `:settings_path` - The path for settings page (default: "/settings")
  """

  @doc """
  Mounts SbAuthEx authentication routes.

  This macro adds:
  - GET /auth/login - Initiate login
  - GET /auth/callback - OAuth callback
  - DELETE /auth/logout - Logout

  Optionally (with live_session for proper authentication):
  - GET /settings - Settings page (if :settings option is true)
  """
  defmacro sb_auth_routes(opts \\ []) do
    scope_path = Keyword.get(opts, :scope, "/auth")
    include_settings = Keyword.get(opts, :settings, true)
    settings_path = Keyword.get(opts, :settings_path, "/settings")

    quote do
      scope unquote(scope_path), SbAuthEx do
        get "/login", AuthController, :login
        get "/callback", AuthController, :callback
        delete "/logout", AuthController, :logout
      end

      if unquote(include_settings) do
        live_session :sb_auth_settings,
          on_mount: [{SbAuthEx.Hooks.OnMount, :require_authenticated}] do
          live unquote(settings_path), SbAuthEx.SettingsLive, :index
        end
      end
    end
  end
end
