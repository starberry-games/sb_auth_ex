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
  """

  @doc """
  Mounts SbAuthEx authentication routes.

  This macro adds:
  - GET /auth/login - Initiate login
  - GET /auth/callback - OAuth callback
  - DELETE /auth/logout - Logout
  - DELETE /auth/account - Delete account
  """
  defmacro sb_auth_routes(opts \\ []) do
    scope_path = Keyword.get(opts, :scope, "/auth")

    quote do
      scope unquote(scope_path), SbAuthEx do
        get "/login", AuthController, :login
        get "/callback", AuthController, :callback
        delete "/logout", AuthController, :logout
        delete "/account", AuthController, :delete_account
      end
    end
  end
end
