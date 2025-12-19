defmodule SbAuthEx.Plugs.RequireAuth do
  @moduledoc """
  Plug that ensures a user is authenticated.

  Redirects to the login page if the user is not authenticated.
  """
  import Plug.Conn
  import Phoenix.Controller

  def init(opts), do: opts

  def call(conn, _opts) do
    if conn.assigns[:current_identity] do
      conn
    else
      login_path = SbAuthEx.login_path()

      conn
      |> put_flash(:error, "You must be logged in to access this page.")
      |> redirect(to: login_path)
      |> halt()
    end
  end
end
