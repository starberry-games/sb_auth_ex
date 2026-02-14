defmodule SbAuthEx.Plugs.RequireAuth do
  @moduledoc """
  Plug that ensures a user is authenticated.

  Redirects to the login page if the user is not authenticated.
  Automatically passes the current request path as `return_to` so the user
  is redirected back after login.
  """
  import Plug.Conn
  import Phoenix.Controller

  def init(opts), do: opts

  def call(conn, _opts) do
    if conn.assigns[:current_identity] do
      conn
    else
      return_to = request_path_with_query(conn)
      login_url = SbAuthEx.login_path() <> "?" <> URI.encode_query(%{"return_to" => return_to})

      conn
      |> put_flash(:error, "You must be logged in to access this page.")
      |> redirect(to: login_url)
      |> halt()
    end
  end

  defp request_path_with_query(conn) do
    case conn.query_string do
      "" -> conn.request_path
      qs -> conn.request_path <> "?" <> qs
    end
  end
end
