defmodule SbAuthEx.Plugs.RedirectIfAuthenticated do
  @moduledoc """
  Plug that redirects authenticated users away from auth pages.
  """
  import Plug.Conn
  import Phoenix.Controller

  def init(opts), do: opts

  def call(conn, _opts) do
    if conn.assigns[:current_identity] do
      redirect_path = SbAuthEx.after_login_path()

      conn
      |> redirect(to: redirect_path)
      |> halt()
    else
      conn
    end
  end
end
