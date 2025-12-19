defmodule SbAuthEx.Plugs.FetchCurrentIdentity do
  @moduledoc """
  Plug that fetches the current identity from session and assigns it to the connection.

  Assigns both `:current_identity` and `:current_scope` for consistency with LiveView hooks.
  """
  import Plug.Conn

  alias SbAuthEx.Accounts

  def init(opts), do: opts

  def call(conn, _opts) do
    identity_id = get_session(conn, :identity_id)

    if identity_id do
      case Accounts.get_identity(identity_id) do
        nil ->
          conn
          |> configure_session(drop: true)
          |> assign(:current_identity, nil)
          |> assign(:current_scope, nil)

        identity ->
          conn
          |> assign(:current_identity, identity)
          |> assign(:current_scope, %{identity: identity, identity_id: identity.id})
      end
    else
      conn
      |> assign(:current_identity, nil)
      |> assign(:current_scope, nil)
    end
  end
end
