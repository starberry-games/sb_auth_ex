defmodule SbAuthEx.Hooks.OnMount do
  @moduledoc """
  LiveView on_mount hooks for authentication.

  ## Usage

  In your router:

      live_session :authenticated,
        on_mount: [{SbAuthEx.Hooks.OnMount, :require_authenticated}] do
        live "/dashboard", DashboardLive
      end

      live_session :public,
        on_mount: [{SbAuthEx.Hooks.OnMount, :fetch_current_identity}] do
        live "/", HomeLive
      end
  """
  import Phoenix.LiveView
  import Phoenix.Component

  alias SbAuthEx.Accounts

  @doc """
  Handles on_mount callbacks for authentication.

  ## Modes

  - `:fetch_current_identity` - Fetches the current identity from the session and assigns it.
    Does not require authentication.
  - `:require_authenticated` - Requires the user to be authenticated.
    Redirects to login if not authenticated.
  - `:redirect_if_authenticated` - Redirects authenticated users away from auth pages.
  """
  def on_mount(mode, params, session, socket)

  def on_mount(:fetch_current_identity, _params, session, socket) do
    socket = assign_current_identity(socket, session)
    {:cont, socket}
  end

  def on_mount(:require_authenticated, _params, session, socket) do
    socket = assign_current_identity(socket, session)

    if socket.assigns.current_identity do
      {:cont, socket}
    else
      socket =
        socket
        |> put_flash(:error, "You must be logged in to access this page.")
        |> redirect(to: SbAuthEx.login_path())

      {:halt, socket}
    end
  end

  def on_mount(:redirect_if_authenticated, _params, session, socket) do
    socket = assign_current_identity(socket, session)

    if socket.assigns.current_identity do
      socket = redirect(socket, to: SbAuthEx.after_login_path())
      {:halt, socket}
    else
      {:cont, socket}
    end
  end

  defp assign_current_identity(socket, session) do
    case session["identity_id"] do
      nil ->
        socket
        |> assign(:current_identity, nil)
        |> assign(:current_scope, nil)

      identity_id ->
        case Accounts.get_identity(identity_id) do
          nil ->
            socket
            |> assign(:current_identity, nil)
            |> assign(:current_scope, nil)

          identity ->
            socket
            |> assign(:current_identity, identity)
            |> assign(:current_scope, %{identity: identity, identity_id: identity.id})
        end
    end
  end
end
