defmodule SbAuthEx.Components.UserMenu do
  @moduledoc """
  Simple auth button component.

  Shows a login button when logged out, or a configurable profile button when logged in.

  ## Usage

      <SbAuthEx.Components.UserMenu.user_menu current_identity={@current_identity} />

  ## Customizing button text and path

      <SbAuthEx.Components.UserMenu.user_menu
        current_identity={@current_identity}
        logged_in_text="My Account"
        logged_in_path="/account"
      />
  """
  use Phoenix.Component

  @doc """
  Renders auth button.

  When logged in: Shows configurable button linking to settings/profile
  When logged out: Shows "Log in" button

  ## Attributes

  - `current_identity` - The current identity (or nil if not logged in)
  - `class` - Additional CSS classes for the container
  - `login_text` - Text for login button (default: "Log in")
  - `login_class` - CSS classes for the login button
  - `logged_in_text` - Text for logged-in button (default: "Profile")
  - `logged_in_path` - Path for logged-in button (default: settings_path)
  - `logged_in_class` - CSS classes for the logged-in button
  """
  attr :current_identity, :map, default: nil
  attr :class, :string, default: ""
  attr :login_text, :string, default: "Log in"
  attr :login_class, :string, default: "btn btn-primary btn-sm"
  attr :logged_in_text, :string, default: "Profile"
  attr :logged_in_path, :string, default: nil
  attr :logged_in_class, :string, default: "btn btn-ghost btn-sm"

  def user_menu(assigns) do
    assigns = assign_new(assigns, :resolved_path, fn ->
      assigns.logged_in_path || SbAuthEx.settings_path()
    end)

    ~H"""
    <div class={@class}>
      <%= if @current_identity do %>
        <a href={@resolved_path} class={@logged_in_class}>
          {@logged_in_text}
        </a>
      <% else %>
        <a href={SbAuthEx.login_path()} class={@login_class}>
          {@login_text}
        </a>
      <% end %>
    </div>
    """
  end
end
