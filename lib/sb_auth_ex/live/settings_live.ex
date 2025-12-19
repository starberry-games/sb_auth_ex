defmodule SbAuthEx.SettingsLive do
  @moduledoc """
  LiveView for user settings/profile management.

  Allows users to edit their nickname and view their identity info.

  ## Customization

  Apps can customize the appearance via assigns:
  - `:wrapper_class` - CSS class for the wrapper div
  - `:form_class` - CSS class for the form
  """
  use Phoenix.LiveView

  alias SbAuthEx.Accounts

  @impl true
  def mount(_params, _session, socket) do
    # current_identity is already set by on_mount hook (:require_authenticated)
    # which also handles redirecting unauthenticated users
    identity = socket.assigns.current_identity
    changeset = SbAuthEx.Identity.profile_changeset(identity, %{})

    {:ok,
     socket
     |> assign(:form, to_form(changeset))
     |> assign(:saved, false)
     |> assign(:wrapper_class, "max-w-md mx-auto p-6")
     |> assign(:form_class, "")}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class={@wrapper_class}>
      <h1 class="text-2xl font-bold mb-8">Settings</h1>

      <section class="mb-8">
        <h2 class="text-sm font-medium text-base-content/60 uppercase tracking-wide mb-3">Account</h2>
        <div class="p-4 bg-base-200 rounded-lg">
          <p class="text-sm text-base-content/70">Signed in as</p>
          <p class="font-semibold mt-1">{@current_identity.email}</p>
          <p class="text-xs text-base-content/50 mt-2 font-mono">ID: {@current_identity.sb_id}</p>
        </div>
      </section>

      <section class="mb-8">
        <h2 class="text-sm font-medium text-base-content/60 uppercase tracking-wide mb-3">Profile</h2>
        <.form for={@form} phx-submit="save" phx-change="validate" class={@form_class}>
          <div class="form-control">
            <label class="label">
              <span class="label-text font-medium">Nickname</span>
            </label>
            <input
              type="text"
              name={@form[:nickname].name}
              value={@form[:nickname].value}
              class="input input-bordered w-full"
              placeholder="Enter a display name"
              maxlength="50"
              phx-debounce="300"
            />
            <%= if @form[:nickname].errors != [] do %>
              <label class="label">
                <span class="label-text-alt text-error">
                  {Enum.map(@form[:nickname].errors, fn {msg, _} -> msg end) |> Enum.join(", ")}
                </span>
              </label>
            <% end %>
          </div>

          <div class="mt-4 flex items-center gap-4">
            <button type="submit" class="btn btn-primary">
              Save Changes
            </button>
            <%= if @saved do %>
              <span class="text-success text-sm ml-1">
                ✓ Saved
              </span>
            <% end %>
          </div>
        </.form>
      </section>

      <section class="pt-6 border-t border-base-300">
        <h2 class="text-sm font-medium text-base-content/60 uppercase tracking-wide mb-3">Session</h2>
        <p class="text-sm text-base-content/70 mb-4">Sign out of your account on this device.</p>
        <.link
          href={SbAuthEx.logout_path()}
          method="delete"
          class="btn btn-error"
        >
          Log out
        </.link>
      </section>
    </div>
    """
  end

  @impl true
  def handle_event("validate", %{"identity" => params}, socket) do
    changeset =
      socket.assigns.current_identity
      |> SbAuthEx.Identity.profile_changeset(params)
      |> Map.put(:action, :validate)

    {:noreply, socket |> assign(:form, to_form(changeset)) |> assign(:saved, false)}
  end

  def handle_event("validate", params, socket) do
    identity_params = params["identity"] || params
    handle_event("validate", %{"identity" => identity_params}, socket)
  end

  @impl true
  def handle_event("save", %{"identity" => params}, socket) do
    identity = socket.assigns.current_identity

    case Accounts.update_identity(identity, params) do
      {:ok, updated_identity} ->
        {:noreply,
         socket
         |> assign(:current_identity, updated_identity)
         |> assign(:form, to_form(SbAuthEx.Identity.profile_changeset(updated_identity, %{})))
         |> assign(:saved, true)}

      {:error, changeset} ->
        {:noreply, socket |> assign(:form, to_form(changeset)) |> assign(:saved, false)}
    end
  end

  def handle_event("save", params, socket) do
    identity_params = params["identity"] || params
    handle_event("save", %{"identity" => identity_params}, socket)
  end
end
