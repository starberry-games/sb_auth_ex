defmodule SbAuthEx.Accounts do
  @moduledoc """
  The Accounts context handles identity management and authentication.
  """
  alias SbAuthEx.Identity

  @doc """
  Returns the configured Ecto repo.
  """
  def repo do
    Application.get_env(:sb_auth_ex, :repo) ||
      raise "SbAuthEx requires :repo to be configured"
  end

  @doc """
  Gets an identity by internal id.

  Returns `nil` if the identity does not exist.
  """
  def get_identity(id), do: repo().get(Identity, id)

  @doc """
  Gets an identity by their sb_id (WorkOS user_id).

  Returns `nil` if the identity does not exist.
  """
  def get_identity_by_sb_id(sb_id) do
    repo().get_by(Identity, sb_id: sb_id)
  end

  @doc """
  Gets an identity by email.

  Returns `nil` if the identity does not exist.
  """
  def get_identity_by_email(email) do
    repo().get_by(Identity, email: email)
  end

  @doc """
  Gets an identity by linked user_id.

  Returns `nil` if no identity is linked to this user.
  """
  def get_identity_by_user_id(user_id) do
    repo().get_by(Identity, user_id: user_id)
  end

  @doc """
  Creates or updates an identity from provider authentication response.

  If an identity with the given sb_id exists, updates their email.
  Otherwise, creates a new identity.

  Uses Ecto's on_conflict option for atomic upsert.
  """
  def upsert_identity_from_provider!(provider_user_id, email) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %Identity{}
    |> Identity.changeset(%{sb_id: provider_user_id, email: email})
    |> repo().insert(
      on_conflict: [set: [email: email, updated_at: now]],
      conflict_target: :sb_id,
      returning: true
    )
  end

  @doc """
  Updates an identity's profile fields (like nickname).
  """
  def update_identity(%Identity{} = identity, attrs) do
    identity
    |> Identity.profile_changeset(attrs)
    |> repo().update()
  end

  @doc """
  Links an identity to an app-specific user.
  """
  def link_to_user(%Identity{} = identity, user_id) do
    identity
    |> Identity.link_changeset(user_id)
    |> repo().update()
  end

  @doc """
  Attempts to auto-link an identity to a user by matching email.
  Calls the configured callback to find the user.

  Does nothing if:
  - `auto_link_by_email` is not enabled
  - Identity already has a `user_id` (already linked)
  - Callback returns nil (no matching user)

  Returns `{:ok, identity}` if linked, or `{:ok, identity}` unchanged otherwise.
  """
  def maybe_auto_link_by_email(%Identity{user_id: user_id} = identity) when not is_nil(user_id) do
    # Already linked, nothing to do
    {:ok, identity}
  end

  def maybe_auto_link_by_email(%Identity{} = identity) do
    case Application.get_env(:sb_auth_ex, :auto_link_by_email, false) do
      false ->
        {:ok, identity}

      true ->
        case get_user_by_email_callback(identity.email) do
          nil -> {:ok, identity}
          user_id -> link_to_user(identity, user_id)
        end
    end
  end

  defp get_user_by_email_callback(email) do
    case Application.get_env(:sb_auth_ex, :get_user_id_by_email) do
      nil -> nil
      {module, function} -> apply(module, function, [email])
      fun when is_function(fun, 1) -> fun.(email)
    end
  end
end
