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

end
