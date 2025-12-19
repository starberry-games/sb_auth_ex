defmodule SbAuthEx.Identity do
  @moduledoc """
  Schema representing an authenticated identity from WorkOS.

  The `sb_id` field stores the WorkOS user_id and serves as the
  global cross-application identifier for this identity.

  The optional `user_id` field can be used to link this identity
  to an app-specific users table.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "sb_identities" do
    field :sb_id, :string
    field :email, :string
    field :nickname, :string
    field :user_id, :integer

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating or updating an identity from provider authentication.
  """
  def changeset(identity, attrs) do
    identity
    |> cast(attrs, [:sb_id, :email, :nickname, :user_id])
    |> validate_required([:sb_id, :email])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+$/, message: "must be a valid email")
    |> unique_constraint(:sb_id)
    |> unique_constraint(:email)
  end

  @doc """
  Changeset for updating profile fields (nickname only).
  Does not allow changing sb_id or email.
  """
  def profile_changeset(identity, attrs) do
    identity
    |> cast(attrs, [:nickname])
    |> validate_length(:nickname, max: 50)
  end

  @doc """
  Changeset for linking an identity to an app user.
  """
  def link_changeset(identity, user_id) do
    identity
    |> cast(%{user_id: user_id}, [:user_id])
  end
end
