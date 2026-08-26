defmodule SbAuthEx.FakeRepo do
  @moduledoc """
  Minimal in-memory stand-in for the host app's Ecto repo.

  Implements the calls `SbAuthEx.Accounts` makes on the authentication and
  account-deletion paths, so controller tests can exercise them without a
  database. State lives in the test process (process dictionary), so tests
  stay isolated.
  """

  alias SbAuthEx.Identity

  @key {__MODULE__, :identities}

  def reset, do: Process.put(@key, %{})

  def all_identities, do: Map.values(Process.get(@key, %{}))

  def get_by(Identity, sb_id: sb_id) do
    Process.get(@key, %{}) |> Map.get(sb_id)
  end

  def get(Identity, id) do
    Enum.find(all_identities(), &(&1.id == id))
  end

  def insert(%Ecto.Changeset{valid?: true} = changeset, _opts) do
    identities = Process.get(@key, %{})
    %Identity{} = attrs = Ecto.Changeset.apply_changes(changeset)

    identity =
      case Map.get(identities, attrs.sb_id) do
        nil -> %Identity{attrs | id: map_size(identities) + 1}
        %Identity{} = existing -> %Identity{existing | email: attrs.email}
      end

    Process.put(@key, Map.put(identities, identity.sb_id, identity))
    {:ok, identity}
  end

  def insert(%Ecto.Changeset{} = changeset, _opts), do: {:error, changeset}

  def delete(%Identity{} = identity) do
    identities = Process.get(@key, %{})

    if Map.has_key?(identities, identity.sb_id) do
      Process.put(@key, Map.delete(identities, identity.sb_id))
      {:ok, identity}
    else
      raise Ecto.StaleEntryError,
        action: :delete,
        changeset: Ecto.Changeset.change(identity)
    end
  end
end
