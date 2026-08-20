defmodule SbAuthEx.FakeRepo do
  @moduledoc """
  Minimal in-memory stand-in for the host app's Ecto repo.

  Only implements the calls `SbAuthEx.Accounts` makes on the login path
  (`get_by/2` and `insert/2`), so controller tests can exercise the full
  callback without a database. State lives in the test process (process
  dictionary), so tests stay isolated.
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
end
