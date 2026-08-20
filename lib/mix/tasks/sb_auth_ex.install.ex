defmodule Mix.Tasks.SbAuthEx.Install do
  @shortdoc "Generates SbAuthEx migration and prints setup instructions"

  @moduledoc """
  Generates the migration file for SbAuthEx and prints setup instructions.

  ## Usage

      mix sb_auth_ex.install

  This will:
  1. Generate a migration file for the `sb_identities` table
  2. Print the migration content to copy
  3. Print configuration instructions
  """
  use Mix.Task

  @impl true
  def run(_args) do
    Mix.Task.run("ecto.gen.migration", ["create_sb_identities"])

    Mix.shell().info("""

    ✅ Migration file created!

    Copy this into your migration file:

        def change do
          create table(:sb_identities) do
            add :sb_id, :string, null: false
            add :email, :string, null: false
            add :nickname, :string

            timestamps(type: :utc_datetime)
          end

          create unique_index(:sb_identities, [:sb_id])
          create unique_index(:sb_identities, [:email])
        end

    📌 If you have an existing users table and want to link identities:

        # Add this field to the migration:
        add :user_id, references(:users, on_delete: :nilify_all)

        # And this index:
        create index(:sb_identities, [:user_id])

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    📝 Add this to your config/config.exs:

        config :sb_auth_ex,
          repo: MyApp.Repo,
          endpoint: MyAppWeb.Endpoint

    📝 Add this to your config/runtime.exs:

        config :sb_auth_ex,
          workos: [
            api_key: System.fetch_env!("WORKOS_API_KEY"),
            client_id: System.fetch_env!("WORKOS_CLIENT_ID"),
            redirect_uri: System.fetch_env!("WORKOS_REDIRECT_URI")
          ]

    📝 Update your router.ex:

        import SbAuthEx.Router

        pipeline :browser do
          # ... existing plugs ...
          plug SbAuthEx.Plugs.FetchCurrentIdentity
        end

        scope "/", MyAppWeb do
          pipe_through :browser

          sb_auth_routes()

          # ... your routes ...
        end

    📝 Add the user menu to your layout:

        <SbAuthEx.Components.UserMenu.user_menu current_identity={@current_identity} />

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Then run: mix ecto.migrate
    """)
  end
end
