# SbAuthEx

A reusable authentication package for Elixir/Phoenix apps using WorkOS AuthKit.

## Features

- OAuth authentication via WorkOS AuthKit (Google, GitHub, email, etc.)
- Identity management with `sb_identities` table
- Optional linking to your app's existing users table
- Plugs and LiveView hooks for authentication

## Installation

### 1. Add Dependency

Add `sb_auth_ex` to your dependencies in `mix.exs`. Choose one of these options:

**Option A: Git dependency (recommended for private packages)**

Host `sb_auth_ex` in a private GitHub repository and reference it via SSH:

```elixir
defp deps do
  [
    {:sb_auth_ex, git: "git@github.com:starberry-games/sb_auth_ex.git"},
    # ... other deps
  ]
end
```

You can also pin to a specific tag or branch:

```elixir
{:sb_auth_ex, git: "git@github.com:starberry-games/sb_auth_ex.git", tag: "v0.1.0"}
{:sb_auth_ex, git: "git@github.com:starberry-games/sb_auth_ex.git", branch: "main"}
```

Anyone with SSH access to the repo can run `mix deps.get` to fetch the package.

After adding the dependency, run:

```bash
mix deps.get
```

### 2. Run Install Task

```bash
mix sb_auth_ex.install
```

This generates a migration file and prints setup instructions.

### 3. Update Migration

Edit the generated migration file (`priv/repo/migrations/*_create_sb_identities.exs`):

```elixir
def change do
  create table(:sb_identities) do
    add :sb_id, :string, null: false
    add :email, :string, null: false
    add :nickname, :string
    add :user_id, :integer  # Optional: link to your users table

    timestamps(type: :utc_datetime)
  end

  create unique_index(:sb_identities, [:sb_id])
  create unique_index(:sb_identities, [:email])
  create index(:sb_identities, [:user_id])
end
```

**If linking to existing users table:**

```elixir
add :user_id, references(:users, on_delete: :nilify_all)
```

Run the migration:

```bash
mix ecto.migrate
```

### 4. Configure the Package

**config/config.exs:**

```elixir
# Required configuration
config :sb_auth_ex,
  repo: MyApp.Repo,
  endpoint: MyAppWeb.Endpoint

# Optional: customize paths (these are the defaults)
config :sb_auth_ex,
  login_path: "/auth/login",
  logout_path: "/auth/logout",
  after_login_path: "/",
  after_logout_path: "/"

# Optional: callback after each successful login
config :sb_auth_ex,
  on_login: {MyApp.Users, :on_login}
```

**config/runtime.exs:**

```elixir
if workos_api_key = System.get_env("WORKOS_API_KEY") do
  workos_client_id =
    System.get_env("WORKOS_CLIENT_ID") ||
      raise "WORKOS_CLIENT_ID is required"

  workos_redirect_uri =
    System.get_env("WORKOS_REDIRECT_URI") ||
      raise "WORKOS_REDIRECT_URI is required"

  config :workos, WorkOS.Client,
    api_key: workos_api_key,
    client_id: workos_client_id

  config :sb_auth_ex,
    workos: [
      client_id: workos_client_id,
      redirect_uri: workos_redirect_uri
    ]
end
```

### 5. Update Router

```elixir
defmodule MyAppWeb.Router do
  use MyAppWeb, :router
  import SbAuthEx.Router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {MyAppWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug SbAuthEx.Plugs.FetchCurrentIdentity  # Add this
  end

  # Mount auth routes
  scope "/" do
    pipe_through :browser

    sb_auth_routes()  # Adds /auth/login, /auth/callback, /auth/logout
  end

  # Your app routes
  scope "/", MyAppWeb do
    pipe_through :browser

    get "/", PageController, :home
  end

  # Protected LiveView routes
  live_session :authenticated,
    on_mount: [{SbAuthEx.Hooks.OnMount, :require_authenticated}] do
    scope "/", MyAppWeb do
      pipe_through :browser
      live "/dashboard", DashboardLive
    end
  end

  # Public LiveView routes with identity context
  live_session :public,
    on_mount: [{SbAuthEx.Hooks.OnMount, :fetch_current_identity}] do
    scope "/", MyAppWeb do
      pipe_through :browser
      live "/public", PublicLive
    end
  end
end
```

### 6. Environment Variables

Set these environment variables:

```bash
WORKOS_API_KEY=sk_live_...
WORKOS_CLIENT_ID=client_...
WORKOS_REDIRECT_URI=http://localhost:4000/auth/callback  # dev
# WORKOS_REDIRECT_URI=https://myapp.com/auth/callback    # prod
```

## Usage

### Accessing Current Identity

The identity is made available through two mechanisms:

| Context | Mechanism | Sets `current_identity` |
|---------|-----------|------------------------|
| Controllers | `FetchCurrentIdentity` plug | `conn.assigns.current_identity` |
| LiveView | `on_mount` hook | `socket.assigns.current_identity` |

Both also set `current_scope` with `%{identity: identity, identity_id: id}` for convenience.

**In Controllers (via plug):**

The `FetchCurrentIdentity` plug reads `identity_id` from the session, fetches the identity from the database, and assigns it:

```elixir
def show(conn, _params) do
  identity = conn.assigns.current_identity
  # identity is nil if not logged in
  # identity.email, identity.nickname, identity.sb_id, identity.user_id
end
```

**In LiveView (via on_mount hook):**

The `on_mount` hook does the same for LiveViews. Make sure your LiveView is inside a `live_session` with the appropriate hook:

```elixir
# In router
live_session :authenticated,
  on_mount: [{SbAuthEx.Hooks.OnMount, :require_authenticated}] do
    live "/dashboard", DashboardLive
  end
```

```elixir
# In your LiveView - identity is already available
def mount(_params, _session, socket) do
  # No need to read from session or fetch from DB - the hook already did it
  identity = socket.assigns.current_identity

  {:ok, assign(socket, :user_email, identity.email)}
end
```

> **Note:** Don't read from `session` and call `Accounts.get_identity()` manually in your LiveView mount - that's redundant. The `on_mount` hook handles fetching and assigning the identity before your `mount/3` is called.

**In Templates:**

```heex
<%= if @current_identity do %>
  <p>Welcome, <%= @current_identity.email %></p>
<% else %>
  <a href="/auth/login">Sign in</a>
<% end %>
```

### Linking Identities to App Users

The `user_id` field on identities is optional and flexible. You can link identities to your app's users table whenever it makes sense for your use case.

#### Strategy 1: No User Table (Simplest)

Just use `sb_identities` for authentication. No linking needed.

```elixir
# Access identity directly
identity = conn.assigns.current_identity
identity.email     # "user@example.com"
identity.nickname  # "John"
identity.sb_id     # "user_01ABC..."
```

You can add a users table later when you need app-specific user data.

#### Strategy 2: Manual Linking

Link identities to users manually when it makes sense:

```elixir
# When creating a user from an identity
def create_user_from_identity(identity, attrs) do
  {:ok, user} = Repo.insert(%User{email: identity.email, name: attrs.name})

  # Link the identity to the new user
  SbAuthEx.Accounts.link_to_user(identity, user.id)

  {:ok, user}
end

# Or link an existing identity to an existing user
identity = SbAuthEx.Accounts.get_identity_by_email("user@example.com")
SbAuthEx.Accounts.link_to_user(identity, user.id)
```

#### Strategy 3: Add User Table Later

Start without a users table, add one when needed:

```elixir
# Later, when you add a users table, backfill links:
def backfill_user_links do
  Repo.all(User)
  |> Enum.each(fn user ->
    case SbAuthEx.Accounts.get_identity_by_email(user.email) do
      nil -> :ok  # No identity for this user yet
      identity -> SbAuthEx.Accounts.link_to_user(identity, user.id)
    end
  end)
end
```

#### Getting Linked Data

```elixir
# Get identity by linked user
identity = SbAuthEx.Accounts.get_identity_by_user_id(user.id)

# Get user from identity (in your app)
user = Repo.get(User, identity.user_id)
```

### Callbacks

#### on_login

Called after every successful login. Useful for:

```elixir
# config/config.exs
config :sb_auth_ex,
  on_login: {MyApp.Users, :on_login}
```

```elixir
# lib/my_app/users.ex
defmodule MyApp.Users do
  def on_login(identity, conn) do
    # Check if this is a new user (no linked user yet)
    if is_nil(identity.user_id) do
      # Send welcome email, create profile, etc.
      MyApp.Mailer.send_welcome_email(identity.email)
    end

    # Access request info from conn if needed
    user_agent = Plug.Conn.get_req_header(conn, "user-agent")

    # Sync with external service
    MyApp.Analytics.track_login(identity)

    :ok
  end
end
```

You can also use an anonymous function:

```elixir
config :sb_auth_ex,
  on_login: fn identity, conn ->
    IO.puts("User logged in: #{identity.email}")
  end
```

### Implementing a Settings Page

If you need a settings/profile page, implement it in your consuming app using the provided account functions:

**In a LiveView:**

```elixir
defmodule MyAppWeb.SettingsLive do
  use MyAppWeb, :live_view

  def mount(_params, _session, socket) do
    # current_identity is set by the :require_authenticated on_mount hook
    identity = socket.assigns.current_identity
    changeset = SbAuthEx.Identity.profile_changeset(identity, %{})

    {:ok, assign(socket, form: to_form(changeset))}
  end

  def handle_event("save", %{"identity" => params}, socket) do
    identity = socket.assigns.current_identity

    case SbAuthEx.Accounts.update_identity(identity, params) do
      {:ok, updated_identity} ->
        {:noreply,
         socket
         |> assign(:current_identity, updated_identity)
         |> put_flash(:info, "Profile updated!")}

      {:error, changeset} ->
        {:noreply, assign(socket, form: to_form(changeset))}
    end
  end
end
```

**In a Controller:**

```elixir
def update(conn, %{"identity" => params}) do
  identity = conn.assigns.current_identity

  case SbAuthEx.Accounts.update_identity(identity, params) do
    {:ok, _identity} ->
      conn
      |> put_flash(:info, "Profile updated!")
      |> redirect(to: ~p"/settings")

    {:error, changeset} ->
      render(conn, :edit, changeset: changeset)
  end
end
```

The `profile_changeset/2` validates the nickname field (max 50 characters).

### Available Functions

```elixir
# Get identity by ID
SbAuthEx.Accounts.get_identity(id)

# Get identity by WorkOS user ID
SbAuthEx.Accounts.get_identity_by_sb_id(sb_id)

# Get identity by email
SbAuthEx.Accounts.get_identity_by_email(email)

# Get identity by linked user ID
SbAuthEx.Accounts.get_identity_by_user_id(user_id)

# Update identity profile (nickname)
SbAuthEx.Accounts.update_identity(identity, %{nickname: "New Name"})

# Link identity to app user
SbAuthEx.Accounts.link_to_user(identity, user_id)
```

## Router Options

```elixir
# Default settings
sb_auth_routes()

# Customize auth route prefix
sb_auth_routes(scope: "/api/auth")
```

## LiveView Hooks

Available hooks for `on_mount`:

- `:fetch_current_identity` - Fetches identity without requiring auth
- `:require_authenticated` - Requires auth, redirects to login if not
- `:redirect_if_authenticated` - Redirects logged-in users away (for login pages)

```elixir
live_session :my_session,
  on_mount: [{SbAuthEx.Hooks.OnMount, :require_authenticated}] do
  # routes...
end
```

## Plugs

Plugs are for traditional controller routes (non-LiveView). For LiveView, use the `on_mount` hooks instead.

### FetchCurrentIdentity

Fetches identity from session and assigns it to `conn.assigns.current_identity`. Add this to your browser pipeline:

```elixir
pipeline :browser do
  # ... other plugs
  plug SbAuthEx.Plugs.FetchCurrentIdentity
end
```

### RequireAuth

Requires authentication for controller routes. Redirects to login if not authenticated.

```elixir
# Define a pipeline
pipeline :require_auth do
  plug SbAuthEx.Plugs.RequireAuth
end

# Use it for protected controller routes
scope "/admin", MyAppWeb do
  pipe_through [:browser, :require_auth]

  get "/", AdminController, :index
  get "/users", AdminController, :users
end
```

### RedirectIfAuthenticated

Redirects authenticated users away (useful for login/register pages that logged-in users shouldn't see).

```elixir
# Define a pipeline
pipeline :redirect_if_authenticated do
  plug SbAuthEx.Plugs.RedirectIfAuthenticated
end

# Use it for auth pages
scope "/", MyAppWeb do
  pipe_through [:browser, :redirect_if_authenticated]

  get "/register", RegistrationController, :new
  post "/register", RegistrationController, :create
end
```

> **Note:** `conn.assigns` is server-side only. The client cannot modify it - they can only send the session cookie (which is cryptographically signed). The plug reads the session, looks up the identity in the database, and sets the assign. This is safe.

## Schema Reference

### sb_identities Table

| Column | Type | Description |
|--------|------|-------------|
| id | integer | Primary key |
| sb_id | string | WorkOS user ID (unique) |
| email | string | User email (unique) |
| nickname | string | Display name (optional) |
| user_id | integer | Foreign key to app's users (optional) |
| inserted_at | utc_datetime | Created timestamp |
| updated_at | utc_datetime | Updated timestamp |

## WorkOS Dashboard Setup

### Initial Setup

1. Go to [WorkOS Dashboard](https://dashboard.workos.com/)
2. Create a new project (or use existing)
3. Go to **AuthKit** in the sidebar
4. Click **Enable AuthKit**

### Configure Redirect URIs

Go to **Redirects** in the AuthKit section and add your callback URLs:

| Environment | Redirect URI |
|-------------|--------------|
| Development | `http://localhost:4000/auth/callback` |
| Staging | `https://staging.yourapp.com/auth/callback` |
| Production | `https://yourapp.com/auth/callback` |

> **Note:** You can add multiple redirect URIs to the same WorkOS project. The `WORKOS_REDIRECT_URI` environment variable in your app determines which one is used.

### Configure Authentication Methods

Go to **Authentication** in the AuthKit section:

1. **Email + Password** - Enable if you want email/password login
2. **Social Logins** - Enable Google, GitHub, Microsoft, etc.
   - For Google: You'll need to configure OAuth credentials in Google Cloud Console
   - For GitHub: Configure OAuth app in GitHub Developer Settings
3. **Magic Link** - Enable for passwordless email login

### Get Your Credentials

Go to **API Keys** in the sidebar:

1. Copy your **API Key** (starts with `sk_`)
2. Go to **AuthKit > Settings** and copy your **Client ID** (starts with `client_`)

### Multi-App Setup

**Option A: Single WorkOS Project (Recommended for same user base)**

If all your apps share the same users:
- Use ONE WorkOS project
- Add all redirect URIs (dev/staging/prod for each app)
- Same API Key and Client ID across apps
- Users have same `sb_id` across all apps

```
Redirect URIs:
- http://localhost:4000/auth/callback       (App A - dev)
- https://app-a.com/auth/callback           (App A - prod)
- http://localhost:4001/auth/callback       (App B - dev)
- https://app-b.com/auth/callback           (App B - prod)
```

**Option B: Separate WorkOS Projects (Isolated apps)**

If apps should have separate user bases:
- Create separate WorkOS project per app
- Each has its own API Key and Client ID
- Users have different `sb_id` per app

### Environment Variables Per Environment

**Development (.env or shell):**
```bash
WORKOS_API_KEY=sk_test_...
WORKOS_CLIENT_ID=client_...
WORKOS_REDIRECT_URI=http://localhost:4000/auth/callback
```

**Staging (e.g., Fly.io secrets):**
```bash
fly secrets set WORKOS_API_KEY=sk_test_...
fly secrets set WORKOS_CLIENT_ID=client_...
fly secrets set WORKOS_REDIRECT_URI=https://staging.yourapp.com/auth/callback
```

**Production (e.g., Fly.io secrets):**
```bash
fly secrets set WORKOS_API_KEY=sk_live_...
fly secrets set WORKOS_CLIENT_ID=client_...
fly secrets set WORKOS_REDIRECT_URI=https://yourapp.com/auth/callback
```

> **Important:** Use `sk_test_` keys for development/staging and `sk_live_` keys for production.

### Testing Checklist

Before going live, verify:

- [ ] Redirect URI matches exactly (including trailing slashes)
- [ ] All auth methods you want are enabled in WorkOS dashboard
- [ ] Social login providers are configured (Google, GitHub, etc.)
- [ ] Environment variables are set correctly per environment
- [ ] Test login flow end-to-end in each environment
