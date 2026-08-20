# SbAuthEx

A reusable authentication package for Elixir/Phoenix apps using WorkOS AuthKit.

## Features

- OAuth authentication via WorkOS AuthKit (Google, GitHub, email, etc.), with
  PKCE and a per-login `state` — see [Login CSRF protection](#login-csrf-protection)
- Identity management with `sb_identities` table
- Optional linking to your app's existing users table
- Plugs and LiveView hooks for authentication
- Lifecycle callbacks: `on_login`, `on_register`, `on_logout`, `on_delete_account`
- Account deletion with WorkOS user cleanup (`DELETE /auth/account`)
- `return_to` redirect support (return users to the page they were trying to visit)

## Upgrading to 0.7 (WorkOS SDK 3.x)

0.7 moves from the WorkOS Elixir SDK 1.x to 3.x and fixes a login-CSRF
vulnerability (missing OAuth `state`). To upgrade a consuming app:

1. Bump `sb_auth_ex` to `v0.7.0` (and `workos` to `~> 3.0` if you depend on it
   directly). Requires Elixir **1.18+**.
2. Move the WorkOS credentials into the `:sb_auth_ex` config (see
   [Configure the Package](#4-configure-the-package)). The old
   `config :workos, WorkOS.Client, ...` is still read as a fallback, so this
   step is not strictly required, but the 3.x SDK ignores it.
3. If your app wrapped `SbAuthEx.AuthController` to add its own `state` check,
   remove the wrapper — the library now does this itself.
4. If you call the `WorkOS.*` modules directly, follow the SDK's 3.x API: every
   function takes an explicit client, which you can get from
   `SbAuthEx.WorkOSClient.client/0`.
5. `hackney`/`tesla` are no longer pulled in (the 3.x SDK uses `req`), so any
   `hackney` version pin you kept for `sb_auth_ex`'s sake can go.

## Installation

### 1. Add Dependency

Add `sb_auth_ex` to your dependencies in `mix.exs`. Choose one of these options:

**Option A: Git dependency**

Reference `sb_auth_ex` via SSH:

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

# Optional: lifecycle callbacks
config :sb_auth_ex,
  on_login: {MyApp.Users, :on_login},
  on_register: {MyApp.Users, :on_register},
  on_logout: {MyApp.Users, :on_logout},
  on_delete_account: {MyApp.Users, :on_delete_account}
```

**config/runtime.exs:**

```elixir
config :sb_auth_ex,
  workos: [
    api_key: System.fetch_env!("WORKOS_API_KEY"),
    client_id: System.fetch_env!("WORKOS_CLIENT_ID"),
    redirect_uri: System.fetch_env!("WORKOS_REDIRECT_URI")
  ]
```

`api_key` and `client_id` may be omitted if the `WORKOS_API_KEY` /
`WORKOS_CLIENT_ID` environment variables are set — the WorkOS SDK falls back to
them. The pre-0.7 shape (`config :workos, WorkOS.Client, api_key: ..., client_id: ...`)
is still read as a fallback, so existing apps keep working, but the WorkOS 3.x
SDK itself no longer uses that key — prefer the `:sb_auth_ex` config above.

Other `WorkOS.Client.new/1` options (`:base_url`, `:timeout`, `:max_retries`,
`:req_options`) can be passed in the same keyword list; see `SbAuthEx.WorkOSClient`.

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

    sb_auth_routes()  # Adds /auth/login, /auth/callback, /auth/logout, /auth/account
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

The redirect URI must be registered in the WorkOS dashboard (Redirects). The
logout flow additionally redirects the browser back to
`endpoint.url() <> after_logout_path` — if your WorkOS project restricts logout
redirect URIs, register that URL too.

## Login CSRF protection

`GET /auth/login` starts an OAuth authorization-code flow with **PKCE** and a
random, per-attempt **`state`** (generated by
`WorkOS.AuthKit.get_pkce_authorization_url/2`). Both are stored in a
short-lived (10 min), encrypted, `HttpOnly`, `SameSite=Lax` cookie bound to the
browser that started the login.

`GET /auth/callback` then:

1. consumes that cookie (each login attempt can be redeemed exactly once),
2. refuses the request — without contacting WorkOS — if the cookie is missing,
   or the `state` query parameter is missing or does not match
   (`Plug.Crypto.secure_compare/2`),
3. only then exchanges the `code` together with the PKCE `code_verifier`.

This closes the classic login-CSRF hole where an attacker hands a victim their
own `?code=` and the victim's browser ends up signed in to the attacker's
account. No configuration is needed; it is always on.

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

All callbacks receive `(identity, conn)` and can be configured as either a `{Module, :function}` tuple or an anonymous function. Return values are ignored.

```elixir
# config/config.exs
config :sb_auth_ex,
  on_login: {MyApp.Users, :on_login},
  on_register: {MyApp.Users, :on_register},
  on_logout: {MyApp.Users, :on_logout}
```

#### on_login

Called after every successful login (both new and returning users).

```elixir
def on_login(identity, conn) do
  MyApp.Analytics.track_login(identity)
  :ok
end
```

#### on_register

Called only when a user authenticates for the **first time** (new identity created). When a new user registers, both `on_register` and `on_login` fire, in that order.

```elixir
def on_register(identity, conn) do
  # Send welcome email, create a user profile, etc.
  MyApp.Mailer.send_welcome_email(identity.email)
  :ok
end
```

#### on_logout

Called during logout, **before** the session is cleared. Only fires if the user is actually logged in (identity is available). Useful for audit logging or cleanup.

```elixir
def on_logout(identity, conn) do
  MyApp.Analytics.track_logout(identity)
  :ok
end
```

#### on_delete_account

Called when a user deletes their account, **before** the identity is removed from the database and WorkOS. Use this to clean up all associated app data.

Return `:ok` to proceed with deletion, or `{:error, reason}` to abort (the endpoint will return a 422 with the reason). Any other return value proceeds with deletion.

```elixir
def on_delete_account(identity, conn) do
  # Delete all app data associated with this user before the identity is removed
  if identity.user_id do
    MyApp.Repo.delete_all(from u in MyApp.User, where: u.id == ^identity.user_id)
  end
  :ok
end
```

#### Callback example

```elixir
# lib/my_app/users.ex
defmodule MyApp.Users do
  def on_register(identity, conn) do
    # Create app-specific user record
    {:ok, user} = MyApp.Repo.insert(%MyApp.User{email: identity.email})
    SbAuthEx.Accounts.link_to_user(identity, user.id)
    MyApp.Mailer.send_welcome_email(identity.email)
    :ok
  end

  def on_login(identity, conn) do
    MyApp.Analytics.track_login(identity)
    :ok
  end

  def on_logout(identity, conn) do
    MyApp.Analytics.track_logout(identity)
    :ok
  end

  def on_delete_account(identity, conn) do
    # Clean up all app data before identity is deleted
    if identity.user_id do
      MyApp.Repo.delete_all(from u in MyApp.User, where: u.id == ^identity.user_id)
    end
    :ok
  end
end
```

You can also use anonymous functions:

```elixir
config :sb_auth_ex,
  on_login: fn identity, conn ->
    IO.puts("User logged in: #{identity.email}")
  end
```

### Redirect After Login (`return_to`)

By default, after login users are redirected to `after_login_path` (defaults to `"/"`). With `return_to` support, users are redirected back to the page they were trying to visit.

#### How it works

1. When an unauthenticated user tries to access a protected page, the `RequireAuth` plug automatically appends `?return_to=/original/path` to the login redirect.
2. The login action stores the `return_to` value in a **signed cookie** (5-minute TTL). A signed cookie is used instead of the session because the session is cleared during the OAuth callback.
3. After successful authentication, the callback reads the cookie and redirects to the stored path.

#### Automatic with RequireAuth plug

If you use the `RequireAuth` plug for controller routes, `return_to` works automatically:

```elixir
pipeline :require_auth do
  plug SbAuthEx.Plugs.RequireAuth
end

scope "/admin", MyAppWeb do
  pipe_through [:browser, :require_auth]
  get "/dashboard", AdminController, :dashboard
end
```

A user visiting `/admin/dashboard` while logged out will be redirected to `/auth/login?return_to=%2Fadmin%2Fdashboard`, and after login they'll land on `/admin/dashboard`.

#### Manual usage

You can pass `return_to` manually when linking to the login page:

```heex
<a href={"/auth/login?return_to=#{URI.encode_www_form(@current_path)}"}>Sign in</a>
```

#### LiveView routes

The `require_authenticated` LiveView hook does not automatically set `return_to` because LiveView `on_mount` hooks don't have access to the request URI. For LiveView routes, you can handle this in your own hook:

```elixir
# In your app's custom on_mount hook
def on_mount(:require_registered, _params, session, socket) do
  # ... your identity check ...
  if !identity do
    current_uri = URI.encode_www_form(socket.assigns[:current_uri] || "/")

    socket =
      socket
      |> put_flash(:error, "You must be logged in.")
      |> redirect(to: "/auth/login?return_to=#{current_uri}")

    {:halt, socket}
  end
end
```

#### Security

- Only relative paths starting with `/` are accepted (prevents open redirect attacks)
- Protocol-relative URLs (`//evil.com`) are rejected
- The cookie is cryptographically signed (tamper-proof)
- The cookie expires after 5 minutes

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

### Account Deletion

SbAuthEx provides a built-in `DELETE /auth/account` endpoint that handles the full account deletion flow:

1. Fires the `on_delete_account` callback (so your app can clean up associated data). If the callback returns `{:error, reason}`, deletion is aborted and a 422 is returned.
2. Deletes the user from WorkOS (best-effort — failures are logged but don't block local deletion)
3. Deletes the local identity from `sb_identities`
4. Clears the session
5. Returns `{"deleted": true}` as JSON

The endpoint is idempotent — if the identity was already removed, it still returns `{"deleted": true}`.

#### Setup

The route is included automatically via `sb_auth_routes()`. You need to:

1. **Configure the callback** to clean up your app's data:

```elixir
# config/config.exs
config :sb_auth_ex,
  on_delete_account: {MyApp.Users, :on_delete_account}
```

2. **Implement the callback** to delete associated data:

```elixir
# lib/my_app/users.ex
def on_delete_account(identity, conn) do
  if identity.user_id do
    # Delete all app data for this user
    MyApp.Repo.delete_all(from u in MyApp.User, where: u.id == ^identity.user_id)
  end

  :ok
end
```

3. **Ensure the route is behind authentication** in your router:

```elixir
# The delete endpoint requires current_identity in conn.assigns.
# If called without authentication, it returns {"error": "Not authenticated"} with status 401.

# Ensure your pipeline runs FetchCurrentIdentity:
pipeline :authenticated do
  plug :fetch_session
  plug SbAuthEx.Plugs.FetchCurrentIdentity
end

scope "/auth" do
  pipe_through :authenticated
  # The delete "/account" route is already mounted by sb_auth_routes()
end
```

#### API Response

```
DELETE /auth/account

# Success (200) — also returned if identity was already deleted
{"deleted": true}

# Not authenticated (401)
{"error": "Not authenticated"}

# Callback aborted deletion (422)
{"error": "Cleanup failed: <reason>"}

# Server error (500)
{"error": "Failed to delete account"}
```

#### What Gets Deleted

| Data | Deleted by |
|------|-----------|
| App data (users, related records, etc.) | Your `on_delete_account` callback |
| Local identity (`sb_identities` row) | SbAuthEx automatically |
| WorkOS user | SbAuthEx automatically (best-effort) |
| Session | Your controller (after calling `SbAuthEx.delete_account/2`) |

#### Using from a Custom Controller (e.g., API with Bearer token auth)

The built-in `DELETE /auth/account` route uses session-based auth (browser pipeline). If your client uses a different auth mechanism (e.g., Bearer tokens), you can call `SbAuthEx.delete_account/2` directly from your own controller:

```elixir
# In your API controller
def delete_account(conn, _params) do
  identity = conn.assigns[:current_identity]

  case SbAuthEx.delete_account(identity, conn) do
    {:ok, :deleted} ->
      json(conn, %{deleted: true})

    {:error, {:cleanup_failed, reason}} ->
      conn |> put_status(422) |> json(%{error: "Cleanup failed: #{inspect(reason)}"})

    {:error, _reason} ->
      conn |> put_status(500) |> json(%{error: "Failed to delete account"})
  end
end
```

`SbAuthEx.delete_account/2` handles the full flow (callback + WorkOS deletion + identity cleanup) and returns:
- `{:ok, :deleted}` — success (also when identity was already gone)
- `{:error, {:cleanup_failed, reason}}` — `on_delete_account` callback returned `{:error, reason}`
- `{:error, reason}` — identity deletion failed

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

# Delete identity (low-level)
SbAuthEx.Accounts.delete_identity(identity)

# Delete account (full flow: callback + WorkOS + identity)
SbAuthEx.delete_account(identity, conn)
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

> **Note on `return_to`:** The `:require_authenticated` hook does not automatically set `return_to` because LiveView `on_mount` hooks don't have access to the full request URI. For `return_to` support in LiveView routes, see the [Redirect After Login](#redirect-after-login-return_to) section.

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

Requires authentication for controller routes. Redirects to login if not authenticated. Automatically passes the current request path as `return_to` so the user is redirected back after login.

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
