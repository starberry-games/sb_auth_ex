defmodule SbAuthEx.AuthController do
  @moduledoc """
  Handles WorkOS AuthKit authentication flow.
  """
  use Phoenix.Controller, formats: [:html, :json]
  import Plug.Conn

  alias SbAuthEx.Accounts

  @return_to_cookie "_sb_auth_return_to"

  @doc """
  Initiates the AuthKit login flow by redirecting to WorkOS hosted UI.

  Accepts an optional `return_to` query parameter. If present, stores it in a
  signed cookie so the user can be redirected back after authentication.
  """
  def login(conn, params) do
    conn = store_return_to_cookie(conn, params)

    config = Application.get_env(:sb_auth_ex, :workos, [])
    redirect_uri = config[:redirect_uri]

    case WorkOS.UserManagement.get_authorization_url(%{
           provider: "authkit",
           redirect_uri: redirect_uri
         }) do
      {:ok, authorization_url} ->
        # Force account selection on every login to allow switching accounts
        url = authorization_url <> "&prompt=select_account"
        redirect(conn, external: url)

      {:error, reason} ->
        conn
        |> put_flash(:error, "Failed to initiate login: #{inspect(reason)}")
        |> redirect(to: SbAuthEx.after_logout_path())
    end
  end

  @doc """
  Handles the OAuth callback from WorkOS after user authentication.
  """
  def callback(conn, %{"code" => code}) do
    case WorkOS.UserManagement.authenticate_with_code(%{code: code}) do
      {:ok, auth} ->
        {user, access_token} = extract_auth_data(auth)
        handle_successful_auth(conn, user, access_token)

      {:error, reason} ->
        conn
        |> clear_return_to_cookie()
        |> put_flash(:error, "Authentication failed: #{inspect(reason)}")
        |> redirect(to: SbAuthEx.after_logout_path())
    end
  end

  def callback(conn, _params) do
    conn
    |> clear_return_to_cookie()
    |> put_flash(:error, "Authentication failed: missing authorization code")
    |> redirect(to: SbAuthEx.after_logout_path())
  end

  defp extract_auth_data(%{user: user, access_token: token}), do: {user, token}

  @doc """
  Logs out the current user by clearing the session and redirecting to WorkOS logout.

  Fires the `on_logout` callback (if configured) before clearing the session.
  """
  def logout(conn, _params) do
    # Fire on_logout callback while identity is still available
    maybe_call_on_logout(conn)

    session_id = get_session(conn, :workos_session_id)

    # Clear local session first
    conn = configure_session(conn, drop: true)

    # If we have a WorkOS session ID, get logout URL from WorkOS API
    if session_id do
      return_to = SbAuthEx.after_logout_path()
      # Build full URL
      endpoint = Application.get_env(:sb_auth_ex, :endpoint)
      full_return_to = if endpoint, do: endpoint.url() <> return_to, else: return_to

      case get_workos_logout_url(session_id, full_return_to) do
        {:ok, logout_url} ->
          redirect(conn, external: logout_url)

        {:error, _reason} ->
          conn
          |> put_flash(:info, "You have been logged out.")
          |> redirect(to: SbAuthEx.after_logout_path())
      end
    else
      conn
      |> put_flash(:info, "You have been logged out.")
      |> redirect(to: SbAuthEx.after_logout_path())
    end
  end

  @doc """
  Deletes the current user's account.

  Requires `current_identity` in conn assigns. Fires the `on_delete_account`
  callback before deletion so the consuming app can clean up associated data.
  The callback should return `:ok` to proceed with deletion, or
  `{:error, reason}` to abort. Any other return value proceeds.
  The endpoint is idempotent: returns `{"deleted": true}` even if
  the identity was already removed.
  Deletes the WorkOS user (best-effort), then deletes the local identity,
  clears the session, and returns JSON `{"deleted": true}`.
  """
  def delete_account(conn, _params) do
    identity = conn.assigns[:current_identity]

    if identity do
      case maybe_call_on_delete_account(conn, identity) do
        {:error, reason} ->
          conn
          |> put_status(422)
          |> json(%{error: "Cleanup failed: #{inspect(reason)}"})

        _ ->
          delete_workos_user(identity.sb_id)

          case Accounts.delete_identity(identity) do
            {:ok, _deleted} ->
              conn
              |> configure_session(drop: true)
              |> put_status(200)
              |> json(%{deleted: true})

            {:error, :already_deleted} ->
              conn
              |> configure_session(drop: true)
              |> put_status(200)
              |> json(%{deleted: true})

            {:error, _reason} ->
              conn
              |> put_status(500)
              |> json(%{error: "Failed to delete account"})
          end
      end
    else
      conn
      |> put_status(401)
      |> json(%{error: "Not authenticated"})
    end
  end

  defp delete_workos_user(workos_user_id) do
    config = Application.get_env(:workos, WorkOS.Client)
    api_key = config[:api_key]

    url = "https://api.workos.com/user_management/users/#{workos_user_id}"

    case Req.delete(url,
           headers: [{"Authorization", "Bearer #{api_key}"}]
         ) do
      {:ok, %{status: status}} when status in [200, 204] ->
        :ok

      {:ok, %{status: status, body: body}} ->
        require Logger
        Logger.warning("Failed to delete WorkOS user #{workos_user_id}: HTTP #{status} #{inspect(body)}")
        {:error, {:http_error, status, body}}

      {:error, reason} ->
        require Logger
        Logger.warning("Failed to delete WorkOS user #{workos_user_id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp maybe_call_on_delete_account(conn, identity) do
    case Application.get_env(:sb_auth_ex, :on_delete_account) do
      nil -> :ok
      {module, function} -> apply(module, function, [identity, conn])
      fun when is_function(fun, 2) -> fun.(identity, conn)
    end
  end

  defp get_workos_logout_url(session_id, return_to) do
    config = Application.get_env(:workos, WorkOS.Client)
    api_key = config[:api_key]

    url = "https://api.workos.com/user_management/sessions/logout"

    case Req.get(url,
           params: [session_id: session_id, return_to: return_to],
           headers: [{"Authorization", "Bearer #{api_key}"}]
         ) do
      {:ok, %{status: 200, body: %{"url" => logout_url}}} ->
        {:ok, logout_url}

      {:ok, %{status: status, body: body}} ->
        {:error, {:http_error, status, body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp handle_successful_auth(conn, workos_user, access_token) do
    # WorkOS returns user as a map with string keys
    user_id = workos_user["id"] || workos_user[:id]
    email = workos_user["email"] || workos_user[:email]

    # Extract session_id from JWT access token
    session_id = extract_session_id(access_token)

    # Check if this is a new user BEFORE the upsert
    is_new_user = is_nil(Accounts.get_identity_by_sb_id(user_id))

    case Accounts.upsert_identity_from_provider!(user_id, email) do
      {:ok, identity} ->
        # For new users: fire on_register first, then on_login
        if is_new_user, do: maybe_call_on_register(conn, identity)
        maybe_call_on_login(conn, identity)

        {conn, redirect_to} = consume_return_to_cookie(conn)

        # Clear old session completely and set fresh values
        conn
        |> clear_session()
        |> put_session(:identity_id, identity.id)
        |> put_session(:workos_session_id, session_id)
        |> redirect(to: redirect_to)

      {:error, changeset} ->
        conn
        |> clear_return_to_cookie()
        |> put_flash(:error, "Failed to create account: #{inspect(changeset.errors)}")
        |> redirect(to: SbAuthEx.after_logout_path())
    end
  end

  defp maybe_call_on_login(conn, identity) do
    case Application.get_env(:sb_auth_ex, :on_login) do
      nil -> :ok
      {module, function} -> apply(module, function, [identity, conn])
      fun when is_function(fun, 2) -> fun.(identity, conn)
    end
  end

  defp maybe_call_on_register(conn, identity) do
    case Application.get_env(:sb_auth_ex, :on_register) do
      nil -> :ok
      {module, function} -> apply(module, function, [identity, conn])
      fun when is_function(fun, 2) -> fun.(identity, conn)
    end
  end

  defp maybe_call_on_logout(conn) do
    identity = conn.assigns[:current_identity]

    if identity do
      case Application.get_env(:sb_auth_ex, :on_logout) do
        nil -> :ok
        {module, function} -> apply(module, function, [identity, conn])
        fun when is_function(fun, 2) -> fun.(identity, conn)
      end
    end
  end

  defp store_return_to_cookie(conn, %{"return_to" => return_to})
       when is_binary(return_to) do
    if valid_return_to?(return_to) do
      put_resp_cookie(conn, @return_to_cookie, return_to,
        sign: true,
        max_age: 300,
        http_only: true,
        same_site: "Lax"
      )
    else
      clear_return_to_cookie(conn)
    end
  end

  defp store_return_to_cookie(conn, _params), do: clear_return_to_cookie(conn)

  defp consume_return_to_cookie(conn) do
    conn = fetch_cookies(conn, signed: [@return_to_cookie])
    return_to = conn.cookies[@return_to_cookie]
    conn = clear_return_to_cookie(conn)

    redirect_to =
      if valid_return_to?(return_to) do
        return_to
      else
        SbAuthEx.after_login_path()
      end

    {conn, redirect_to}
  end

  defp clear_return_to_cookie(conn), do: delete_resp_cookie(conn, @return_to_cookie)

  defp valid_return_to?(return_to) when is_binary(return_to) do
    String.starts_with?(return_to, "/") and not String.starts_with?(return_to, "//")
  end

  defp valid_return_to?(_return_to), do: false

  defp extract_session_id(nil), do: nil

  defp extract_session_id(access_token) do
    # JWT is base64 encoded: header.payload.signature
    case String.split(access_token, ".") do
      [_header, payload, _signature] ->
        case Base.url_decode64(payload, padding: false) do
          {:ok, json} ->
            case Jason.decode(json) do
              {:ok, claims} -> claims["sid"]
              _ -> nil
            end

          _ ->
            nil
        end

      _ ->
        nil
    end
  end
end
