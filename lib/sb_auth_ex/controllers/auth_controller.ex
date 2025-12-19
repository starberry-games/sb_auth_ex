defmodule SbAuthEx.AuthController do
  @moduledoc """
  Handles WorkOS AuthKit authentication flow.
  """
  use Phoenix.Controller, formats: [:html]
  import Plug.Conn

  alias SbAuthEx.Accounts

  @doc """
  Initiates the AuthKit login flow by redirecting to WorkOS hosted UI.
  """
  def login(conn, _params) do
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
        |> put_flash(:error, "Authentication failed: #{inspect(reason)}")
        |> redirect(to: SbAuthEx.after_logout_path())
    end
  end

  def callback(conn, _params) do
    conn
    |> put_flash(:error, "Authentication failed: missing authorization code")
    |> redirect(to: SbAuthEx.after_logout_path())
  end

  defp extract_auth_data(%{user: user, access_token: token}), do: {user, token}

  @doc """
  Logs out the current user by clearing the session and redirecting to WorkOS logout.
  """
  def logout(conn, _params) do
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

    case Accounts.upsert_identity_from_provider!(user_id, email) do
      {:ok, identity} ->
        # Maybe auto-link to app user
        {:ok, identity} = Accounts.maybe_auto_link_by_email(identity)

        # Call optional callback
        maybe_call_on_login(identity)

        # Clear old session completely and set fresh values
        conn
        |> clear_session()
        |> put_session(:identity_id, identity.id)
        |> put_session(:workos_session_id, session_id)
        |> redirect(to: SbAuthEx.after_login_path())

      {:error, changeset} ->
        conn
        |> put_flash(:error, "Failed to create account: #{inspect(changeset.errors)}")
        |> redirect(to: SbAuthEx.after_logout_path())
    end
  end

  defp maybe_call_on_login(identity) do
    case Application.get_env(:sb_auth_ex, :on_login) do
      nil -> :ok
      {module, function} -> apply(module, function, [identity])
      fun when is_function(fun, 1) -> fun.(identity)
    end
  end

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
