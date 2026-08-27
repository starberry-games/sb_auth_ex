defmodule SbAuthEx.AuthController do
  @moduledoc """
  Handles the authentication flow for the configured `SbAuthEx.Provider`
  (WorkOS AuthKit by default, or a generic OIDC issuer).

  ## Login CSRF protection

  `login/2` starts an OAuth authorization-code flow with **PKCE** and a random
  **`state`** (plus a **`nonce`** for providers that use one). The `state`,
  PKCE `code_verifier` and `nonce` are parked in a short-lived, encrypted,
  `HttpOnly` cookie bound to the browser that started the login.

  `callback/2` refuses to exchange the authorization code unless the `state`
  query parameter matches the cookie (compared with
  `Plug.Crypto.secure_compare/2`). Without this check an attacker could hand a
  victim their own `?code=` and have the victim's session bound to the
  attacker's account (login CSRF). The `code_verifier` is then sent along with
  the code, so a leaked code alone cannot be redeemed.

  The cookie — rather than the Phoenix session — is used for the same reason as
  the `return_to` cookie: it is explicitly `SameSite=Lax`, so it survives the
  cross-site redirect back from the provider regardless of how the host app
  configured its session cookie.
  """
  use Phoenix.Controller, formats: [:html, :json]
  import Plug.Conn

  alias SbAuthEx.Accounts
  alias SbAuthEx.Provider

  @return_to_cookie "_sb_auth_return_to"
  @oauth_cookie "_sb_auth_oauth"
  @oauth_cookie_max_age 600

  @doc """
  Initiates the login flow by redirecting to the provider's hosted UI.

  Accepts an optional `return_to` query parameter. If present, stores it in a
  signed cookie so the user can be redirected back after authentication.

  Mints a fresh `state` + PKCE pair (and `nonce`, when the provider uses one)
  for this login attempt and stores them in an encrypted cookie for
  `callback/2` to verify.
  """
  def login(conn, params) do
    conn = store_return_to_cookie(conn, params)

    case Provider.current().authorize() do
      {:ok, %{url: url} = authorization} ->
        conn
        |> store_oauth_cookie(authorization)
        |> redirect(external: url)

      # Runtime failure building the redirect (e.g. the issuer's discovery
      # endpoint unreachable) — flash instead of 500ing the login page.
      {:error, reason} ->
        conn
        |> clear_return_to_cookie()
        |> put_flash(:error, failure_message(reason))
        |> redirect(to: SbAuthEx.after_logout_path())
    end
  end

  @doc """
  Handles the OAuth callback from the provider after user authentication.

  Verifies the `state` parameter against the value minted by `login/2` before
  exchanging the authorization code. Any mismatch — missing cookie, missing
  or wrong `state` — aborts the login without contacting the provider.
  """
  def callback(conn, params) do
    {conn, expected} = consume_oauth_cookie(conn)

    with :ok <- check_provider_error(params),
         {:ok, code} <- fetch_code(params),
         {:ok, ctx} <- verify_state(expected, params["state"]),
         {:ok, auth} <- Provider.current().exchange_code(code, ctx) do
      handle_successful_auth(conn, auth)
    else
      {:error, reason} ->
        conn
        |> clear_return_to_cookie()
        |> put_flash(:error, failure_message(reason))
        |> redirect(to: SbAuthEx.after_logout_path())
    end
  end

  @doc """
  Logs out the current user by clearing the session, and redirecting through
  the provider's logout endpoint when the provider has a session to end.

  Fires the `on_logout` callback (if configured) before clearing the session.
  """
  def logout(conn, _params) do
    # Fire on_logout callback while identity is still available
    maybe_call_on_logout(conn)

    session_id = get_session(conn, :workos_session_id)

    # Clear local session first
    conn = configure_session(conn, drop: true)

    return_to = SbAuthEx.after_logout_path()

    # Only touch endpoint.url() when there is a provider session to end —
    # it raises when the endpoint is not running (shutdown, worker-only nodes).
    provider_logout =
      if session_id do
        endpoint = Application.get_env(:sb_auth_ex, :endpoint)
        full_return_to = if endpoint, do: endpoint.url() <> return_to, else: return_to
        Provider.current().logout_url(session_id, full_return_to)
      else
        :none
      end

    case provider_logout do
      {:ok, logout_url} ->
        redirect(conn, external: logout_url)

      :none ->
        conn
        |> put_flash(:info, "You have been logged out.")
        |> redirect(to: return_to)
    end
  end

  @doc """
  Deletes the current user's account.

  Requires `current_identity` in conn assigns. Delegates to `SbAuthEx.delete_account/2`
  for the full deletion flow (provider, callback, identity cleanup).
  If provider-side deletion fails, it returns 502 without running application
  cleanup, deleting the local identity, or dropping the session.
  """
  def delete_account(conn, _params) do
    identity = conn.assigns[:current_identity]

    if identity do
      case SbAuthEx.delete_account(identity, conn) do
        {:ok, :deleted} ->
          conn
          |> configure_session(drop: true)
          |> put_status(200)
          |> json(%{deleted: true})

        {:error, {:cleanup_failed, reason}} ->
          conn
          |> put_status(422)
          |> json(%{error: "Cleanup failed: #{inspect(reason)}"})

        {:error, {:workos_delete_failed, _reason}} ->
          conn
          |> put_status(502)
          |> json(%{error: "Failed to delete account"})

        {:error, _reason} ->
          conn
          |> put_status(500)
          |> json(%{error: "Failed to delete account"})
      end
    else
      conn
      |> put_status(401)
      |> json(%{error: "Not authenticated"})
    end
  end

  # ---------------------------------------------------------------------------
  # Callback steps
  # ---------------------------------------------------------------------------

  # Providers report user-facing failures (cancelled login, denied access, ...)
  # as ?error=...&error_description=... instead of ?code=...
  defp check_provider_error(%{"error" => error} = params) when is_binary(error) do
    {:error, {:provider_error, error, params["error_description"]}}
  end

  defp check_provider_error(_params), do: :ok

  defp fetch_code(%{"code" => code}) when is_binary(code) and code != "", do: {:ok, code}
  defp fetch_code(_params), do: {:error, :missing_code}

  defp verify_state(%{state: expected, code_verifier: code_verifier} = cookie, provided)
       when is_binary(expected) and is_binary(provided) do
    if Plug.Crypto.secure_compare(expected, provided) do
      {:ok, %{code_verifier: code_verifier, nonce: Map.get(cookie, :nonce)}}
    else
      {:error, :invalid_state}
    end
  end

  defp verify_state(nil, _provided), do: {:error, :missing_oauth_cookie}
  defp verify_state(_expected, _provided), do: {:error, :missing_state}

  defp failure_message({:provider_error, error, description}) do
    "Authentication failed: #{description || error}"
  end

  defp failure_message(:missing_code),
    do: "Authentication failed: missing authorization code"

  defp failure_message(reason)
       when reason in [:invalid_state, :missing_state, :missing_oauth_cookie] do
    "Authentication failed: invalid or expired login request. Please try again."
  end

  defp failure_message(:invalid_user_payload),
    do: "Authentication failed: unexpected response from the identity provider"

  defp failure_message(reason)
       when reason in [
              :invalid_signature,
              :invalid_issuer,
              :invalid_audience,
              :token_expired,
              :token_not_yet_valid,
              :missing_expiry,
              :unknown_signing_key,
              :malformed_token,
              :invalid_nonce,
              :missing_id_token,
              :subject_mismatch,
              :missing_subject
            ] or
              (is_tuple(reason) and elem(reason, 0) == :disallowed_alg) do
    "Authentication failed: the identity provider returned an invalid token"
  end

  defp failure_message(:missing_email),
    do: "Authentication failed: the identity provider did not supply an email address"

  defp failure_message({:token_endpoint_error, status, _body}),
    do: "Authentication failed: the identity provider rejected the login (HTTP #{status})"

  # WorkOS API errors carry a user-appropriate message from the API itself
  # (e.g. "The code has expired"); every other exception (transport errors,
  # decode errors) would echo internal detail and falls through to the
  # generic clause below.
  defp failure_message(%WorkOS.ApiError{} = error),
    do: "Authentication failed: #{Exception.message(error)}"

  # Everything else (discovery/JWKS/userinfo transport failures, malformed
  # provider responses, unexpected exceptions, ...) — log the real term
  # server-side, keep internal details (hostnames, error structs) out of the
  # user-visible flash.
  defp failure_message(reason) do
    require Logger
    Logger.warning("SbAuthEx: authentication failed: #{inspect(reason)}")
    "Authentication failed: could not reach the identity provider. Please try again."
  end

  defp handle_successful_auth(conn, %SbAuthEx.Auth{sb_id: sb_id, email: email} = auth) do
    # Check if this is a new user BEFORE the upsert
    is_new_user = is_nil(Accounts.get_identity_by_sb_id(sb_id))

    case Accounts.upsert_identity_from_provider!(sb_id, email) do
      {:ok, identity} ->
        # For new users: fire on_register first, then on_login
        if is_new_user, do: maybe_call_on_register(conn, identity)
        maybe_call_on_login(conn, identity)

        {conn, redirect_to} = consume_return_to_cookie(conn)

        # Clear old session completely and set fresh values
        conn
        |> clear_session()
        |> put_session(:identity_id, identity.id)
        |> put_session(:workos_session_id, auth.session_id)
        |> redirect(to: redirect_to)

      {:error, changeset} ->
        conn
        |> clear_return_to_cookie()
        |> put_flash(:error, "Failed to create account: #{inspect(changeset.errors)}")
        |> redirect(to: SbAuthEx.after_logout_path())
    end
  end

  # ---------------------------------------------------------------------------
  # Lifecycle callbacks
  # ---------------------------------------------------------------------------

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

  # ---------------------------------------------------------------------------
  # OAuth state / PKCE cookie
  # ---------------------------------------------------------------------------

  defp store_oauth_cookie(conn, %{state: state, code_verifier: code_verifier} = authorization) do
    value = %{state: state, code_verifier: code_verifier, nonce: authorization[:nonce]}

    put_resp_cookie(conn, @oauth_cookie, value,
      encrypt: true,
      max_age: @oauth_cookie_max_age,
      http_only: true,
      same_site: "Lax"
    )
  end

  # Reads and immediately invalidates the oauth cookie: each login attempt is
  # redeemable exactly once.
  defp consume_oauth_cookie(conn) do
    conn = fetch_cookies(conn, encrypted: [@oauth_cookie])

    expected =
      case conn.cookies[@oauth_cookie] do
        %{state: state, code_verifier: _code_verifier} = cookie when is_binary(state) ->
          cookie

        _ ->
          nil
      end

    {delete_resp_cookie(conn, @oauth_cookie), expected}
  end

  # ---------------------------------------------------------------------------
  # return_to cookie
  # ---------------------------------------------------------------------------

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
end
