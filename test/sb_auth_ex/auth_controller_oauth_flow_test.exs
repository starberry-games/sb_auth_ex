defmodule SbAuthEx.AuthControllerOAuthFlowTest do
  @moduledoc """
  End-to-end tests for the login -> callback -> logout flow against a stubbed
  WorkOS API (via `Req.Test`), with a focus on the login-CSRF protection:
  the callback must refuse to redeem a code unless the `state` matches the
  value minted by `login/2` for this browser.
  """
  use ExUnit.Case, async: false

  alias SbAuthEx.AuthController
  alias SbAuthEx.FakeRepo

  @oauth_cookie "_sb_auth_oauth"
  @return_to_cookie "_sb_auth_return_to"
  @redirect_uri "http://localhost/auth/callback"
  @secret_key_base String.duplicate("a", 64)

  # A syntactically valid JWT whose payload is {"sid":"session_01TEST"}.
  @access_token "eyJhbGciOiJSUzI1NiJ9." <>
                  Base.url_encode64(~s({"sid":"session_01TEST"}), padding: false) <>
                  ".sig"

  setup do
    previous = %{
      workos: Application.get_env(:sb_auth_ex, :workos),
      workos_client: Application.get_env(:workos, WorkOS.Client),
      repo: Application.get_env(:sb_auth_ex, :repo),
      on_login: Application.get_env(:sb_auth_ex, :on_login),
      on_register: Application.get_env(:sb_auth_ex, :on_register)
    }

    Application.put_env(:sb_auth_ex, :workos,
      api_key: "sk_test_123",
      client_id: "client_test_123",
      redirect_uri: @redirect_uri,
      req_options: [plug: {Req.Test, SbAuthEx.WorkOSStub}]
    )

    Application.delete_env(:workos, WorkOS.Client)
    Application.put_env(:sb_auth_ex, :repo, FakeRepo)
    Application.delete_env(:sb_auth_ex, :on_login)
    Application.delete_env(:sb_auth_ex, :on_register)
    FakeRepo.reset()

    # Default stub: any request to WorkOS is a test failure. Tests that expect
    # a token exchange override this with their own stub.
    test_pid = self()

    Req.Test.stub(SbAuthEx.WorkOSStub, fn conn ->
      send(test_pid, {:unexpected_workos_request, conn.method, conn.request_path})
      Req.Test.json(Plug.Conn.put_status(conn, 500), %{"message" => "unexpected request"})
    end)

    on_exit(fn ->
      restore_env(:sb_auth_ex, :workos, previous.workos)
      restore_env(:workos, WorkOS.Client, previous.workos_client)
      restore_env(:sb_auth_ex, :repo, previous.repo)
      restore_env(:sb_auth_ex, :on_login, previous.on_login)
      restore_env(:sb_auth_ex, :on_register, previous.on_register)
    end)

    :ok
  end

  describe "login/2" do
    test "redirects to the AuthKit authorize URL with state and PKCE challenge" do
      conn = login()

      assert conn.status == 302
      assert [location] = Plug.Conn.get_resp_header(conn, "location")

      uri = URI.parse(location)
      assert uri.host == "api.workos.com"
      assert uri.path == "/user_management/authorize"

      query = URI.decode_query(uri.query)
      assert query["client_id"] == "client_test_123"
      assert query["redirect_uri"] == @redirect_uri
      assert query["provider"] == "authkit"
      assert query["response_type"] == "code"
      assert query["prompt"] == "select_account"
      assert query["code_challenge_method"] == "S256"
      assert is_binary(query["code_challenge"]) and query["code_challenge"] != ""
      assert is_binary(query["state"]) and byte_size(query["state"]) >= 32
    end

    test "stores state and code_verifier in an encrypted, short-lived, HttpOnly cookie" do
      conn = login()
      state = conn |> authorize_query() |> Map.fetch!("state")

      assert %{value: value, max_age: 600, http_only: true, same_site: "Lax"} =
               conn.resp_cookies[@oauth_cookie]

      # The raw cookie must not leak the state or verifier in cleartext.
      refute String.contains?(value, state)

      assert %{state: ^state, code_verifier: verifier} = decrypt_cookie(value)
      assert byte_size(verifier) >= 43
    end

    test "mints a fresh state for every login attempt" do
      state_a = login() |> authorize_query() |> Map.fetch!("state")
      state_b = login() |> authorize_query() |> Map.fetch!("state")

      assert state_a != state_b
    end

    test "raises a clear error when the WorkOS API key is missing" do
      Application.put_env(:sb_auth_ex, :workos,
        client_id: "client_test_123",
        redirect_uri: @redirect_uri
      )

      System.delete_env("WORKOS_API_KEY")

      assert_raise WorkOS.ConfigurationError, ~r/Missing API key/, fn -> login() end
    end
  end

  describe "callback/2 — login CSRF protection" do
    test "refuses a callback that carries no oauth cookie (login not started here)" do
      conn = callback(%{"code" => "code_attacker", "state" => "whatever"}, cookie: nil)

      assert_refused(conn)
      refute_received {:unexpected_workos_request, _, _}
    end

    test "refuses a callback without a state parameter" do
      %{cookie: cookie} = login_state()

      conn = callback(%{"code" => "code_attacker"}, cookie: cookie)

      assert_refused(conn)
      refute_received {:unexpected_workos_request, _, _}
    end

    test "refuses a callback whose state does not match the one minted at login" do
      %{cookie: cookie} = login_state()

      conn = callback(%{"code" => "code_attacker", "state" => "forged-state"}, cookie: cookie)

      assert_refused(conn)
      refute_received {:unexpected_workos_request, _, _}
    end

    test "refuses a state minted for a different browser" do
      %{cookie: cookie_victim} = login_state()
      %{state: state_attacker} = login_state()

      conn =
        callback(%{"code" => "code_attacker", "state" => state_attacker}, cookie: cookie_victim)

      assert_refused(conn)
      refute_received {:unexpected_workos_request, _, _}
    end

    test "refuses a callback without a code and clears the return_to cookie" do
      %{cookie: cookie, state: state} = login_state()

      conn =
        callback(%{"state" => state}, cookie: cookie, return_to_cookie: "stale")

      assert conn.status == 302
      assert [location] = Plug.Conn.get_resp_header(conn, "location")
      assert location == SbAuthEx.after_logout_path()
      assert %{max_age: 0} = conn.resp_cookies[@return_to_cookie]
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "missing authorization code"
      refute_received {:unexpected_workos_request, _, _}
    end

    test "surfaces a provider error (e.g. user cancelled) without exchanging anything" do
      %{cookie: cookie, state: state} = login_state()

      conn =
        callback(
          %{
            "error" => "access_denied",
            "error_description" => "User cancelled",
            "state" => state
          },
          cookie: cookie
        )

      assert conn.status == 302
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "User cancelled"
      refute_received {:unexpected_workos_request, _, _}
    end

    test "the oauth cookie is consumed on every callback, matching or not" do
      %{cookie: cookie} = login_state()

      conn = callback(%{"code" => "x", "state" => "nope"}, cookie: cookie)

      assert %{max_age: 0} = conn.resp_cookies[@oauth_cookie]
    end
  end

  describe "callback/2 — happy path" do
    test "exchanges the code with the PKCE verifier and signs the user in" do
      %{cookie: cookie, state: state, code_verifier: code_verifier} = login_state()
      test_pid = self()

      Req.Test.stub(SbAuthEx.WorkOSStub, fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        send(test_pid, {:workos_request, conn.method, conn.request_path, Jason.decode!(body)})

        Req.Test.json(conn, %{
          "user" => %{
            "object" => "user",
            "id" => "user_01TEST",
            "email" => "ada@example.com",
            "email_verified" => true,
            "created_at" => "2026-01-01T00:00:00.000Z",
            "updated_at" => "2026-01-01T00:00:00.000Z"
          },
          "access_token" => @access_token,
          "refresh_token" => "rt_test"
        })
      end)

      conn = callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert_received {:workos_request, "POST", "/user_management/authenticate", body}
      assert body["code"] == "code_ok"
      assert body["code_verifier"] == code_verifier
      assert body["grant_type"] == "authorization_code"
      assert body["client_id"] == "client_test_123"

      assert conn.status == 302
      assert [location] = Plug.Conn.get_resp_header(conn, "location")
      assert location == SbAuthEx.after_login_path()

      assert [%{sb_id: "user_01TEST", email: "ada@example.com", id: identity_id}] =
               FakeRepo.all_identities()

      assert Plug.Conn.get_session(conn, :identity_id) == identity_id
      assert Plug.Conn.get_session(conn, :workos_session_id) == "session_01TEST"
      assert %{max_age: 0} = conn.resp_cookies[@oauth_cookie]
    end

    test "fires on_register then on_login for a new user, and honours return_to" do
      %{cookie: cookie, state: state} = login_state(%{"return_to" => "/admin"})
      test_pid = self()

      Application.put_env(:sb_auth_ex, :on_register, fn identity, _conn ->
        send(test_pid, {:on_register, identity.sb_id})
      end)

      Application.put_env(:sb_auth_ex, :on_login, fn identity, _conn ->
        send(test_pid, {:on_login, identity.sb_id})
      end)

      Req.Test.stub(SbAuthEx.WorkOSStub, fn conn ->
        Req.Test.json(conn, %{
          "user" => %{"id" => "user_01NEW", "email" => "new@example.com"},
          "access_token" => @access_token
        })
      end)

      conn =
        callback(%{"code" => "code_ok", "state" => state},
          cookie: cookie,
          return_to_cookie: signed_return_to("/admin")
        )

      assert [location] = Plug.Conn.get_resp_header(conn, "location")
      assert location == "/admin"

      assert_received {:on_register, "user_01NEW"}
      assert_received {:on_login, "user_01NEW"}
    end

    test "a WorkOS API error on the exchange is reported, not crashed on" do
      %{cookie: cookie, state: state} = login_state()

      Req.Test.stub(SbAuthEx.WorkOSStub, fn conn ->
        conn
        |> Plug.Conn.put_status(400)
        |> Req.Test.json(%{"code" => "invalid_grant", "message" => "The code has expired"})
      end)

      conn = callback(%{"code" => "code_expired", "state" => state}, cookie: cookie)

      assert conn.status == 302
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "The code has expired"
      assert FakeRepo.all_identities() == []
    end
  end

  describe "logout/2" do
    test "redirects through the WorkOS logout URL when a WorkOS session id is known" do
      conn =
        Phoenix.ConnTest.build_conn(:delete, "/auth/logout")
        |> Plug.Test.init_test_session(%{identity_id: 1, workos_session_id: "session_01TEST"})
        |> Phoenix.Controller.fetch_flash([])
        |> AuthController.logout(%{})

      assert conn.status == 302
      assert [location] = Plug.Conn.get_resp_header(conn, "location")

      uri = URI.parse(location)
      assert uri.host == "api.workos.com"
      assert uri.path == "/user_management/sessions/logout"

      assert %{"session_id" => "session_01TEST", "return_to" => return_to} =
               URI.decode_query(uri.query)

      assert return_to == SbAuthEx.after_logout_path()
      # No API call is made: the logout URL is built locally.
      refute_received {:unexpected_workos_request, _, _}
    end

    test "redirects locally when there is no WorkOS session id" do
      conn =
        Phoenix.ConnTest.build_conn(:delete, "/auth/logout")
        |> Plug.Test.init_test_session(%{})
        |> Phoenix.Controller.fetch_flash([])
        |> AuthController.logout(%{})

      assert conn.status == 302
      assert [location] = Plug.Conn.get_resp_header(conn, "location")
      assert location == SbAuthEx.after_logout_path()
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp login(params \\ %{}) do
    Phoenix.ConnTest.build_conn(:get, "/auth/login")
    |> put_secret_key_base()
    |> AuthController.login(params)
  end

  # Performs a login and returns what the browser would hold afterwards.
  defp login_state(params \\ %{}) do
    conn = login(params)
    %{value: cookie} = conn.resp_cookies[@oauth_cookie]
    %{state: state, code_verifier: verifier} = decrypt_cookie(cookie)
    %{cookie: cookie, state: state, code_verifier: verifier}
  end

  defp callback(params, opts) do
    conn =
      Phoenix.ConnTest.build_conn(:get, "/auth/callback")
      |> put_secret_key_base()
      |> Plug.Test.init_test_session(%{})
      |> Phoenix.Controller.fetch_flash([])

    conn =
      case opts[:cookie] do
        nil -> conn
        cookie -> Plug.Test.put_req_cookie(conn, @oauth_cookie, cookie)
      end

    conn =
      case opts[:return_to_cookie] do
        nil -> conn
        value -> Plug.Test.put_req_cookie(conn, @return_to_cookie, value)
      end

    AuthController.callback(conn, params)
  end

  defp assert_refused(conn) do
    assert conn.status == 302
    assert [location] = Plug.Conn.get_resp_header(conn, "location")
    assert location == SbAuthEx.after_logout_path()
    assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "invalid or expired login request"
    assert Plug.Conn.get_session(conn, :identity_id) == nil
    assert FakeRepo.all_identities() == []
  end

  defp authorize_query(conn) do
    [location] = Plug.Conn.get_resp_header(conn, "location")
    location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
  end

  defp decrypt_cookie(value) do
    conn =
      Phoenix.ConnTest.build_conn(:get, "/")
      |> put_secret_key_base()
      |> Plug.Test.put_req_cookie(@oauth_cookie, value)
      |> Plug.Conn.fetch_cookies(encrypted: [@oauth_cookie])

    conn.cookies[@oauth_cookie]
  end

  defp signed_return_to(path) do
    conn =
      Phoenix.ConnTest.build_conn(:get, "/")
      |> put_secret_key_base()
      |> Plug.Conn.put_resp_cookie(@return_to_cookie, path, sign: true)

    conn.resp_cookies[@return_to_cookie].value
  end

  defp put_secret_key_base(conn), do: %{conn | secret_key_base: @secret_key_base}

  defp restore_env(app, key, nil), do: Application.delete_env(app, key)
  defp restore_env(app, key, value), do: Application.put_env(app, key, value)
end
