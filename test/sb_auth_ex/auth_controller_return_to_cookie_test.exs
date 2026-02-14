defmodule SbAuthEx.AuthControllerReturnToCookieTest do
  use ExUnit.Case, async: false

  alias SbAuthEx.AuthController

  @return_to_cookie "_sb_auth_return_to"

  setup do
    previous_workos_client = Application.get_env(:workos, WorkOS.Client)
    previous_workos = Application.get_env(:sb_auth_ex, :workos)

    client_config =
      (previous_workos_client || [])
      |> Keyword.put(:client_id, "client_test_123")

    Application.put_env(:workos, WorkOS.Client, client_config)
    Application.put_env(:sb_auth_ex, :workos, redirect_uri: "http://localhost/auth/callback")

    on_exit(fn ->
      restore_env(:workos, WorkOS.Client, previous_workos_client)
      restore_env(:sb_auth_ex, :workos, previous_workos)
    end)

    :ok
  end

  test "login without return_to clears stale return_to cookie" do
    conn =
      Phoenix.ConnTest.build_conn(:get, "/auth/login")
      |> Plug.Test.put_req_cookie(@return_to_cookie, "stale-cookie")
      |> AuthController.login(%{})

    assert conn.status == 302
    assert %{max_age: 0} = conn.resp_cookies[@return_to_cookie]
    assert [location] = Plug.Conn.get_resp_header(conn, "location")
    assert String.contains?(location, "/user_management/authorize?")
  end

  test "login with invalid return_to clears stale return_to cookie" do
    conn =
      Phoenix.ConnTest.build_conn(:get, "/auth/login")
      |> Plug.Test.put_req_cookie(@return_to_cookie, "stale-cookie")
      |> AuthController.login(%{"return_to" => "https://evil.example/admin"})

    assert conn.status == 302
    assert %{max_age: 0} = conn.resp_cookies[@return_to_cookie]
  end

  test "callback without code clears stale return_to cookie" do
    conn =
      Phoenix.ConnTest.build_conn(:get, "/auth/callback")
      |> Plug.Test.init_test_session(%{})
      |> Phoenix.Controller.fetch_flash([])
      |> Plug.Test.put_req_cookie(@return_to_cookie, "stale-cookie")
      |> AuthController.callback(%{})

    assert conn.status == 302
    assert %{max_age: 0} = conn.resp_cookies[@return_to_cookie]
    assert [location] = Plug.Conn.get_resp_header(conn, "location")
    assert location == SbAuthEx.after_logout_path()
  end

  test "login with valid return_to stores return_to cookie" do
    conn =
      Phoenix.ConnTest.build_conn(:get, "/auth/login")
      |> put_secret_key_base()
      |> AuthController.login(%{"return_to" => "/admin"})

    assert conn.status == 302
    assert %{max_age: 300} = conn.resp_cookies[@return_to_cookie]
  end

  defp put_secret_key_base(conn), do: %{conn | secret_key_base: String.duplicate("a", 64)}

  defp restore_env(app, key, nil), do: Application.delete_env(app, key)
  defp restore_env(app, key, value), do: Application.put_env(app, key, value)
end
