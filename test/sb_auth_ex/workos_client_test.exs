defmodule SbAuthEx.WorkOSClientTest do
  use ExUnit.Case, async: false

  alias SbAuthEx.WorkOSClient

  setup do
    previous_workos = Application.get_env(:sb_auth_ex, :workos)
    previous_legacy = Application.get_env(:workos, WorkOS.Client)
    previous_api_key_env = System.get_env("WORKOS_API_KEY")
    previous_client_id_env = System.get_env("WORKOS_CLIENT_ID")

    Application.delete_env(:sb_auth_ex, :workos)
    Application.delete_env(:workos, WorkOS.Client)
    System.delete_env("WORKOS_API_KEY")
    System.delete_env("WORKOS_CLIENT_ID")

    on_exit(fn ->
      restore_env(:sb_auth_ex, :workos, previous_workos)
      restore_env(:workos, WorkOS.Client, previous_legacy)
      restore_sys_env("WORKOS_API_KEY", previous_api_key_env)
      restore_sys_env("WORKOS_CLIENT_ID", previous_client_id_env)
    end)

    :ok
  end

  test "builds the client from config :sb_auth_ex, :workos" do
    Application.put_env(:sb_auth_ex, :workos,
      api_key: "sk_a",
      client_id: "client_a",
      redirect_uri: "http://localhost/auth/callback",
      base_url: "https://workos.example.test/",
      timeout: 1234
    )

    client = WorkOSClient.client()

    assert %WorkOS.Client{api_key: "sk_a", client_id: "client_a", timeout: 1234} = client
    assert client.base_url == "https://workos.example.test"
    assert WorkOSClient.redirect_uri() == "http://localhost/auth/callback"
  end

  test "falls back to the legacy config :workos, WorkOS.Client for api_key and client_id" do
    Application.put_env(:workos, WorkOS.Client, api_key: "sk_legacy", client_id: "client_legacy")
    Application.put_env(:sb_auth_ex, :workos, redirect_uri: "http://localhost/auth/callback")

    assert %WorkOS.Client{api_key: "sk_legacy", client_id: "client_legacy"} =
             WorkOSClient.client()
  end

  test "sb_auth_ex config takes precedence over legacy config, key by key" do
    Application.put_env(:workos, WorkOS.Client, api_key: "sk_legacy", client_id: "client_legacy")
    Application.put_env(:sb_auth_ex, :workos, client_id: "client_new")

    assert %WorkOS.Client{api_key: "sk_legacy", client_id: "client_new"} = WorkOSClient.client()
  end

  test "falls back to WORKOS_API_KEY / WORKOS_CLIENT_ID environment variables" do
    System.put_env("WORKOS_API_KEY", "sk_env")
    System.put_env("WORKOS_CLIENT_ID", "client_env")

    assert %WorkOS.Client{api_key: "sk_env", client_id: "client_env"} = WorkOSClient.client()
  end

  test "raises when no API key can be found" do
    Application.put_env(:sb_auth_ex, :workos, client_id: "client_a")

    assert_raise WorkOS.ConfigurationError, ~r/Missing API key/, fn -> WorkOSClient.client() end
  end

  test "raises when no client ID can be found" do
    Application.put_env(:sb_auth_ex, :workos, api_key: "sk_a")

    assert_raise ArgumentError, ~r/missing WorkOS client ID/, fn -> WorkOSClient.client() end
  end

  test "raises when redirect_uri is not configured" do
    assert_raise ArgumentError, ~r/missing WorkOS redirect URI/, fn ->
      WorkOSClient.redirect_uri()
    end
  end

  defp restore_env(app, key, nil), do: Application.delete_env(app, key)
  defp restore_env(app, key, value), do: Application.put_env(app, key, value)

  defp restore_sys_env(name, nil), do: System.delete_env(name)
  defp restore_sys_env(name, value), do: System.put_env(name, value)
end
