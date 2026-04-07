defmodule SbAuthEx.AuthControllerDeleteAccountTest do
  use ExUnit.Case, async: false

  alias SbAuthEx.AuthController

  setup do
    previous_on_delete = Application.get_env(:sb_auth_ex, :on_delete_account)

    on_exit(fn ->
      restore_env(:sb_auth_ex, :on_delete_account, previous_on_delete)
    end)

    :ok
  end

  test "returns 401 JSON when not authenticated" do
    conn =
      Phoenix.ConnTest.build_conn(:delete, "/auth/account")
      |> Plug.Test.init_test_session(%{})
      |> Plug.Conn.assign(:current_identity, nil)
      |> AuthController.delete_account(%{})

    assert conn.status == 401
    assert Jason.decode!(conn.resp_body) == %{"error" => "Not authenticated"}
  end

  test "returns 401 JSON when current_identity is missing from assigns" do
    conn =
      Phoenix.ConnTest.build_conn(:delete, "/auth/account")
      |> Plug.Test.init_test_session(%{})
      |> AuthController.delete_account(%{})

    assert conn.status == 401
    assert Jason.decode!(conn.resp_body) == %{"error" => "Not authenticated"}
  end

  defp restore_env(app, key, nil), do: Application.delete_env(app, key)
  defp restore_env(app, key, value), do: Application.put_env(app, key, value)
end
