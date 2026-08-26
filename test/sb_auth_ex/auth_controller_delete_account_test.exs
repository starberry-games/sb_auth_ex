defmodule SbAuthEx.AuthControllerDeleteAccountTest do
  use ExUnit.Case, async: false

  alias SbAuthEx.AuthController
  alias SbAuthEx.FakeRepo

  import ExUnit.CaptureLog

  @session_id "session_01TEST"

  setup do
    previous = %{
      on_delete: Application.get_env(:sb_auth_ex, :on_delete_account),
      repo: Application.get_env(:sb_auth_ex, :repo),
      workos: Application.get_env(:sb_auth_ex, :workos),
      workos_client: Application.get_env(:workos, WorkOS.Client)
    }

    Application.delete_env(:sb_auth_ex, :on_delete_account)
    Application.put_env(:sb_auth_ex, :repo, FakeRepo)

    Application.put_env(:sb_auth_ex, :workos,
      api_key: "sk_test_123",
      client_id: "client_test_123",
      req_options: [plug: {Req.Test, SbAuthEx.DeleteAccountWorkOSStub}]
    )

    Application.delete_env(:workos, WorkOS.Client)
    FakeRepo.reset()

    test_pid = self()

    Req.Test.stub(SbAuthEx.DeleteAccountWorkOSStub, fn conn ->
      send(test_pid, {:unexpected_workos_request, conn.method, conn.request_path})
      Req.Test.json(Plug.Conn.put_status(conn, 500), %{"message" => "unexpected request"})
    end)

    on_exit(fn ->
      restore_env(:sb_auth_ex, :on_delete_account, previous.on_delete)
      restore_env(:sb_auth_ex, :repo, previous.repo)
      restore_env(:sb_auth_ex, :workos, previous.workos)
      restore_env(:workos, WorkOS.Client, previous.workos_client)
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
    refute_received {:unexpected_workos_request, _, _}
  end

  test "returns 401 JSON when current_identity is missing from assigns" do
    conn =
      Phoenix.ConnTest.build_conn(:delete, "/auth/account")
      |> Plug.Test.init_test_session(%{})
      |> AuthController.delete_account(%{})

    assert conn.status == 401
    assert Jason.decode!(conn.resp_body) == %{"error" => "Not authenticated"}
    refute_received {:unexpected_workos_request, _, _}
  end

  test "deletes the WorkOS user and local identity before reporting success" do
    identity = create_identity()
    test_pid = self()

    Req.Test.stub(SbAuthEx.DeleteAccountWorkOSStub, fn conn ->
      send(test_pid, {:workos_request, conn.method, conn.request_path})
      Req.Test.json(conn, %{})
    end)

    conn = identity |> authenticated_conn() |> AuthController.delete_account(%{})

    assert_received {:workos_request, "DELETE", "/user_management/users/user_01TEST"}
    assert conn.status == 200
    assert Jason.decode!(conn.resp_body) == %{"deleted" => true}
    assert FakeRepo.all_identities() == []
    assert conn.private.plug_session_info == :drop
  end

  test "treats a missing WorkOS user as idempotent success" do
    identity = create_identity()

    Req.Test.stub(SbAuthEx.DeleteAccountWorkOSStub, fn conn ->
      conn
      |> Plug.Conn.put_status(404)
      |> Req.Test.json(%{"code" => "not_found", "message" => "User not found"})
    end)

    conn = identity |> authenticated_conn() |> AuthController.delete_account(%{})

    assert conn.status == 200
    assert Jason.decode!(conn.resp_body) == %{"deleted" => true}
    assert FakeRepo.all_identities() == []
    assert conn.private.plug_session_info == :drop
  end

  test "returns 502 and retains the local identity and session when WorkOS deletion fails" do
    identity = create_identity()

    Req.Test.stub(SbAuthEx.DeleteAccountWorkOSStub, fn conn ->
      conn
      |> Plug.Conn.put_status(500)
      |> Req.Test.json(%{"code" => "server_error", "message" => "WorkOS unavailable"})
    end)

    {conn, log} =
      with_log(fn ->
        identity
        |> authenticated_conn()
        |> AuthController.delete_account(%{})
      end)

    assert conn.status == 502
    assert Jason.decode!(conn.resp_body) == %{"error" => "Failed to delete account"}
    assert [^identity] = FakeRepo.all_identities()
    assert Plug.Conn.get_session(conn, :identity_id) == identity.id
    assert Plug.Conn.get_session(conn, :workos_session_id) == @session_id
    assert conn.private.plug_session_info != :drop
    assert log =~ "Failed to delete WorkOS user user_01TEST"
  end

  test "aborts before contacting WorkOS when application cleanup fails" do
    identity = create_identity()

    Application.put_env(:sb_auth_ex, :on_delete_account, fn _identity, _conn ->
      {:error, :busy}
    end)

    conn = identity |> authenticated_conn() |> AuthController.delete_account(%{})

    assert conn.status == 422
    assert Jason.decode!(conn.resp_body) == %{"error" => "Cleanup failed: :busy"}
    assert [^identity] = FakeRepo.all_identities()
    assert Plug.Conn.get_session(conn, :identity_id) == identity.id
    assert Plug.Conn.get_session(conn, :workos_session_id) == @session_id
    refute_received {:unexpected_workos_request, _, _}
  end

  defp create_identity do
    assert {:ok, identity} =
             SbAuthEx.Accounts.upsert_identity_from_provider!("user_01TEST", "ada@example.com")

    identity
  end

  defp authenticated_conn(identity) do
    Phoenix.ConnTest.build_conn(:delete, "/auth/account")
    |> Plug.Test.init_test_session(%{
      identity_id: identity.id,
      workos_session_id: @session_id
    })
    |> Plug.Conn.assign(:current_identity, identity)
  end

  defp restore_env(app, key, nil), do: Application.delete_env(app, key)
  defp restore_env(app, key, value), do: Application.put_env(app, key, value)
end
