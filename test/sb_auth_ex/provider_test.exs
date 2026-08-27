defmodule SbAuthEx.ProviderTest do
  use ExUnit.Case, async: false

  setup do
    previous = Application.get_env(:sb_auth_ex, :provider)

    on_exit(fn ->
      if previous do
        Application.put_env(:sb_auth_ex, :provider, previous)
      else
        Application.delete_env(:sb_auth_ex, :provider)
      end
    end)

    :ok
  end

  test "defaults to the WorkOS provider when nothing is configured" do
    Application.delete_env(:sb_auth_ex, :provider)
    assert SbAuthEx.Provider.current() == SbAuthEx.Providers.WorkOS
  end

  test "selects the built-in providers by key" do
    Application.put_env(:sb_auth_ex, :provider, :workos)
    assert SbAuthEx.Provider.current() == SbAuthEx.Providers.WorkOS

    Application.put_env(:sb_auth_ex, :provider, :oidc)
    assert SbAuthEx.Provider.current() == SbAuthEx.Providers.OIDC
  end

  test "accepts a custom module implementing the behaviour" do
    Application.put_env(:sb_auth_ex, :provider, SbAuthEx.Providers.OIDC)
    assert SbAuthEx.Provider.current() == SbAuthEx.Providers.OIDC
  end

  test "rejects anything else with a clear error" do
    Application.put_env(:sb_auth_ex, :provider, :saml)

    assert_raise ArgumentError, ~r/must be :workos, :oidc, or a module/, fn ->
      SbAuthEx.Provider.current()
    end
  end
end
