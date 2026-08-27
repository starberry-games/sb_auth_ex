defmodule SbAuthEx.AuthControllerOIDCFlowTest do
  @moduledoc """
  End-to-end tests for the login -> callback -> logout flow with
  `provider: :oidc`, against a stubbed issuer (via `Req.Test`) serving OIDC
  discovery, JWKS, the token endpoint and userinfo. Tokens are real RS256 JWTs
  signed with a per-run test key, so the verification path (signature, issuer,
  audience, expiry, nonce, algorithm allowlist, key rotation) is exercised for
  real.
  """
  use ExUnit.Case, async: false

  alias SbAuthEx.AuthController
  alias SbAuthEx.FakeRepo

  @oauth_cookie "_sb_auth_oauth"
  @secret_key_base String.duplicate("a", 64)

  @issuer "https://issuer.example.test"
  @client_id "client_oidc_123"
  @client_secret "secret_oidc_123"
  @redirect_uri "http://localhost/auth/callback"
  @audience "https://studio.example.test"
  @kid "test-key-1"
  @sub "sub_" <> String.duplicate("a", 43)

  setup_all do
    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    other_jwk = JOSE.JWK.generate_key({:rsa, 2048})

    %{jwk: jwk, other_jwk: other_jwk, jwks: jwks_for(jwk, @kid)}
  end

  setup do
    previous = %{
      provider: Application.get_env(:sb_auth_ex, :provider),
      oidc: Application.get_env(:sb_auth_ex, :oidc),
      repo: Application.get_env(:sb_auth_ex, :repo),
      on_login: Application.get_env(:sb_auth_ex, :on_login),
      on_register: Application.get_env(:sb_auth_ex, :on_register)
    }

    Application.put_env(:sb_auth_ex, :provider, :oidc)

    Application.put_env(:sb_auth_ex, :oidc,
      issuer: @issuer,
      client_id: @client_id,
      client_secret: @client_secret,
      redirect_uri: @redirect_uri,
      audience: @audience,
      req_options: [plug: {Req.Test, SbAuthEx.OIDCStub}]
    )

    Application.put_env(:sb_auth_ex, :repo, FakeRepo)
    Application.delete_env(:sb_auth_ex, :on_login)
    Application.delete_env(:sb_auth_ex, :on_register)
    FakeRepo.reset()
    SbAuthEx.Providers.OIDC.reset_cache()

    on_exit(fn ->
      restore_env(:sb_auth_ex, :provider, previous.provider)
      restore_env(:sb_auth_ex, :oidc, previous.oidc)
      restore_env(:sb_auth_ex, :repo, previous.repo)
      restore_env(:sb_auth_ex, :on_login, previous.on_login)
      restore_env(:sb_auth_ex, :on_register, previous.on_register)
      SbAuthEx.Providers.OIDC.reset_cache()
    end)

    :ok
  end

  describe "login/2" do
    test "redirects to the discovered authorization endpoint with PKCE, state, nonce and resource",
         %{jwks: jwks} do
      stub_issuer(jwks)

      conn = login()

      assert conn.status == 302
      assert [location] = Plug.Conn.get_resp_header(conn, "location")

      uri = URI.parse(location)
      assert uri.host == "issuer.example.test"
      assert uri.path == "/oauth2/authorize"

      query = URI.decode_query(uri.query)
      assert query["response_type"] == "code"
      assert query["client_id"] == @client_id
      assert query["redirect_uri"] == @redirect_uri
      assert query["scope"] == "openid profile email"
      assert query["resource"] == @audience
      assert query["code_challenge_method"] == "S256"
      assert is_binary(query["code_challenge"]) and query["code_challenge"] != ""
      assert is_binary(query["state"]) and byte_size(query["state"]) >= 32
      assert is_binary(query["nonce"]) and byte_size(query["nonce"]) >= 32

      # The cookie parks state, verifier and nonce for the callback.
      assert %{value: value, max_age: 600, http_only: true, same_site: "Lax"} =
               conn.resp_cookies[@oauth_cookie]

      assert %{state: state, code_verifier: verifier, nonce: nonce} = decrypt_cookie(value)
      assert state == query["state"]
      assert nonce == query["nonce"]
      assert byte_size(verifier) >= 43

      # PKCE challenge is S256 of the stored verifier.
      assert query["code_challenge"] ==
               Base.url_encode64(:crypto.hash(:sha256, verifier), padding: false)
    end

    test "fetches discovery once and caches it", %{jwks: jwks} do
      stub_issuer(jwks)

      login()
      assert_received {:oidc_request, :discovery}

      login()
      refute_received {:oidc_request, :discovery}
    end

    test "raises a clear error when required OIDC config is missing", %{jwks: jwks} do
      stub_issuer(jwks)

      Application.put_env(
        :sb_auth_ex,
        :oidc,
        Keyword.delete(Application.get_env(:sb_auth_ex, :oidc), :audience)
      )

      assert_raise ArgumentError, ~r/missing OIDC audience/, fn -> login() end
    end

    test "rejects an unsupported token_auth_method with a clear error" do
      put_oidc_config(:token_auth_method, :private_key_jwt)

      assert_raise ArgumentError, ~r/unsupported OIDC token_auth_method/, fn -> login() end
    end

    test "rejects a plain-http issuer with a clear error" do
      put_oidc_config(:issuer, "http://issuer.example.test")

      assert_raise ArgumentError, ~r/issuer must be https/, fn -> login() end
    end

    test "rejects malformed scopes config with a clear error" do
      put_oidc_config(:scopes, :openid)

      assert_raise ArgumentError, ~r/scopes must be a string or a list/, fn -> login() end
    end

    @tag capture_log: true
    test "a discovery failure is reported with a flash, not a 500" do
      put_oidc_config(:req_options, plug: {Req.Test, SbAuthEx.OIDCStub}, retry: false)

      Req.Test.stub(SbAuthEx.OIDCStub, fn conn ->
        Req.Test.json(Plug.Conn.put_status(conn, 503), %{"error" => "unavailable"})
      end)

      conn = login()

      assert conn.status == 302
      assert [location] = Plug.Conn.get_resp_header(conn, "location")
      assert location == SbAuthEx.after_logout_path()

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~
               "could not reach the identity provider"
    end
  end

  describe "callback/2 — happy path" do
    test "exchanges the code with PKCE + Basic auth, verifies the tokens, signs the user in",
         %{jwk: jwk, jwks: jwks} do
      %{cookie: cookie, state: state, code_verifier: code_verifier, nonce: nonce} =
        stubbed_login_state(jwks)

      claims = access_claims(%{"email" => "sam@starberry.games"})

      stub_issuer(jwks,
        tokens: %{
          "access_token" => sign(jwk, claims),
          "id_token" => sign(jwk, id_claims(nonce))
        }
      )

      conn = callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert_received {:token_request, form, auth_header}
      assert form["grant_type"] == "authorization_code"
      assert form["code"] == "code_ok"
      assert form["code_verifier"] == code_verifier
      assert form["redirect_uri"] == @redirect_uri
      assert form["client_id"] == @client_id
      assert form["resource"] == @audience
      refute Map.has_key?(form, "client_secret")
      assert auth_header == "Basic " <> Base.encode64("#{@client_id}:#{@client_secret}")

      assert conn.status == 302
      assert [location] = Plug.Conn.get_resp_header(conn, "location")
      assert location == SbAuthEx.after_login_path()

      assert [%{sb_id: @sub, email: "sam@starberry.games", id: identity_id}] =
               FakeRepo.all_identities()

      assert Plug.Conn.get_session(conn, :identity_id) == identity_id
      assert Plug.Conn.get_session(conn, :workos_session_id) == "oidc_session_01"
      assert %{max_age: 0} = conn.resp_cookies[@oauth_cookie]
    end

    test "takes the email from a verified id_token when the access token has none",
         %{jwk: jwk, jwks: jwks} do
      %{cookie: cookie, state: state, nonce: nonce} = stubbed_login_state(jwks)

      id_claims =
        access_claims(%{
          "aud" => @client_id,
          "nonce" => nonce,
          "email" => "sam@starberry.games"
        })

      stub_issuer(jwks,
        tokens: %{
          "access_token" => sign(jwk, access_claims()),
          "id_token" => sign(jwk, id_claims)
        }
      )

      callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert [%{sb_id: @sub, email: "sam@starberry.games"}] = FakeRepo.all_identities()
    end

    test "falls back to userinfo (with matching sub) when no token carries an email",
         %{jwk: jwk, jwks: jwks} do
      %{cookie: cookie, state: state, nonce: nonce} = stubbed_login_state(jwks)

      stub_issuer(jwks,
        tokens: %{
          "access_token" => sign(jwk, access_claims()),
          "id_token" => sign(jwk, id_claims(nonce))
        },
        userinfo: %{"sub" => @sub, "email" => "sam@starberry.games"}
      )

      callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert [%{sb_id: @sub, email: "sam@starberry.games"}] = FakeRepo.all_identities()
    end

    test "refuses when no email can be found anywhere", %{jwk: jwk, jwks: jwks} do
      %{cookie: cookie, state: state, nonce: nonce} = stubbed_login_state(jwks)

      stub_issuer(jwks,
        tokens: %{
          "access_token" => sign(jwk, access_claims()),
          "id_token" => sign(jwk, id_claims(nonce))
        },
        userinfo: %{"sub" => @sub}
      )

      conn = callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "did not supply an email address"
      assert FakeRepo.all_identities() == []
    end

    test "runs on the access token alone when scopes exclude openid", %{jwk: jwk, jwks: jwks} do
      put_oidc_config(:scopes, ["profile", "email"])

      %{cookie: cookie, state: state} = stubbed_login_state(jwks)

      stub_issuer(jwks,
        tokens: %{"access_token" => sign(jwk, access_claims(%{"email" => "sam@starberry.games"}))}
      )

      callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert [%{sb_id: @sub, email: "sam@starberry.games"}] = FakeRepo.all_identities()
    end

    test "treats an empty client_secret as a public client (no Basic auth)",
         %{jwk: jwk, jwks: jwks} do
      put_oidc_config(:client_secret, "")

      %{cookie: cookie, state: state, nonce: nonce} = stubbed_login_state(jwks)

      claims = access_claims(%{"email" => "sam@starberry.games"})

      stub_issuer(jwks,
        tokens: %{
          "access_token" => sign(jwk, claims),
          "id_token" => sign(jwk, id_claims(nonce))
        }
      )

      callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert_received {:token_request, form, auth_header}
      assert auth_header == nil
      refute Map.has_key?(form, "client_secret")
      assert [%{sb_id: @sub}] = FakeRepo.all_identities()
    end

    test "skips an email the issuer marks unverified and uses the next source",
         %{jwk: jwk, jwks: jwks} do
      %{cookie: cookie, state: state, nonce: nonce} = stubbed_login_state(jwks)

      id_with_unverified_email =
        id_claims(nonce, %{"email" => "spoofed@starberry.games", "email_verified" => false})

      stub_issuer(jwks,
        tokens: %{
          "access_token" => sign(jwk, access_claims(%{"email" => "sam@starberry.games"})),
          "id_token" => sign(jwk, id_with_unverified_email)
        }
      )

      callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert [%{email: "sam@starberry.games"}] = FakeRepo.all_identities()
    end

    test "require_verified_email: true refuses an email without email_verified: true",
         %{jwk: jwk, jwks: jwks} do
      put_oidc_config(:require_verified_email, true)

      %{cookie: cookie, state: state, nonce: nonce} = stubbed_login_state(jwks)

      stub_issuer(jwks,
        tokens: %{
          "access_token" => sign(jwk, access_claims()),
          "id_token" => sign(jwk, id_claims(nonce, %{"email" => "sam@starberry.games"}))
        },
        userinfo: %{"sub" => @sub, "email" => "sam@starberry.games"}
      )

      conn = callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "did not supply an email address"
      assert FakeRepo.all_identities() == []
    end

    test "accepts a multi-audience id_token when azp names this client",
         %{jwk: jwk, jwks: jwks} do
      %{cookie: cookie, state: state, nonce: nonce} = stubbed_login_state(jwks)

      multi_aud =
        id_claims(nonce, %{
          "aud" => [@client_id, "client_other"],
          "azp" => @client_id,
          "email" => "sam@starberry.games"
        })

      stub_issuer(jwks,
        tokens: %{
          "access_token" => sign(jwk, access_claims()),
          "id_token" => sign(jwk, multi_aud)
        }
      )

      callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert [%{sb_id: @sub}] = FakeRepo.all_identities()
    end

    test "accepts fractional NumericDate exp/nbf claims", %{jwk: jwk, jwks: jwks} do
      %{cookie: cookie, state: state, nonce: nonce} = stubbed_login_state(jwks)

      fractional = %{
        "exp" => System.system_time(:second) + 300.5,
        "nbf" => System.system_time(:second) - 10.5,
        "email" => "sam@starberry.games"
      }

      stub_issuer(jwks,
        tokens: %{
          "access_token" => sign(jwk, access_claims(fractional)),
          "id_token" => sign(jwk, id_claims(nonce, fractional))
        }
      )

      callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert [%{sb_id: @sub}] = FakeRepo.all_identities()
    end

    test "refetches the JWKS once when the token uses a freshly rotated key",
         %{jwk: jwk, other_jwk: rotated_jwk, jwks: jwks} do
      %{cookie: cookie, state: state, nonce: nonce} = stubbed_login_state(jwks)

      rotated_kid = "test-key-2"
      claims = access_claims(%{"email" => "sam@starberry.games"})

      fetches = :counters.new(1, [])

      stub_issuer(jwks,
        tokens: %{
          "access_token" => sign(rotated_jwk, claims, kid: rotated_kid),
          "id_token" => sign(rotated_jwk, id_claims(nonce), kid: rotated_kid)
        },
        jwks_fun: fn ->
          :counters.add(fetches, 1, 1)

          case :counters.get(fetches, 1) do
            1 -> jwks_for(jwk, @kid)
            _ -> jwks_for(rotated_jwk, rotated_kid)
          end
        end
      )

      callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert :counters.get(fetches, 1) == 2
      assert [%{sb_id: @sub}] = FakeRepo.all_identities()
    end
  end

  describe "callback/2 — verification failures" do
    test "refuses a token minted for another tool (wrong audience)", %{jwk: jwk, jwks: jwks} do
      refused_with_token(jwk, jwks, access_claims(%{"aud" => "https://other-tool.example.test"}))
    end

    test "refuses a token from another issuer", %{jwk: jwk, jwks: jwks} do
      refused_with_token(jwk, jwks, access_claims(%{"iss" => "https://evil.example.test"}))
    end

    test "refuses an expired token", %{jwk: jwk, jwks: jwks} do
      refused_with_token(
        jwk,
        jwks,
        access_claims(%{"exp" => System.system_time(:second) - 3600})
      )
    end

    test "refuses a token without an expiry", %{jwk: jwk, jwks: jwks} do
      refused_with_token(jwk, jwks, Map.delete(access_claims(), "exp"))
    end

    test "refuses a token signed by the wrong key", %{other_jwk: other_jwk, jwks: jwks} do
      # Same kid, different key material: signature verification must fail.
      refused_with_token(other_jwk, jwks, access_claims(%{"email" => "sam@starberry.games"}))
    end

    test "refuses a symmetric-algorithm downgrade (HS256)", %{jwks: jwks} do
      oct_jwk = JOSE.JWK.from_oct("supersecretsupersecretsupersecret")
      token = sign(oct_jwk, access_claims(), alg: "HS256")

      %{cookie: cookie, state: state} = stubbed_login_state(jwks)
      stub_issuer(jwks, tokens: %{"access_token" => token})

      conn = callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "invalid token"
      assert FakeRepo.all_identities() == []
      # The allowlist rejects the alg before any key is fetched.
      refute_received {:oidc_request, :jwks}
    end

    test "refuses a token response without an id_token when openid was requested",
         %{jwk: jwk, jwks: jwks} do
      %{cookie: cookie, state: state} = stubbed_login_state(jwks)

      stub_issuer(jwks,
        tokens: %{"access_token" => sign(jwk, access_claims(%{"email" => "sam@starberry.games"}))}
      )

      conn = callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "invalid token"
      assert FakeRepo.all_identities() == []
    end

    test "refuses an id_token whose nonce does not match the login attempt",
         %{jwk: jwk, jwks: jwks} do
      %{cookie: cookie, state: state} = stubbed_login_state(jwks)

      id_claims =
        access_claims(%{"aud" => @client_id, "nonce" => "forged", "email" => "x@example.com"})

      stub_issuer(jwks,
        tokens: %{
          "access_token" => sign(jwk, access_claims()),
          "id_token" => sign(jwk, id_claims)
        }
      )

      conn = callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "invalid token"
      assert FakeRepo.all_identities() == []
    end

    test "refuses a multi-audience id_token that does not name this client as azp",
         %{jwk: jwk, jwks: jwks} do
      %{cookie: cookie, state: state, nonce: nonce} = stubbed_login_state(jwks)

      multi_aud =
        id_claims(nonce, %{
          "aud" => [@client_id, "client_other"],
          "email" => "sam@starberry.games"
        })

      stub_issuer(jwks,
        tokens: %{
          "access_token" => sign(jwk, access_claims()),
          "id_token" => sign(jwk, multi_aud)
        }
      )

      conn = callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "invalid token"
      assert FakeRepo.all_identities() == []
    end

    @tag capture_log: true
    test "a non-JSON 200 from the token endpoint is sanitized, not echoed", %{jwks: jwks} do
      %{cookie: cookie, state: state} = stubbed_login_state(jwks)

      stub_issuer(jwks,
        token_fun: fn conn ->
          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.resp(200, "<html>WAF error page</html>")
        end
      )

      conn = callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

      error = Phoenix.Flash.get(conn.assigns.flash, :error)
      assert error =~ "could not reach the identity provider"
      refute error =~ "0x3C"
      assert FakeRepo.all_identities() == []
    end

    test "a token endpoint rejection is reported, not crashed on", %{jwks: jwks} do
      %{cookie: cookie, state: state} = stubbed_login_state(jwks)

      stub_issuer(jwks,
        token_fun: fn conn ->
          conn
          |> Plug.Conn.put_status(400)
          |> Req.Test.json(%{"error" => "invalid_grant"})
        end
      )

      conn = callback(%{"code" => "code_expired", "state" => state}, cookie: cookie)

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "HTTP 400"
      assert FakeRepo.all_identities() == []
    end

    test "refuses a callback that carries no oauth cookie without contacting the issuer",
         %{jwks: jwks} do
      stub_issuer(jwks)

      conn = callback(%{"code" => "code_attacker", "state" => "whatever"}, cookie: nil)

      assert conn.status == 302
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "invalid or expired login request"
      assert FakeRepo.all_identities() == []
      refute_received {:token_request, _, _}
    end
  end

  describe "logout/2" do
    test "logs out locally — the OIDC provider has no session to end" do
      conn =
        Phoenix.ConnTest.build_conn(:delete, "/auth/logout")
        |> Plug.Test.init_test_session(%{identity_id: 1, workos_session_id: "oidc_session_01"})
        |> Phoenix.Controller.fetch_flash([])
        |> AuthController.logout(%{})

      assert conn.status == 302
      assert [location] = Plug.Conn.get_resp_header(conn, "location")
      assert location == SbAuthEx.after_logout_path()
    end
  end

  # ---------------------------------------------------------------------------
  # Issuer stub
  # ---------------------------------------------------------------------------

  # Serves discovery, JWKS, the token endpoint and userinfo. Every request is
  # reported back to the test process.
  defp stub_issuer(jwks, opts \\ []) do
    test_pid = self()

    token_fun =
      opts[:token_fun] ||
        fn conn ->
          Req.Test.json(conn, opts[:tokens] || %{"access_token" => "unset"})
        end

    jwks_fun = opts[:jwks_fun] || fn -> jwks end

    Req.Test.stub(SbAuthEx.OIDCStub, fn conn ->
      case {conn.method, conn.request_path} do
        {"GET", "/.well-known/openid-configuration"} ->
          send(test_pid, {:oidc_request, :discovery})

          Req.Test.json(conn, %{
            "issuer" => @issuer,
            "authorization_endpoint" => @issuer <> "/oauth2/authorize",
            "token_endpoint" => @issuer <> "/oauth2/token",
            "jwks_uri" => @issuer <> "/oauth2/jwks",
            "userinfo_endpoint" => @issuer <> "/oauth2/userinfo"
          })

        {"GET", "/oauth2/jwks"} ->
          send(test_pid, {:oidc_request, :jwks})
          Req.Test.json(conn, jwks_fun.())

        {"POST", "/oauth2/token"} ->
          {:ok, body, conn} = Plug.Conn.read_body(conn)
          auth_header = List.first(Plug.Conn.get_req_header(conn, "authorization"))
          send(test_pid, {:token_request, URI.decode_query(body), auth_header})
          token_fun.(conn)

        {"GET", "/oauth2/userinfo"} ->
          send(test_pid, {:oidc_request, :userinfo})
          Req.Test.json(conn, opts[:userinfo] || %{})

        other ->
          send(test_pid, {:unexpected_oidc_request, other})
          Req.Test.json(Plug.Conn.put_status(conn, 500), %{"error" => "unexpected"})
      end
    end)
  end

  # ---------------------------------------------------------------------------
  # JWT helpers
  # ---------------------------------------------------------------------------

  defp jwks_for(jwk, kid) do
    {_meta, public_map} = JOSE.JWK.to_public_map(jwk)
    %{"keys" => [Map.put(public_map, "kid", kid)]}
  end

  defp access_claims(overrides \\ %{}) do
    Map.merge(
      %{
        "iss" => @issuer,
        "sub" => @sub,
        "aud" => @audience,
        "exp" => System.system_time(:second) + 300,
        "sid" => "oidc_session_01"
      },
      overrides
    )
  end

  # Claims for a well-formed id_token belonging to the same login attempt.
  defp id_claims(nonce, overrides \\ %{}) do
    access_claims(Map.merge(%{"aud" => @client_id, "nonce" => nonce}, overrides))
  end

  defp sign(jwk, claims, opts \\ []) do
    jws = %{"alg" => Keyword.get(opts, :alg, "RS256"), "kid" => Keyword.get(opts, :kid, @kid)}
    {_meta, token} = jwk |> JOSE.JWT.sign(jws, claims) |> JOSE.JWS.compact()
    token
  end

  # A token that must be refused with the generic invalid-token flash.
  defp refused_with_token(signing_jwk, jwks, claims) do
    %{cookie: cookie, state: state} = stubbed_login_state(jwks)
    stub_issuer(jwks, tokens: %{"access_token" => sign(signing_jwk, claims)})

    conn = callback(%{"code" => "code_ok", "state" => state}, cookie: cookie)

    assert conn.status == 302
    assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "invalid token"
    assert FakeRepo.all_identities() == []
    assert Plug.Conn.get_session(conn, :identity_id) == nil
  end

  # ---------------------------------------------------------------------------
  # Conn helpers (mirroring the WorkOS flow test)
  # ---------------------------------------------------------------------------

  defp login(params \\ %{}) do
    Phoenix.ConnTest.build_conn(:get, "/auth/login")
    |> put_secret_key_base()
    |> Plug.Test.init_test_session(%{})
    |> Phoenix.Controller.fetch_flash([])
    |> AuthController.login(params)
  end

  defp login_state(params \\ %{}) do
    conn = login(params)
    %{value: cookie} = conn.resp_cookies[@oauth_cookie]
    %{state: state, code_verifier: verifier, nonce: nonce} = decrypt_cookie(cookie)
    %{cookie: cookie, state: state, code_verifier: verifier, nonce: nonce}
  end

  # Stubs the issuer first so login can resolve discovery, then logs in.
  defp stubbed_login_state(jwks) do
    stub_issuer(jwks)
    login_state()
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

    AuthController.callback(conn, params)
  end

  defp decrypt_cookie(value) do
    conn =
      Phoenix.ConnTest.build_conn(:get, "/")
      |> put_secret_key_base()
      |> Plug.Test.put_req_cookie(@oauth_cookie, value)
      |> Plug.Conn.fetch_cookies(encrypted: [@oauth_cookie])

    conn.cookies[@oauth_cookie]
  end

  defp put_oidc_config(key, value) do
    Application.put_env(
      :sb_auth_ex,
      :oidc,
      Keyword.put(Application.get_env(:sb_auth_ex, :oidc), key, value)
    )
  end

  defp put_secret_key_base(conn), do: %{conn | secret_key_base: @secret_key_base}

  defp restore_env(app, key, nil), do: Application.delete_env(app, key)
  defp restore_env(app, key, value), do: Application.put_env(app, key, value)
end
