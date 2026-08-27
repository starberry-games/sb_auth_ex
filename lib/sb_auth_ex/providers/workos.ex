defmodule SbAuthEx.Providers.WorkOS do
  @moduledoc """
  The default `SbAuthEx.Provider`: WorkOS AuthKit via the User Management API.

  Configuration is unchanged from previous releases — see `SbAuthEx.WorkOSClient`
  for how the client is built:

      config :sb_auth_ex,
        workos: [api_key: ..., client_id: ..., redirect_uri: ...]
  """

  @behaviour SbAuthEx.Provider

  alias SbAuthEx.WorkOSClient

  @impl true
  def authorize do
    %{url: url, code_verifier: code_verifier, state: state} =
      WorkOS.AuthKit.get_pkce_authorization_url(WorkOSClient.client(), %{
        provider: "authkit",
        redirect_uri: WorkOSClient.redirect_uri(),
        # Force account selection on every login to allow switching accounts
        prompt: "select_account"
      })

    {:ok, %{url: url, state: state, code_verifier: code_verifier, nonce: nil}}
  end

  @impl true
  def exchange_code(code, %{code_verifier: code_verifier}) do
    case WorkOS.UserManagement.authenticate_with_code(WorkOSClient.client(), %{
           code: code,
           code_verifier: code_verifier
         }) do
      {:ok,
       %WorkOS.AuthenticateResponse{
         user: %WorkOS.User{id: user_id, email: email},
         access_token: access_token
       }}
      when is_binary(user_id) and is_binary(email) ->
        {:ok,
         %SbAuthEx.Auth{
           sb_id: user_id,
           email: email,
           session_id: extract_session_id(access_token)
         }}

      {:ok, _response} ->
        {:error, :invalid_user_payload}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def logout_url(nil, _return_to), do: :none

  def logout_url(session_id, return_to) do
    # A pure URL build, no API call.
    {:ok,
     WorkOS.UserManagement.get_logout_url(WorkOSClient.client(), %{
       session_id: session_id,
       return_to: return_to
     })}
  end

  @impl true
  def delete_user(workos_user_id) do
    case WorkOS.UserManagement.delete_user(WorkOSClient.client(), workos_user_id) do
      {:ok, _} ->
        :ok

      {:error,
       %WorkOS.ApiError{
         status: 404,
         kind: :not_found,
         code: "entity_not_found",
         request_id: request_id,
         body: %{"entity_id" => ^workos_user_id}
       }}
      when is_binary(request_id) and request_id != "" ->
        # A structured WorkOS response confirms this exact user is already gone.
        # Generic 404s from a bad base URL or path must fail closed below.
        :ok

      {:error, error} ->
        require Logger

        Logger.warning(
          "Failed to delete WorkOS user #{workos_user_id}: #{Exception.message(error)}"
        )

        {:error, error}
    end
  end

  # ---------------------------------------------------------------------------
  # JWT helpers
  # ---------------------------------------------------------------------------

  # Pulls the WorkOS session id (`sid`) out of the access token without
  # verifying it — it is only used to build the hosted logout URL.
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
