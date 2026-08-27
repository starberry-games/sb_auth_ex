defmodule SbAuthEx.Auth do
  @moduledoc """
  Normalized result of a successful provider authentication.

  Every `SbAuthEx.Provider` returns this struct from `c:SbAuthEx.Provider.exchange_code/2`
  so the controller, session handling and `SbAuthEx.Accounts` never see
  provider-specific response shapes.

  - `sb_id` — the provider's stable subject for this identity. Stored in
    `SbAuthEx.Identity.sb_id`, the global cross-application identifier.
    A WorkOS `user_...` id and an OIDC `sub` land here alike.
  - `email` — the identity's email address.
  - `session_id` — the provider session id (WorkOS `sid` claim) when one
    exists, used to end the provider session on logout. `nil` otherwise.
  - `claims` — the full verified claim set, for providers that have one.
  """

  @enforce_keys [:sb_id, :email]
  defstruct [:sb_id, :email, :session_id, claims: %{}]

  @type t :: %__MODULE__{
          sb_id: String.t(),
          email: String.t(),
          session_id: String.t() | nil,
          claims: map()
        }
end
