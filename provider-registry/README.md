# Provider Registry

This contract manages verified healthcare providers.

**A provider could be:**

* Hospital
* Clinic
* Doctor
* Laboratory
* Pharmacy
* Insurance company
* Public health agency

**What it does**
* Registers healthcare providers.
* Verifies providers before they can request access.
* Allows an admin to suspend, reinstate, or revoke a provider.
* Resolves a provider from either its `provider_id` or its wallet address.

## Build & Test

Run these commands from the repository root:

```sh
cargo build --target wasm32v1-none --release
cargo test -p provider-registry
```

Format and lint checks (also run in CI):

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Admin trust model

The contract is initialized exactly once with a trusted verifying authority
(the admin), for example a LockA medical-board address:

```rust
initialize(env, admin: Address)
```

Verification, reinstatement, suspension, and revocation are all gated to the
stored admin. `transfer_admin` lets the current admin hand control to a new
address during an organizational handover. Transferring to the same address is
rejected with `Error::SameAdmin` rather than silently doing nothing.

Registration itself is self-service: only the provider wallet can register its
own address, and the entry starts in `Pending` status until an admin verifies
it. A wallet can only ever be linked to one provider entry, even if that
provider is later revoked.

## Public API

| Function | Description |
| --- | --- |
| `initialize(env, admin: Address) -> Result<(), Error>` | One-time setup of the verifying admin. |
| `transfer_admin(env, current_admin: Address, new_admin: Address) -> Result<(), Error>` | Hand admin control to a new address. |
| `register_provider(env, provider_wallet_address: Address, provider_type: ProviderType, license_hash: BytesN<32>, country: Symbol) -> Result<u64, Error>` | Self-register a provider starting in `Pending`; returns the new `provider_id`. |
| `verify_provider(env, admin: Address, provider_id: u64) -> Result<(), Error>` | Verify a `Pending` provider. |
| `reinstate_provider(env, admin: Address, provider_id: u64) -> Result<(), Error>` | Restore a `Suspended` provider to `Verified`. |
| `suspend_provider(env, admin: Address, provider_id: u64) -> Result<(), Error>` | Temporarily suspend a `Verified` provider. |
| `revoke_provider(env, admin: Address, provider_id: u64) -> Result<(), Error>` | Permanently revoke a provider (from `Pending`, `Verified`, or `Suspended`). |
| `get_provider(env, provider_id: u64) -> Option<Provider>` | Read a provider by id (no auth required). |
| `get_provider_by_wallet(env, wallet_address: Address) -> Option<Provider>` | Read a provider by wallet address (no auth required). |
| `is_provider_verified(env, provider_id: u64) -> bool` | `true` only when the provider exists and is `Verified`. |

All admin-gated functions return `Error::NotInitialized` before
`initialize` and `Error::NotAdmin` when the authenticated caller is not the
stored admin. Status-changing functions return
`Error::InvalidStatusTransition` when the requested change is not legal from
the provider's current status.

## Provider status transitions

`Pending -> Verified`, `Pending -> Revoked`, `Verified -> Suspended`,
`Verified -> Revoked`, `Suspended -> Verified` (reinstatement),
`Suspended -> Revoked`. `Revoked` is terminal: no transitions are allowed out
of it.

## Events

Provider lifecycle events use the `("provider", <verb>)` topic pair. Admin
handover uses `("provider_registry", "admin_transferred")`. Event data is a map
keyed by the field names below.

| Event | Topics | Data |
| --- | --- | --- |
| `ProviderRegistered` | `("provider", "registered")` | `provider_id`, `provider_wallet_address`, `provider_type`, `country` |
| `ProviderVerified` | `("provider", "verified")` | `provider_id`, `provider_wallet_address`, `verified_by` |
| `ProviderStatusChanged` | `("provider", "status_changed")` | `provider_id`, `old_status`, `new_status`, `changed_by` |
| `AdminTransferred` | `("provider_registry", "admin_transferred")` | `old_admin`, `new_admin` |

Events are published only after every validation for the call has passed.
