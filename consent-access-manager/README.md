# Consent & Access Manager

Controls who can access a patient's medical records, for how long, and under
which record scope.

**What it does**
* Allows providers to request access to patient records.
* Allows patients to approve or reject requests.
* Supports limited access by record type.
* Supports expiry-based access.
* Allows patients to revoke access anytime.
* Creates an on-chain consent trail.

## Record scopes

| Scope | Grants access to |
| --- | --- |
| `AllRecords` | Every record category held for the patient. |
| `LabResultsOnly` | Laboratory results only. |
| `PrescriptionsOnly` | Prescriptions only. |
| `VaccinationRecordsOnly` | Vaccination records only. |
| `EmergencySummaryOnly` | Emergency summary only (e.g. blood type, allergies). |
| `InsuranceDataOnly` | Insurance-related data only. |

A grant for `AllRecords` satisfies any narrower scope query. Every other scope
matches only itself.

## Data stored

Each `AccessRequest` records: `access_id`, `passport_id`, `provider_id`,
`record_scope`, `duration_seconds`, `approved`, `expires_at`, `revoked`,
`rejected`, and `created_at`.

Rejection and revocation are stored as flags on the request rather than by
removing it from the patient's index, so the index remains a full consent
trail. Active grants are derived by filtering on `approved`, `revoked`, and
`expires_at`.

## Public API

```rust
pub fn request_access(
    env: Env,
    provider_id: Address,
    passport_id: Address,
    record_scope: RecordScope,
    duration_seconds: u64,
) -> Result<u64, Error>;

pub fn approve_access(
    env: Env,
    passport_id: Address,
    access_id: u64,
) -> Result<(), Error>;

pub fn reject_access(
    env: Env,
    passport_id: Address,
    access_id: u64,
) -> Result<(), Error>;

pub fn revoke_access(
    env: Env,
    passport_id: Address,
    access_id: u64,
) -> Result<(), Error>;

pub fn check_access(
    env: Env,
    passport_id: Address,
    provider_id: Address,
    record_scope: RecordScope,
) -> bool;

pub fn get_active_permissions(env: Env, passport_id: Address) -> Vec<AccessRequest>;
```

* `request_access` requires the provider's authorization and rejects a zero
  duration with `Error::InvalidDuration`. Re-requesting the same
  provider/scope pair creates a new independent grant.
* `approve_access`, `reject_access`, and `revoke_access` require the owning
  patient passport's authorization.
* `check_access` and `get_active_permissions` are read-only and require no
  authorization.
* Revocation is idempotent: revoking an already-revoked request succeeds.
* Expiry is enforced lazily on every read path through the shared `is_active`
  helper. A grant is valid while `expires_at > env.ledger().timestamp()`.

## Events

Every event uses fixed topics `("access", <verb>)`, so indexers can subscribe to
the `"access"` topic and branch on the verb. The event schema is defined in
`src/events.rs`.

| Event | Topics | Data |
| --- | --- | --- |
| `AccessRequested` | `("access", "requested")` | `access_id`, `passport_id`, `provider_id`, `record_scope` |
| `AccessApproved` | `("access", "approved")` | `access_id`, `passport_id`, `provider_id` |
| `AccessRejected` | `("access", "rejected")` | `access_id`, `passport_id`, `provider_id` |
| `AccessRevoked` | `("access", "revoked")` | `access_id`, `passport_id`, `provider_id`, `revoked_at` |

Events are emitted only on successful state changes. Natural expiry does not
emit an event because it is evaluated lazily when access state is read.

## Errors

All expected failures return a typed `Error` variant:

| Error | Returned when |
| --- | --- |
| `InvalidDuration` | A request uses a zero `duration_seconds`. |
| `RequestNotFound` | No request exists for the given `access_id`. |
| `NotOwner` | The request belongs to a different passport. |
| `AlreadyRevoked` | The request is already revoked. |
| `AlreadyApproved` | The request is already approved. |
| `AlreadyRejected` | The request is already rejected. |

## Build & Test

From the repository root:

```sh
cargo test -p consent-access-manager
cargo clippy -p consent-access-manager --all-targets -- -D warnings
cargo fmt --all -- --check
```

Build the contract for Stellar/Soroban:

```sh
rustup target add wasm32v1-none
cargo build -p consent-access-manager --target wasm32v1-none --release
```

Generate the API documentation:

```sh
cargo doc -p consent-access-manager --no-deps
```
