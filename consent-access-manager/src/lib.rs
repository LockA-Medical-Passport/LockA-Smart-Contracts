//! Consent and access control for LockA medical passports.
//!
//! Providers request access to a patient's records under a [`RecordScope`],
//! and the patient decides whether to approve, reject, or later revoke that
//! access. See [`ConsentAccessManager`] for the public contract API and the
//! re-exported event types for the schema emitted on every state change.

#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Vec};

mod error;
mod events;
mod storage;
mod types;

pub use error::Error;
pub use events::{AccessApproved, AccessRejected, AccessRequested, AccessRevoked};
pub use storage::AccessRequest;
pub use types::RecordScope;

/// The consent and access manager contract, exposing the provider-request and
/// patient-decision API for record access grants.
#[contract]
pub struct ConsentAccessManager;

#[contractimpl]
impl ConsentAccessManager {
    /// Records a provider's request for access to a patient's records.
    ///
    /// The request starts unapproved and unrevoked: `approved` and `revoked`
    /// are `false`, `rejected` is `false`, and `expires_at` stays `0` until
    /// the patient approves it and the requested `duration_seconds` window
    /// begins. Emits an [`AccessRequested`] event on success.
    ///
    /// Requesting the same `provider_id`/`record_scope` combination again
    /// while an earlier grant is still active is allowed: each call creates a
    /// new, independent request with its own `access_id`. Access remains
    /// valid while any one of those grants is active.
    ///
    /// # Arguments
    ///
    /// * `provider_id` - The provider requesting access; must authorize the
    ///   call.
    /// * `passport_id` - The patient passport whose records are requested.
    /// * `record_scope` - The record categories the provider is asking for.
    /// * `duration_seconds` - How long access should last once approved; must
    ///   be greater than zero.
    ///
    /// # Returns
    ///
    /// The newly allocated `access_id`, which the patient uses to approve or
    /// reject the request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDuration`] when `duration_seconds` is zero.
    pub fn request_access(
        env: Env,
        provider_id: Address,
        passport_id: Address,
        record_scope: RecordScope,
        duration_seconds: u64,
    ) -> Result<u64, Error> {
        provider_id.require_auth();

        if duration_seconds == 0 {
            return Err(Error::InvalidDuration);
        }

        let access_id = storage::next_access_id(&env);
        let request = AccessRequest {
            access_id,
            passport_id,
            provider_id,
            record_scope,
            duration_seconds,
            approved: false,
            expires_at: 0,
            revoked: false,
            rejected: false,
            created_at: env.ledger().timestamp(),
        };
        storage::write_access_request(&env, &request);

        AccessRequested {
            access_id: request.access_id,
            passport_id: request.passport_id,
            provider_id: request.provider_id,
            record_scope: request.record_scope,
        }
        .publish(&env);

        Ok(access_id)
    }

    /// Approves a pending access request, activating it for the duration the
    /// provider requested.
    ///
    /// `duration_seconds` is carried from the original `request_access`
    /// call rather than accepted again here, so a patient cannot be tricked
    /// into granting a longer window than the one they were shown when the
    /// request was made. `expires_at` is set to `env.ledger().timestamp() +
    /// duration_seconds` at approval time. Emits an [`AccessApproved`] event on
    /// success.
    ///
    /// Approving an already-approved request is allowed and refreshes
    /// `expires_at` from the current ledger time.
    ///
    /// # Arguments
    ///
    /// * `passport_id` - The patient passport that owns the request; must
    ///   authorize the call.
    /// * `access_id` - The request to approve.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RequestNotFound`] if `access_id` does not exist,
    /// [`Error::NotOwner`] if it belongs to a different passport,
    /// [`Error::AlreadyRevoked`] if it was revoked, or
    /// [`Error::AlreadyRejected`] if it was rejected.
    pub fn approve_access(env: Env, passport_id: Address, access_id: u64) -> Result<(), Error> {
        passport_id.require_auth();

        let mut request =
            storage::read_access_request(&env, access_id).ok_or(Error::RequestNotFound)?;
        if request.passport_id != passport_id {
            return Err(Error::NotOwner);
        }
        if request.revoked {
            return Err(Error::AlreadyRevoked);
        }
        if request.rejected {
            return Err(Error::AlreadyRejected);
        }

        request.approved = true;
        request.expires_at = env.ledger().timestamp() + request.duration_seconds;
        storage::write_access_request(&env, &request);

        AccessApproved {
            access_id: request.access_id,
            passport_id: request.passport_id,
            provider_id: request.provider_id,
        }
        .publish(&env);

        Ok(())
    }

    /// Rejects a pending access request instead of approving it.
    ///
    /// Rejection is recorded on the request itself via the `rejected` field
    /// (see the doc comment on [`AccessRequest`]) rather than by removing it
    /// from the patient's request index, so the index remains a full consent
    /// trail. Emits an [`AccessRejected`] event on success.
    ///
    /// # Arguments
    ///
    /// * `passport_id` - The patient passport that owns the request; must
    ///   authorize the call.
    /// * `access_id` - The request to reject.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RequestNotFound`] if `access_id` does not exist,
    /// [`Error::NotOwner`] if it belongs to a different passport,
    /// [`Error::AlreadyApproved`] if it was already approved,
    /// [`Error::AlreadyRevoked`] if it was already revoked, or
    /// [`Error::AlreadyRejected`] if it was already rejected.
    pub fn reject_access(env: Env, passport_id: Address, access_id: u64) -> Result<(), Error> {
        passport_id.require_auth();

        let mut request =
            storage::read_access_request(&env, access_id).ok_or(Error::RequestNotFound)?;
        if request.passport_id != passport_id {
            return Err(Error::NotOwner);
        }
        if request.approved {
            return Err(Error::AlreadyApproved);
        }
        if request.revoked {
            return Err(Error::AlreadyRevoked);
        }
        if request.rejected {
            return Err(Error::AlreadyRejected);
        }

        request.rejected = true;
        storage::write_access_request(&env, &request);

        AccessRejected {
            access_id: request.access_id,
            passport_id: request.passport_id,
            provider_id: request.provider_id,
        }
        .publish(&env);

        Ok(())
    }

    /// Revokes an access grant, immediately invalidating it regardless of
    /// its current `approved` or `expires_at` state.
    ///
    /// Like rejection, revocation is recorded via the `revoked` field on the
    /// request itself (see the doc comment on [`AccessRequest`]); the entry
    /// stays in the patient's request index. Emits an [`AccessRevoked`] event
    /// on every successful call.
    ///
    /// Revoking an already-revoked request is idempotent and succeeds without
    /// error, so callers don't need to check current state before revoking.
    ///
    /// # Arguments
    ///
    /// * `passport_id` - The patient passport that owns the request; must
    ///   authorize the call.
    /// * `access_id` - The request to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RequestNotFound`] if `access_id` does not exist, or
    /// [`Error::NotOwner`] if it belongs to a different passport.
    pub fn revoke_access(env: Env, passport_id: Address, access_id: u64) -> Result<(), Error> {
        passport_id.require_auth();

        let mut request =
            storage::read_access_request(&env, access_id).ok_or(Error::RequestNotFound)?;
        if request.passport_id != passport_id {
            return Err(Error::NotOwner);
        }

        request.revoked = true;
        storage::write_access_request(&env, &request);

        AccessRevoked {
            access_id: request.access_id,
            passport_id: request.passport_id,
            provider_id: request.provider_id,
            revoked_at: env.ledger().timestamp(),
        }
        .publish(&env);

        Ok(())
    }

    /// Returns whether `provider_id` currently has valid access to
    /// `passport_id`'s records under `record_scope`.
    ///
    /// Access is valid when a matching request exists with `approved ==
    /// true`, `revoked == false`, `expires_at > env.ledger().timestamp()`,
    /// and either its `record_scope` matches the query or the stored scope is
    /// [`RecordScope::AllRecords`]. Read-only: no authorization is required,
    /// so any caller (e.g. the `medical-record-registry` contract) can invoke
    /// it.
    ///
    /// # Arguments
    ///
    /// * `passport_id` - The patient passport being queried.
    /// * `provider_id` - The provider whose access is being checked.
    /// * `record_scope` - The record category the caller wants to access.
    ///
    /// # Returns
    ///
    /// `true` if at least one active grant for `provider_id` covers
    /// `record_scope`, or `false` when no request matches. This function never
    /// panics for missing state.
    pub fn check_access(
        env: Env,
        passport_id: Address,
        provider_id: Address,
        record_scope: RecordScope,
    ) -> bool {
        let now = env.ledger().timestamp();

        for access_id in storage::read_patient_index(&env, &passport_id) {
            let Some(request) = storage::read_access_request(&env, access_id) else {
                continue;
            };

            let scope_matches = request.record_scope == record_scope
                || request.record_scope == RecordScope::AllRecords;

            if request.provider_id == provider_id
                && storage::is_active(&request, now)
                && scope_matches
            {
                return true;
            }
        }

        false
    }

    /// Returns every currently active grant for `passport_id`: `approved`,
    /// not `revoked`, and not yet expired, per the same shared `is_active`
    /// definition also used by `check_access`.
    ///
    /// Results are ordered by ascending `access_id`, i.e. the order the
    /// underlying requests were created in (the order `request_access`
    /// appended them to the patient's index).
    ///
    /// Read-only: no authorization is required, since the result only
    /// contains state already scoped to `passport_id`.
    ///
    /// # Arguments
    ///
    /// * `passport_id` - The patient passport whose active grants are listed.
    ///
    /// # Returns
    ///
    /// A vector of active [`AccessRequest`] values, empty when the passport has
    /// no active grants.
    ///
    /// This walks every `access_id` ever recorded for the passport and
    /// returns every active match in one call, with no cap or pagination.
    /// That is acceptable for the request volumes this contract expects
    /// (a patient's provider grants), but a passport with an unusually large
    /// request history could make this call read and return an unbounded
    /// number of ledger entries. If that becomes a real constraint, switch
    /// to a paginated interface (e.g. a `starting_after: Option<u64>` plus
    /// `limit: u32`) rather than returning everything.
    pub fn get_active_permissions(env: Env, passport_id: Address) -> Vec<AccessRequest> {
        let now = env.ledger().timestamp();
        let mut active = Vec::new(&env);

        for access_id in storage::read_patient_index(&env, &passport_id) {
            if let Some(request) = storage::read_access_request(&env, access_id) {
                if storage::is_active(&request, now) {
                    active.push_back(request);
                }
            }
        }

        active
    }
}

#[cfg(test)]
mod test;
