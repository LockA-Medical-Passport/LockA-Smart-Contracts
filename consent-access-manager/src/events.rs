//! Contract events emitted by [`crate::ConsentAccessManager`].
//!
//! Every event uses fixed topics `("access", <verb>)`, so an off-chain
//! indexer can subscribe to the `"access"` topic and branch on the verb
//! without decoding event data. Each event's data is a map keyed by its
//! field names (the [`contractevent`] default `data_format`). This module is
//! the single source of truth for the event schema; publish events by
//! constructing one of these types and calling `.publish(&env)`, rather than
//! calling `env.events().publish(...)` directly at call sites.

use soroban_sdk::{contractevent, Address};

use crate::RecordScope;

/// Emitted when [`crate::ConsentAccessManager::request_access`] records a new
/// access request.
///
/// - Topics: `("access", "requested")`
/// - Data: `access_id: u64`, `passport_id: Address`, `provider_id: Address`,
///   `record_scope: RecordScope`
#[contractevent(topics = ["access", "requested"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequested {
    pub access_id: u64,
    pub passport_id: Address,
    pub provider_id: Address,
    pub record_scope: RecordScope,
}

/// Emitted when [`crate::ConsentAccessManager::approve_access`] approves a
/// request.
///
/// - Topics: `("access", "approved")`
/// - Data: `access_id: u64`, `passport_id: Address`, `provider_id: Address`
#[contractevent(topics = ["access", "approved"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessApproved {
    pub access_id: u64,
    pub passport_id: Address,
    pub provider_id: Address,
}

/// Emitted when [`crate::ConsentAccessManager::reject_access`] rejects a
/// request.
///
/// - Topics: `("access", "rejected")`
/// - Data: `access_id: u64`, `passport_id: Address`, `provider_id: Address`
#[contractevent(topics = ["access", "rejected"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRejected {
    pub access_id: u64,
    pub passport_id: Address,
    pub provider_id: Address,
}

/// Emitted when [`crate::ConsentAccessManager::revoke_access`] revokes a
/// request, immediately withdrawing any access it granted.
///
/// - Topics: `("access", "revoked")`
/// - Data: `access_id: u64`, `passport_id: Address`, `provider_id: Address`,
///   `revoked_at: u64` (ledger timestamp of the revocation)
#[contractevent(topics = ["access", "revoked"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRevoked {
    pub access_id: u64,
    pub passport_id: Address,
    pub provider_id: Address,
    pub revoked_at: u64,
}
