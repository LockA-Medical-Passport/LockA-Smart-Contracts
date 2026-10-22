//! Contract events emitted by [`crate::ProviderRegistry`].
//!
//! Provider lifecycle events use fixed topics `("provider", <verb>)`, and
//! admin handover uses `("provider_registry", "admin_transferred")`, so an
//! off-chain indexer can subscribe to either topic and branch on the verb
//! without decoding event data. Each event's data is a map keyed by its field
//! names (the [`contractevent`] default `data_format`). This module is the
//! single source of truth for the event schema; publish events by constructing
//! one of these types and calling `.publish(&env)`, rather than calling
//! `env.events().publish(...)` directly at call sites.

use soroban_sdk::{contractevent, Address, Symbol};

use crate::types::{ProviderStatus, ProviderType};

/// Emitted when [`crate::ProviderRegistry::register_provider`] records a new
/// provider application.
///
/// - Topics: `("provider", "registered")`
/// - Data: `provider_id: u64`, `provider_wallet_address: Address`,
///   `provider_type: ProviderType`, `country: Symbol`
#[contractevent(topics = ["provider", "registered"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRegistered {
    pub provider_id: u64,
    pub provider_wallet_address: Address,
    pub provider_type: ProviderType,
    pub country: Symbol,
}

/// Emitted when [`crate::ProviderRegistry::verify_provider`] verifies a
/// pending provider.
///
/// - Topics: `("provider", "verified")`
/// - Data: `provider_id: u64`, `provider_wallet_address: Address`,
///   `verified_by: Address`
#[contractevent(topics = ["provider", "verified"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderVerified {
    pub provider_id: u64,
    pub provider_wallet_address: Address,
    pub verified_by: Address,
}

/// Emitted when a provider's status changes via
/// [`crate::ProviderRegistry::suspend_provider`],
/// [`crate::ProviderRegistry::reinstate_provider`], or
/// [`crate::ProviderRegistry::revoke_provider`].
///
/// - Topics: `("provider", "status_changed")`
/// - Data: `provider_id: u64`, `old_status: ProviderStatus`,
///   `new_status: ProviderStatus`, `changed_by: Address`
#[contractevent(topics = ["provider", "status_changed"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderStatusChanged {
    pub provider_id: u64,
    pub old_status: ProviderStatus,
    pub new_status: ProviderStatus,
    pub changed_by: Address,
}

/// Emitted when [`crate::ProviderRegistry::transfer_admin`] hands control of
/// the registry to a new admin.
///
/// - Topics: `("provider_registry", "admin_transferred")`
/// - Data: `old_admin: Address`, `new_admin: Address`
#[contractevent(topics = ["provider_registry", "admin_transferred"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferred {
    pub old_admin: Address,
    pub new_admin: Address,
}
