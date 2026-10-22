//! Typed failure reasons returned by the public contract API.

use soroban_sdk::contracterror;

/// Errors returned by [`ProviderRegistry`](crate::ProviderRegistry).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// The contract has not been initialized with an admin yet.
    NotInitialized = 1,
    /// [`crate::ProviderRegistry::initialize`] has already been called.
    AlreadyInitialized = 2,
    /// The caller is authenticated but is not the stored contract admin.
    NotAdmin = 3,
    /// No provider is stored under the given `provider_id`.
    ProviderNotFound = 4,
    /// The wallet address is already linked to a provider entry.
    WalletAlreadyRegistered = 5,
    /// The requested status change is not allowed from the provider's current
    /// status (see [`crate::is_valid_transition`]).
    InvalidStatusTransition = 6,
    /// [`crate::ProviderRegistry::transfer_admin`] was called with the current
    /// admin as the new admin, which would be a pointless no-op.
    SameAdmin = 7,
}
