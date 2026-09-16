//! Typed failure reasons returned by the public contract API.

use soroban_sdk::contracterror;

/// Errors returned by [`DeviceDataAttestation`](crate::DeviceDataAttestation).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// A device with this `device_id` is already registered; a device can
    /// only be registered once.
    DeviceAlreadyRegistered = 1,
    /// No [`Device`](crate::Device) is stored under the given `device_id`.
    DeviceNotFound = 2,
    /// The device exists but has been revoked, so it cannot submit
    /// attestations.
    DeviceInactive = 3,
    /// The `passport_id` supplied does not match the device's registered
    /// `owner`.
    DeviceOwnerMismatch = 4,
    /// The caller does not match the device's registered `issuer`, so it has
    /// no right to change the device's lifecycle state.
    NotDeviceIssuer = 5,
    /// The signature does not verify against the device's registered
    /// `public_key`.
    ///
    /// In practice, `env.crypto().ed25519_verify` traps the transaction
    /// before this variant can be constructed and returned — the host
    /// function has no fallible form, only a panicking one — so this
    /// documents that failure mode in the contract's public error surface
    /// rather than being a value this crate's own code ever returns.
    InvalidSignature = 6,
    /// `recorded_at` is further in the past than the freshness window this
    /// contract enforces (see `MAX_READING_AGE` in `lib.rs`).
    StaleReading = 7,
    /// `recorded_at` is in the future relative to the ledger timestamp.
    FutureDatedReading = 8,
    /// An attestation with the same `(device_id, reading_hash, recorded_at)`
    /// has already been submitted.
    DuplicateAttestation = 9,
}
