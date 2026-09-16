//! Contract events emitted by [`crate::DeviceDataAttestation`].
//!
//! Device lifecycle events use fixed topics `("device", <verb>)`, and
//! attestation submission uses `("attestation", "submitted")`, so an
//! off-chain indexer can subscribe to either topic and branch on the verb
//! without decoding event data. Each event's data is a map keyed by its
//! field names (the [`contractevent`] default `data_format`). This module is
//! the single source of truth for the event schema; publish events by
//! constructing one of these types and calling `.publish(&env)`, rather than
//! calling `env.events().publish(...)` directly at call sites.

use soroban_sdk::{contractevent, Address, BytesN};

use crate::DeviceCategory;

/// Emitted when [`crate::DeviceDataAttestation::register_device`] registers a
/// new device.
///
/// - Topics: `("device", "registered")`
/// - Data: `device_id: BytesN<32>`, `owner: Address`, `issuer: Address`,
///   `category: DeviceCategory`
#[contractevent(topics = ["device", "registered"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRegistered {
    pub device_id: BytesN<32>,
    pub owner: Address,
    pub issuer: Address,
    pub category: DeviceCategory,
}

/// Emitted when [`crate::DeviceDataAttestation::revoke_device`] revokes a
/// device.
///
/// - Topics: `("device", "revoked")`
/// - Data: `device_id: BytesN<32>`, `owner: Address`, `issuer: Address`
#[contractevent(topics = ["device", "revoked"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRevoked {
    pub device_id: BytesN<32>,
    pub owner: Address,
    pub issuer: Address,
}

/// Emitted when [`crate::DeviceDataAttestation::reactivate_device`]
/// reactivates a device.
///
/// - Topics: `("device", "reactivated")`
/// - Data: `device_id: BytesN<32>`, `owner: Address`, `issuer: Address`
#[contractevent(topics = ["device", "reactivated"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceReactivated {
    pub device_id: BytesN<32>,
    pub owner: Address,
    pub issuer: Address,
}

/// Emitted when [`crate::DeviceDataAttestation::submit_attestation`] records
/// a new attestation. Published only after signature verification and every
/// other validation has passed.
///
/// - Topics: `("attestation", "submitted")`
/// - Data: `attestation_id: u64`, `device_id: BytesN<32>`,
///   `passport_id: Address`, `reading_hash: BytesN<32>`, `recorded_at: u64`
#[contractevent(topics = ["attestation", "submitted"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationSubmitted {
    pub attestation_id: u64,
    pub device_id: BytesN<32>,
    pub passport_id: Address,
    pub reading_hash: BytesN<32>,
    pub recorded_at: u64,
}
