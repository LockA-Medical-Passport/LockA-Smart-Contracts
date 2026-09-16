#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Vec};

mod error;
mod events;
mod storage;
mod types;

pub use error::Error;
pub use events::{AttestationSubmitted, DeviceReactivated, DeviceRegistered, DeviceRevoked};
pub use types::{Device, DeviceAttestation, DeviceCategory};

#[contract]
pub struct DeviceDataAttestation;

/// Freshness window enforced on `recorded_at` by [`DeviceDataAttestation::submit_attestation`]:
/// an attestation is rejected as [`Error::StaleReading`] once the ledger
/// clock is more than this many seconds ahead of the device-reported reading
/// time. Chosen generously (24 hours) to tolerate offline/store-and-forward
/// devices that batch readings before submitting them, while still bounding
/// how long a captured signed payload remains replayable.
const MAX_READING_AGE: u64 = 24 * 60 * 60;

/// Builds the message a device signs when submitting an attestation:
/// `device_id || reading_hash || recorded_at` (the timestamp encoded
/// big-endian). This is the exact layout [`DeviceDataAttestation::submit_attestation`]
/// verifies against the device's registered `public_key`.
fn attestation_message_bytes(
    device_id: &BytesN<32>,
    reading_hash: &BytesN<32>,
    recorded_at: u64,
) -> [u8; 72] {
    let mut message = [0u8; 72];
    message[..32].copy_from_slice(&device_id.to_array());
    message[32..64].copy_from_slice(&reading_hash.to_array());
    message[64..].copy_from_slice(&recorded_at.to_be_bytes());
    message
}

#[contractimpl]
impl DeviceDataAttestation {
    /// Registers a new approved device and links it to the owning patient's
    /// passport.
    ///
    /// Only `issuer` can register a device on its own behalf; only `issuer`
    /// can later revoke or reactivate it (see [`Self::revoke_device`] and
    /// [`Self::reactivate_device`]). The device starts `active` and is added
    /// to `owner`'s device index. Fails with [`Error::DeviceAlreadyRegistered`]
    /// if `device_id` is already registered.
    pub fn register_device(
        env: Env,
        issuer: Address,
        device_id: BytesN<32>,
        owner: Address,
        category: DeviceCategory,
        public_key: BytesN<32>,
    ) -> Result<(), Error> {
        issuer.require_auth();

        if storage::device_exists(&env, &device_id) {
            return Err(Error::DeviceAlreadyRegistered);
        }

        let device = Device {
            device_id: device_id.clone(),
            owner: owner.clone(),
            issuer: issuer.clone(),
            category: category.clone(),
            public_key,
            active: true,
            registered_at: env.ledger().timestamp(),
        };
        storage::write_device(&env, &device);
        storage::add_device_to_patient_index(&env, &owner, &device_id);

        DeviceRegistered {
            device_id,
            owner,
            issuer,
            category,
        }
        .publish(&env);

        Ok(())
    }

    /// Revokes a registered device, e.g. because it was compromised or
    /// decommissioned. A revoked device can no longer submit attestations
    /// via [`Self::submit_attestation`] until it is reactivated.
    ///
    /// Only the device's registered `issuer` can revoke it. Fails with
    /// [`Error::DeviceNotFound`] if `device_id` does not exist, or with
    /// [`Error::NotDeviceIssuer`] if the caller is not that device's
    /// registered issuer. Revoking an already-revoked device is idempotent
    /// and succeeds without error.
    pub fn revoke_device(env: Env, issuer: Address, device_id: BytesN<32>) -> Result<(), Error> {
        issuer.require_auth();

        let mut device = storage::read_device(&env, &device_id).ok_or(Error::DeviceNotFound)?;
        if device.issuer != issuer {
            return Err(Error::NotDeviceIssuer);
        }

        device.active = false;
        storage::write_device(&env, &device);

        DeviceRevoked {
            device_id: device.device_id,
            owner: device.owner,
            issuer: device.issuer,
        }
        .publish(&env);

        Ok(())
    }

    /// Reactivates a device that was previously revoked, e.g. because it was
    /// revoked in error.
    ///
    /// Only the device's registered `issuer` can reactivate it. Fails with
    /// [`Error::DeviceNotFound`] if `device_id` does not exist, or with
    /// [`Error::NotDeviceIssuer`] if the caller is not that device's
    /// registered issuer. Reactivating an already-active device is
    /// idempotent and succeeds without error.
    pub fn reactivate_device(
        env: Env,
        issuer: Address,
        device_id: BytesN<32>,
    ) -> Result<(), Error> {
        issuer.require_auth();

        let mut device = storage::read_device(&env, &device_id).ok_or(Error::DeviceNotFound)?;
        if device.issuer != issuer {
            return Err(Error::NotDeviceIssuer);
        }

        device.active = true;
        storage::write_device(&env, &device);

        DeviceReactivated {
            device_id: device.device_id,
            owner: device.owner,
            issuer: device.issuer,
        }
        .publish(&env);

        Ok(())
    }

    /// Anchors a verifiable, signed device reading on-chain, returning the
    /// new `attestation_id`.
    ///
    /// Unlike the device lifecycle functions, this call is not gated by
    /// `require_auth()` on a Soroban address: a device is not a Stellar
    /// account, so its authority is instead proven by an ed25519 signature
    /// over `device_id || reading_hash || recorded_at`, verified against the
    /// device's registered `public_key`. Any caller (e.g. a relayer or
    /// gateway) may submit on the device's behalf as long as they hold a
    /// validly signed payload.
    ///
    /// Validation, in order: the device must exist ([`Error::DeviceNotFound`])
    /// and be active ([`Error::DeviceInactive`]); `passport_id` must match
    /// the device's registered `owner` ([`Error::DeviceOwnerMismatch`]);
    /// `recorded_at` must not be in the future ([`Error::FutureDatedReading`])
    /// nor older than `MAX_READING_AGE` ([`Error::StaleReading`]); the
    /// `(device_id, reading_hash, recorded_at)` tuple must not have been
    /// submitted before ([`Error::DuplicateAttestation`]); finally the
    /// `signature` is verified via `env.crypto().ed25519_verify`, which
    /// traps the transaction on a forged or mismatched signature rather than
    /// returning [`Error::InvalidSignature`] (see that variant's doc comment).
    /// The trapping check runs last so every other, non-trapping rejection
    /// is checked — and returned as a typed error — first.
    ///
    /// On success, the attestation is persisted and indexed under both its
    /// device and patient, and an [`AttestationSubmitted`] event is published.
    pub fn submit_attestation(
        env: Env,
        device_id: BytesN<32>,
        passport_id: Address,
        reading_hash: BytesN<32>,
        recorded_at: u64,
        issuer_reference: Bytes,
        signature: BytesN<64>,
    ) -> Result<u64, Error> {
        let device = storage::read_device(&env, &device_id).ok_or(Error::DeviceNotFound)?;
        if !device.active {
            return Err(Error::DeviceInactive);
        }
        if device.owner != passport_id {
            return Err(Error::DeviceOwnerMismatch);
        }

        let now = env.ledger().timestamp();
        if recorded_at > now {
            return Err(Error::FutureDatedReading);
        }
        if now - recorded_at > MAX_READING_AGE {
            return Err(Error::StaleReading);
        }

        let message_bytes = attestation_message_bytes(&device_id, &reading_hash, recorded_at);
        let message = Bytes::from_array(&env, &message_bytes);
        let fingerprint = env.crypto().sha256(&message).to_bytes();
        if storage::attestation_seen(&env, &fingerprint) {
            return Err(Error::DuplicateAttestation);
        }

        env.crypto()
            .ed25519_verify(&device.public_key, &message, &signature);

        let attestation_id = storage::next_attestation_id(&env);
        let attestation = DeviceAttestation {
            attestation_id,
            device_id,
            passport_id,
            reading_hash,
            recorded_at,
            submitted_at: now,
            issuer_reference,
        };
        storage::write_attestation(&env, &attestation, &fingerprint);

        AttestationSubmitted {
            attestation_id: attestation.attestation_id,
            device_id: attestation.device_id,
            passport_id: attestation.passport_id,
            reading_hash: attestation.reading_hash,
            recorded_at: attestation.recorded_at,
        }
        .publish(&env);

        Ok(attestation_id)
    }

    /// Returns every attestation recorded for `passport_id`, across all of
    /// their registered devices, in submission order.
    ///
    /// Read-only: no authorization is required, since the result only
    /// contains state already scoped to `passport_id`. Returns an empty
    /// vector for a patient with no attestations.
    ///
    /// This walks every attestation ever recorded for the patient and
    /// returns all of them in one call, with no cap or pagination. That is
    /// acceptable for the attestation volumes this contract expects, but a
    /// patient with an unusually large reading history could make this call
    /// read and return an unbounded number of ledger entries. If that
    /// becomes a real constraint, switch to a paginated interface (e.g. a
    /// `starting_after: Option<u64>` plus `limit: u32`) rather than
    /// returning everything.
    pub fn get_attestations_for_patient(env: Env, passport_id: Address) -> Vec<DeviceAttestation> {
        let mut attestations = Vec::new(&env);
        for attestation_id in storage::read_patient_attestations(&env, &passport_id) {
            if let Some(attestation) = storage::read_attestation(&env, attestation_id) {
                attestations.push_back(attestation);
            }
        }
        attestations
    }

    /// Returns every attestation submitted by `device_id`, in submission
    /// order.
    ///
    /// Read-only: no authorization is required. Returns an empty vector for
    /// a device with no attestations or an unknown `device_id`, rather than
    /// panicking. Subject to the same unbounded-result caveat documented on
    /// [`Self::get_attestations_for_patient`].
    pub fn get_attestations_for_device(env: Env, device_id: BytesN<32>) -> Vec<DeviceAttestation> {
        let mut attestations = Vec::new(&env);
        for attestation_id in storage::read_device_attestations(&env, &device_id) {
            if let Some(attestation) = storage::read_attestation(&env, attestation_id) {
                attestations.push_back(attestation);
            }
        }
        attestations
    }
}

#[cfg(test)]
mod test;
