//! Persistence for [`Device`] and [`DeviceAttestation`] values: the storage
//! key scheme and the helper functions used to read and write them.

use soroban_sdk::{contracttype, Address, BytesN, Env, Vec};

use crate::types::{Device, DeviceAttestation};

/// Storage key scheme used by this contract.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// A single registered device, keyed by its `device_id`.
    Device(BytesN<32>),
    /// The index of device IDs belonging to a given patient.
    PatientDevices(Address),
    /// A single attestation, keyed by its `attestation_id`.
    Attestation(u64),
    /// The index of attestation IDs submitted by a given device.
    DeviceAttestations(BytesN<32>),
    /// The index of attestation IDs recorded for a given patient, across all
    /// of their registered devices.
    PatientAttestations(Address),
    /// Monotonic counter used to allocate the next `attestation_id`.
    NextAttestationId,
    /// Marks a sha256 fingerprint of a `(device_id, reading_hash,
    /// recorded_at)` tuple as already submitted, so a resubmission of the
    /// same reading can be rejected as a duplicate.
    AttestationSeen(BytesN<32>),
}

// Devices and attestations must outlive normal temporary-storage windows.
// The network caps these values, so the SDK only extends a value when it is
// below the threshold and never beyond the network's configured maximum.
const TTL_THRESHOLD: u32 = 2_592_000;
const TTL_BUMP: u32 = 5_184_000;

fn bump_ttl(env: &Env, key: &DataKey) {
    env.storage()
        .persistent()
        .extend_ttl(key, TTL_THRESHOLD, TTL_BUMP);
}

/// Reads a registered device by its `device_id`, if it exists.
pub fn read_device(env: &Env, device_id: &BytesN<32>) -> Option<Device> {
    let key = DataKey::Device(device_id.clone());
    let device = env.storage().persistent().get(&key);
    if device.is_some() {
        bump_ttl(env, &key);
    }
    device
}

/// Persists (or overwrites) a device record under its `device_id`.
pub fn write_device(env: &Env, device: &Device) {
    let key = DataKey::Device(device.device_id.clone());
    env.storage().persistent().set(&key, device);
    bump_ttl(env, &key);
}

/// Returns whether a device with the given `device_id` is already registered.
pub fn device_exists(env: &Env, device_id: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .has(&DataKey::Device(device_id.clone()))
}

/// Adds `device_id` to the index of devices owned by `owner`, if it is not
/// already present.
pub(crate) fn add_device_to_patient_index(env: &Env, owner: &Address, device_id: &BytesN<32>) {
    let key = DataKey::PatientDevices(owner.clone());
    let storage = env.storage().persistent();

    let mut index = storage
        .get::<DataKey, Vec<BytesN<32>>>(&key)
        .unwrap_or(Vec::new(env));
    if !index.contains(device_id) {
        index.push_back(device_id.clone());
    }
    storage.set(&key, &index);
    bump_ttl(env, &key);
}

/// Returns the next unused attestation identifier, advancing the counter.
///
/// Identifiers are allocated starting at 1.
pub(crate) fn next_attestation_id(env: &Env) -> u64 {
    let key = DataKey::NextAttestationId;
    let storage = env.storage().persistent();

    let next = storage.get::<DataKey, u64>(&key).unwrap_or(0) + 1;
    storage.set(&key, &next);
    bump_ttl(env, &key);

    next
}

/// Persists `attestation`, indexing it under its device and patient, and
/// recording `fingerprint` (a sha256 of the attestation's `(device_id,
/// reading_hash, recorded_at)` tuple, computed by the caller) so
/// [`attestation_seen`] can detect a resubmission of the same reading.
pub(crate) fn write_attestation(env: &Env, attestation: &DeviceAttestation, fingerprint: &BytesN<32>) {
    let storage = env.storage().persistent();

    let attestation_key = DataKey::Attestation(attestation.attestation_id);
    storage.set(&attestation_key, attestation);
    bump_ttl(env, &attestation_key);

    let device_key = DataKey::DeviceAttestations(attestation.device_id.clone());
    let mut device_index = storage
        .get::<DataKey, Vec<u64>>(&device_key)
        .unwrap_or(Vec::new(env));
    if !device_index.contains(attestation.attestation_id) {
        device_index.push_back(attestation.attestation_id);
    }
    storage.set(&device_key, &device_index);
    bump_ttl(env, &device_key);

    let patient_key = DataKey::PatientAttestations(attestation.passport_id.clone());
    let mut patient_index = storage
        .get::<DataKey, Vec<u64>>(&patient_key)
        .unwrap_or(Vec::new(env));
    if !patient_index.contains(attestation.attestation_id) {
        patient_index.push_back(attestation.attestation_id);
    }
    storage.set(&patient_key, &patient_index);
    bump_ttl(env, &patient_key);

    let seen_key = DataKey::AttestationSeen(fingerprint.clone());
    storage.set(&seen_key, &true);
    bump_ttl(env, &seen_key);
}

/// Returns the attestation stored under `attestation_id`, if any.
pub(crate) fn read_attestation(env: &Env, attestation_id: u64) -> Option<DeviceAttestation> {
    let key = DataKey::Attestation(attestation_id);
    let storage = env.storage().persistent();

    let attestation = storage.get(&key);
    if attestation.is_some() {
        bump_ttl(env, &key);
    }
    attestation
}

/// Returns every `attestation_id` submitted by `device_id`, in submission
/// order. Returns an empty vector for a device with no attestations or an
/// unknown `device_id`.
pub(crate) fn read_device_attestations(env: &Env, device_id: &BytesN<32>) -> Vec<u64> {
    let key = DataKey::DeviceAttestations(device_id.clone());
    let storage = env.storage().persistent();

    let index = storage
        .get::<DataKey, Vec<u64>>(&key)
        .unwrap_or(Vec::new(env));
    if !index.is_empty() {
        bump_ttl(env, &key);
    }
    index
}

/// Returns every `attestation_id` recorded for `passport_id`, across all of
/// their registered devices, in submission order.
pub(crate) fn read_patient_attestations(env: &Env, passport_id: &Address) -> Vec<u64> {
    let key = DataKey::PatientAttestations(passport_id.clone());
    let storage = env.storage().persistent();

    let index = storage
        .get::<DataKey, Vec<u64>>(&key)
        .unwrap_or(Vec::new(env));
    if !index.is_empty() {
        bump_ttl(env, &key);
    }
    index
}

/// Returns whether `fingerprint` was already recorded by a prior
/// [`write_attestation`] call, i.e. whether the reading it represents has
/// already been submitted.
pub(crate) fn attestation_seen(env: &Env, fingerprint: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .has(&DataKey::AttestationSeen(fingerprint.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DeviceCategory;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Bytes;

    fn sample_device(env: &Env) -> Device {
        Device {
            device_id: BytesN::from_array(env, &[7u8; 32]),
            owner: Address::generate(env),
            issuer: Address::generate(env),
            category: DeviceCategory::GlucoseMonitor,
            public_key: BytesN::from_array(env, &[9u8; 32]),
            active: true,
            registered_at: 12_345,
        }
    }

    fn sample_attestation(env: &Env, attestation_id: u64, device_id: BytesN<32>) -> DeviceAttestation {
        DeviceAttestation {
            attestation_id,
            device_id,
            passport_id: Address::generate(env),
            reading_hash: BytesN::from_array(env, &[3u8; 32]),
            recorded_at: 1_000,
            submitted_at: 1_010,
            issuer_reference: Bytes::new(env),
        }
    }

    #[test]
    fn write_then_read_device() {
        let env = Env::default();
        let contract_id = env.register(crate::DeviceDataAttestation, ());

        env.as_contract(&contract_id, || {
            let device = sample_device(&env);
            write_device(&env, &device);

            let loaded = read_device(&env, &device.device_id).unwrap();
            assert_eq!(loaded, device);
            assert!(device_exists(&env, &device.device_id));
        });
    }

    #[test]
    fn missing_device_lookup_returns_none() {
        let env = Env::default();
        let contract_id = env.register(crate::DeviceDataAttestation, ());

        env.as_contract(&contract_id, || {
            let unknown_id = BytesN::from_array(&env, &[0u8; 32]);
            assert!(read_device(&env, &unknown_id).is_none());
            assert!(!device_exists(&env, &unknown_id));
        });
    }

    #[test]
    fn add_device_to_patient_index_is_idempotent() {
        let env = Env::default();
        let contract_id = env.register(crate::DeviceDataAttestation, ());

        env.as_contract(&contract_id, || {
            let owner = Address::generate(&env);
            let device_id = BytesN::from_array(&env, &[1u8; 32]);

            add_device_to_patient_index(&env, &owner, &device_id);
            add_device_to_patient_index(&env, &owner, &device_id);

            let index = env
                .storage()
                .persistent()
                .get::<DataKey, Vec<BytesN<32>>>(&DataKey::PatientDevices(owner))
                .unwrap();
            assert_eq!(index.len(), 1);
            assert_eq!(index.get(0).unwrap(), device_id);
        });
    }

    #[test]
    fn write_then_read_attestation() {
        let env = Env::default();
        let contract_id = env.register(crate::DeviceDataAttestation, ());

        env.as_contract(&contract_id, || {
            let device_id = BytesN::from_array(&env, &[4u8; 32]);
            let attestation = sample_attestation(&env, 1, device_id);
            let fingerprint = BytesN::from_array(&env, &[5u8; 32]);
            write_attestation(&env, &attestation, &fingerprint);

            assert_eq!(read_attestation(&env, 1), Some(attestation.clone()));
            assert!(attestation_seen(&env, &fingerprint));

            let device_index = read_device_attestations(&env, &attestation.device_id);
            assert_eq!(device_index, Vec::from_array(&env, [1]));

            let patient_index = read_patient_attestations(&env, &attestation.passport_id);
            assert_eq!(patient_index, Vec::from_array(&env, [1]));
        });
    }

    #[test]
    fn missing_attestation_lookup_returns_none() {
        let env = Env::default();
        let contract_id = env.register(crate::DeviceDataAttestation, ());

        env.as_contract(&contract_id, || {
            assert_eq!(read_attestation(&env, 42), None);
            let unknown_fingerprint = BytesN::from_array(&env, &[0u8; 32]);
            assert!(!attestation_seen(&env, &unknown_fingerprint));
        });
    }

    #[test]
    fn next_attestation_id_increments_monotonically() {
        let env = Env::default();
        let contract_id = env.register(crate::DeviceDataAttestation, ());

        env.as_contract(&contract_id, || {
            assert_eq!(next_attestation_id(&env), 1);
            assert_eq!(next_attestation_id(&env), 2);
            assert_eq!(next_attestation_id(&env), 3);
        });
    }
}
