use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::testutils::{
    Address as _, AuthorizedFunction, AuthorizedInvocation, Events as _, Ledger, MockAuth,
    MockAuthInvoke,
};
use soroban_sdk::{Address, Bytes, BytesN, Env, Event as _, IntoVal, InvokeError, Symbol, Vec};

use crate::attestation_message_bytes;
use crate::storage::{read_attestation, read_device, DataKey};
use crate::{
    AttestationSubmitted, Device, DeviceAttestation, DeviceCategory, DeviceDataAttestation,
    DeviceDataAttestationClient, DeviceReactivated, DeviceRegistered, DeviceRevoked, Error,
    MAX_READING_AGE,
};

const NOW: u64 = 1_700_000_000;

struct Fixture {
    env: Env,
    contract_id: Address,
    issuer: Address,
    owner: Address,
}

impl Fixture {
    fn new() -> Self {
        let env = Env::default();
        env.ledger().set_timestamp(NOW);

        let contract_id = env.register(DeviceDataAttestation, ());
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);

        Fixture {
            env,
            contract_id,
            issuer,
            owner,
        }
    }

    fn client(&self) -> DeviceDataAttestationClient<'_> {
        DeviceDataAttestationClient::new(&self.env, &self.contract_id)
    }

    fn stored_device(&self, device_id: &BytesN<32>) -> Option<Device> {
        self.env
            .as_contract(&self.contract_id, || read_device(&self.env, device_id))
    }

    fn stored_attestation(&self, attestation_id: u64) -> Option<DeviceAttestation> {
        self.env
            .as_contract(&self.contract_id, || read_attestation(&self.env, attestation_id))
    }

    fn patient_devices(&self) -> Vec<BytesN<32>> {
        self.env.as_contract(&self.contract_id, || {
            self.env
                .storage()
                .persistent()
                .get::<DataKey, Vec<BytesN<32>>>(&DataKey::PatientDevices(self.owner.clone()))
                .unwrap_or(Vec::new(&self.env))
        })
    }

    /// Registers a fresh device owned by `self.owner` and issued by
    /// `self.issuer`, returning its id and signing key.
    fn register_device(&self, seed: u8) -> (BytesN<32>, SigningKey) {
        self.env.mock_all_auths();

        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let device_id = BytesN::from_array(&self.env, &[seed; 32]);
        let public_key = BytesN::from_array(&self.env, &signing_key.verifying_key().to_bytes());

        self.client().register_device(
            &self.issuer,
            &device_id,
            &self.owner,
            &DeviceCategory::GlucoseMonitor,
            &public_key,
        );

        (device_id, signing_key)
    }

    fn sign(
        &self,
        signing_key: &SigningKey,
        device_id: &BytesN<32>,
        reading_hash: &BytesN<32>,
        recorded_at: u64,
    ) -> BytesN<64> {
        let message = attestation_message_bytes(device_id, reading_hash, recorded_at);
        let signature = signing_key.sign(&message);
        BytesN::from_array(&self.env, &signature.to_bytes())
    }
}

#[test]
fn contract_registers_and_builds_a_client() {
    let env = Env::default();
    let contract_id = env.register(DeviceDataAttestation, ());
    let _client = DeviceDataAttestationClient::new(&env, &contract_id);
}

// --- register_device ---

#[test]
fn register_device_stores_an_active_device_and_indexes_it() {
    let fixture = Fixture::new();
    let (device_id, signing_key) = fixture.register_device(1);

    let device = fixture.stored_device(&device_id).unwrap();
    assert_eq!(device.device_id, device_id);
    assert_eq!(device.owner, fixture.owner);
    assert_eq!(device.issuer, fixture.issuer);
    assert_eq!(device.category, DeviceCategory::GlucoseMonitor);
    assert_eq!(
        device.public_key,
        BytesN::from_array(&fixture.env, &signing_key.verifying_key().to_bytes())
    );
    assert!(device.active);
    assert_eq!(device.registered_at, NOW);

    let index = fixture.patient_devices();
    assert_eq!(index.len(), 1);
    assert_eq!(index.get(0).unwrap(), device_id);
}

#[test]
fn register_device_is_authorized_by_the_issuer() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let device_id = BytesN::from_array(&fixture.env, &[1u8; 32]);
    let public_key = BytesN::from_array(&fixture.env, &[2u8; 32]);

    fixture.client().register_device(
        &fixture.issuer,
        &device_id,
        &fixture.owner,
        &DeviceCategory::Thermometer,
        &public_key,
    );

    assert_eq!(
        fixture.env.auths(),
        [(
            fixture.issuer.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    fixture.contract_id.clone(),
                    Symbol::new(&fixture.env, "register_device"),
                    (
                        fixture.issuer.clone(),
                        device_id.clone(),
                        fixture.owner.clone(),
                        DeviceCategory::Thermometer,
                        public_key.clone(),
                    )
                        .into_val(&fixture.env),
                )),
                sub_invocations: [].into(),
            }
        )]
    );
}

#[test]
fn register_device_fails_without_the_issuers_authorization() {
    let fixture = Fixture::new();
    let impostor = Address::generate(&fixture.env);

    let device_id = BytesN::from_array(&fixture.env, &[1u8; 32]);
    let public_key = BytesN::from_array(&fixture.env, &[2u8; 32]);

    fixture.env.mock_auths(&[MockAuth {
        address: &impostor,
        invoke: &MockAuthInvoke {
            contract: &fixture.contract_id,
            fn_name: "register_device",
            args: (
                fixture.issuer.clone(),
                device_id.clone(),
                fixture.owner.clone(),
                DeviceCategory::GlucoseMonitor,
                public_key.clone(),
            )
                .into_val(&fixture.env),
            sub_invokes: &[],
        },
    }]);

    let result = fixture.client().try_register_device(
        &fixture.issuer,
        &device_id,
        &fixture.owner,
        &DeviceCategory::GlucoseMonitor,
        &public_key,
    );

    assert_eq!(result, Err(Err(InvokeError::Abort)));
    assert!(fixture.stored_device(&device_id).is_none());
}

#[test]
fn register_device_rejects_a_duplicate_device_id() {
    let fixture = Fixture::new();
    let (device_id, _) = fixture.register_device(1);

    let other_owner = Address::generate(&fixture.env);
    let result = fixture.client().try_register_device(
        &fixture.issuer,
        &device_id,
        &other_owner,
        &DeviceCategory::Wearable,
        &BytesN::from_array(&fixture.env, &[9u8; 32]),
    );

    assert_eq!(result, Err(Ok(Error::DeviceAlreadyRegistered)));
    // The original registration must survive an attempted overwrite.
    assert_eq!(fixture.stored_device(&device_id).unwrap().owner, fixture.owner);
}

#[test]
fn register_device_publishes_a_device_registered_event() {
    let fixture = Fixture::new();
    let (device_id, signing_key) = fixture.register_device(1);

    let expected = DeviceRegistered {
        device_id: device_id.clone(),
        owner: fixture.owner.clone(),
        issuer: fixture.issuer.clone(),
        category: DeviceCategory::GlucoseMonitor,
    };

    assert_eq!(
        fixture.env.events().all(),
        [expected.to_xdr(&fixture.env, &fixture.contract_id)]
    );
    let _ = signing_key;
}

#[test]
fn register_device_does_not_publish_an_event_when_it_fails() {
    let fixture = Fixture::new();
    let (device_id, _) = fixture.register_device(1);

    let result = fixture.client().try_register_device(
        &fixture.issuer,
        &device_id,
        &fixture.owner,
        &DeviceCategory::GlucoseMonitor,
        &BytesN::from_array(&fixture.env, &[9u8; 32]),
    );
    assert_eq!(result, Err(Ok(Error::DeviceAlreadyRegistered)));
    // `events().all()` scopes to the most recent top-level invocation, so
    // this reflects only the rejected second call.
    assert!(fixture.env.events().all().events().is_empty());
}

// --- revoke_device / reactivate_device ---

#[test]
fn revoke_device_deactivates_a_registered_device() {
    let fixture = Fixture::new();
    let (device_id, _) = fixture.register_device(1);

    fixture.client().revoke_device(&fixture.issuer, &device_id);

    assert!(!fixture.stored_device(&device_id).unwrap().active);
}

#[test]
fn reactivate_device_reactivates_a_revoked_device() {
    let fixture = Fixture::new();
    let (device_id, _) = fixture.register_device(1);

    fixture.client().revoke_device(&fixture.issuer, &device_id);
    fixture
        .client()
        .reactivate_device(&fixture.issuer, &device_id);

    assert!(fixture.stored_device(&device_id).unwrap().active);
}

#[test]
fn revoke_device_fails_for_an_unknown_device_id() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let unknown_id = BytesN::from_array(&fixture.env, &[0u8; 32]);
    let result = fixture
        .client()
        .try_revoke_device(&fixture.issuer, &unknown_id);

    assert_eq!(result, Err(Ok(Error::DeviceNotFound)));
}

#[test]
fn reactivate_device_fails_for_an_unknown_device_id() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let unknown_id = BytesN::from_array(&fixture.env, &[0u8; 32]);
    let result = fixture
        .client()
        .try_reactivate_device(&fixture.issuer, &unknown_id);

    assert_eq!(result, Err(Ok(Error::DeviceNotFound)));
}

#[test]
fn revoke_device_fails_for_a_caller_that_is_not_the_registered_issuer() {
    let fixture = Fixture::new();
    let (device_id, _) = fixture.register_device(1);

    let impostor_issuer = Address::generate(&fixture.env);
    fixture.env.mock_all_auths();
    let result = fixture
        .client()
        .try_revoke_device(&impostor_issuer, &device_id);

    assert_eq!(result, Err(Ok(Error::NotDeviceIssuer)));
    assert!(fixture.stored_device(&device_id).unwrap().active);
}

#[test]
fn reactivate_device_fails_for_a_caller_that_is_not_the_registered_issuer() {
    let fixture = Fixture::new();
    let (device_id, _) = fixture.register_device(1);
    fixture.client().revoke_device(&fixture.issuer, &device_id);

    let impostor_issuer = Address::generate(&fixture.env);
    fixture.env.mock_all_auths();
    let result = fixture
        .client()
        .try_reactivate_device(&impostor_issuer, &device_id);

    assert_eq!(result, Err(Ok(Error::NotDeviceIssuer)));
    assert!(!fixture.stored_device(&device_id).unwrap().active);
}

#[test]
fn revoke_device_fails_without_the_issuers_authorization() {
    let fixture = Fixture::new();
    let (device_id, _) = fixture.register_device(1);

    let impostor = Address::generate(&fixture.env);
    fixture.env.mock_auths(&[MockAuth {
        address: &impostor,
        invoke: &MockAuthInvoke {
            contract: &fixture.contract_id,
            fn_name: "revoke_device",
            args: (fixture.issuer.clone(), device_id.clone()).into_val(&fixture.env),
            sub_invokes: &[],
        },
    }]);

    let result = fixture
        .client()
        .try_revoke_device(&fixture.issuer, &device_id);

    assert_eq!(result, Err(Err(InvokeError::Abort)));
    assert!(fixture.stored_device(&device_id).unwrap().active);
}

#[test]
fn reactivate_device_fails_without_the_issuers_authorization() {
    let fixture = Fixture::new();
    let (device_id, _) = fixture.register_device(1);
    fixture.client().revoke_device(&fixture.issuer, &device_id);

    let impostor = Address::generate(&fixture.env);
    fixture.env.mock_auths(&[MockAuth {
        address: &impostor,
        invoke: &MockAuthInvoke {
            contract: &fixture.contract_id,
            fn_name: "reactivate_device",
            args: (fixture.issuer.clone(), device_id.clone()).into_val(&fixture.env),
            sub_invokes: &[],
        },
    }]);

    let result = fixture
        .client()
        .try_reactivate_device(&fixture.issuer, &device_id);

    assert_eq!(result, Err(Err(InvokeError::Abort)));
    assert!(!fixture.stored_device(&device_id).unwrap().active);
}

#[test]
fn revoke_device_publishes_a_device_revoked_event() {
    let fixture = Fixture::new();
    let (device_id, _) = fixture.register_device(1);
    fixture.client().revoke_device(&fixture.issuer, &device_id);

    let expected = DeviceRevoked {
        device_id: device_id.clone(),
        owner: fixture.owner.clone(),
        issuer: fixture.issuer.clone(),
    };

    assert_eq!(
        *fixture.env.events().all().events().last().unwrap(),
        expected.to_xdr(&fixture.env, &fixture.contract_id)
    );
}

#[test]
fn reactivate_device_publishes_a_device_reactivated_event() {
    let fixture = Fixture::new();
    let (device_id, _) = fixture.register_device(1);
    fixture.client().revoke_device(&fixture.issuer, &device_id);
    fixture
        .client()
        .reactivate_device(&fixture.issuer, &device_id);

    let expected = DeviceReactivated {
        device_id: device_id.clone(),
        owner: fixture.owner.clone(),
        issuer: fixture.issuer.clone(),
    };

    assert_eq!(
        *fixture.env.events().all().events().last().unwrap(),
        expected.to_xdr(&fixture.env, &fixture.contract_id)
    );
}

// --- submit_attestation ---

#[test]
fn submit_attestation_records_a_valid_signed_reading() {
    let fixture = Fixture::new();
    let (device_id, signing_key) = fixture.register_device(1);

    let reading_hash = BytesN::from_array(&fixture.env, &[42u8; 32]);
    let recorded_at = NOW - 10;
    let signature = fixture.sign(&signing_key, &device_id, &reading_hash, recorded_at);
    let issuer_reference = Bytes::from_array(&fixture.env, b"batch-1");

    let attestation_id = fixture.client().submit_attestation(
        &device_id,
        &fixture.owner,
        &reading_hash,
        &recorded_at,
        &issuer_reference,
        &signature,
    );

    assert_eq!(attestation_id, 1);

    let attestation = fixture.stored_attestation(1).unwrap();
    assert_eq!(attestation.attestation_id, 1);
    assert_eq!(attestation.device_id, device_id);
    assert_eq!(attestation.passport_id, fixture.owner);
    assert_eq!(attestation.reading_hash, reading_hash);
    assert_eq!(attestation.recorded_at, recorded_at);
    assert_eq!(attestation.submitted_at, NOW);
    assert_eq!(attestation.issuer_reference, issuer_reference);

    assert_eq!(
        fixture.client().get_attestations_for_device(&device_id),
        Vec::from_array(&fixture.env, [attestation.clone()])
    );
    assert_eq!(
        fixture.client().get_attestations_for_patient(&fixture.owner),
        Vec::from_array(&fixture.env, [attestation])
    );
}

#[test]
fn submit_attestation_does_not_require_auth_from_the_caller() {
    // No mock_all_auths / mock_auths at all: submit_attestation is gated
    // purely by the device's ed25519 signature, not a Soroban `require_auth`.
    let fixture = Fixture::new();
    let (device_id, signing_key) = fixture.register_device(1);

    let reading_hash = BytesN::from_array(&fixture.env, &[1u8; 32]);
    let recorded_at = NOW - 10;
    let signature = fixture.sign(&signing_key, &device_id, &reading_hash, recorded_at);

    let attestation_id = fixture.client().submit_attestation(
        &device_id,
        &fixture.owner,
        &reading_hash,
        &recorded_at,
        &Bytes::new(&fixture.env),
        &signature,
    );

    assert_eq!(attestation_id, 1);
}

#[test]
fn submit_attestation_fails_for_an_unknown_device() {
    let fixture = Fixture::new();

    let unknown_id = BytesN::from_array(&fixture.env, &[0u8; 32]);
    let result = fixture.client().try_submit_attestation(
        &unknown_id,
        &fixture.owner,
        &BytesN::from_array(&fixture.env, &[1u8; 32]),
        &(NOW - 10),
        &Bytes::new(&fixture.env),
        &BytesN::from_array(&fixture.env, &[0u8; 64]),
    );

    assert_eq!(result, Err(Ok(Error::DeviceNotFound)));
}

#[test]
fn submit_attestation_fails_for_an_inactive_device() {
    let fixture = Fixture::new();
    let (device_id, signing_key) = fixture.register_device(1);
    fixture.client().revoke_device(&fixture.issuer, &device_id);

    let reading_hash = BytesN::from_array(&fixture.env, &[1u8; 32]);
    let recorded_at = NOW - 10;
    let signature = fixture.sign(&signing_key, &device_id, &reading_hash, recorded_at);

    let result = fixture.client().try_submit_attestation(
        &device_id,
        &fixture.owner,
        &reading_hash,
        &recorded_at,
        &Bytes::new(&fixture.env),
        &signature,
    );

    assert_eq!(result, Err(Ok(Error::DeviceInactive)));
}

#[test]
fn submit_attestation_fails_for_an_owner_mismatch() {
    let fixture = Fixture::new();
    let (device_id, signing_key) = fixture.register_device(1);
    let stranger = Address::generate(&fixture.env);

    let reading_hash = BytesN::from_array(&fixture.env, &[1u8; 32]);
    let recorded_at = NOW - 10;
    let signature = fixture.sign(&signing_key, &device_id, &reading_hash, recorded_at);

    let result = fixture.client().try_submit_attestation(
        &device_id,
        &stranger,
        &reading_hash,
        &recorded_at,
        &Bytes::new(&fixture.env),
        &signature,
    );

    assert_eq!(result, Err(Ok(Error::DeviceOwnerMismatch)));
}

#[test]
fn submit_attestation_fails_for_a_forged_signature() {
    let fixture = Fixture::new();
    let (device_id, _) = fixture.register_device(1);
    let forger = SigningKey::from_bytes(&[99u8; 32]);

    let reading_hash = BytesN::from_array(&fixture.env, &[1u8; 32]);
    let recorded_at = NOW - 10;
    // Signed with a key other than the device's registered one.
    let signature = fixture.sign(&forger, &device_id, &reading_hash, recorded_at);

    let result = fixture.client().try_submit_attestation(
        &device_id,
        &fixture.owner,
        &reading_hash,
        &recorded_at,
        &Bytes::new(&fixture.env),
        &signature,
    );

    assert_eq!(result, Err(Err(InvokeError::Abort)));
    assert!(fixture.stored_attestation(1).is_none());
}

#[test]
fn submit_attestation_fails_for_a_future_dated_reading() {
    let fixture = Fixture::new();
    let (device_id, signing_key) = fixture.register_device(1);

    let reading_hash = BytesN::from_array(&fixture.env, &[1u8; 32]);
    let recorded_at = NOW + 1;
    let signature = fixture.sign(&signing_key, &device_id, &reading_hash, recorded_at);

    let result = fixture.client().try_submit_attestation(
        &device_id,
        &fixture.owner,
        &reading_hash,
        &recorded_at,
        &Bytes::new(&fixture.env),
        &signature,
    );

    assert_eq!(result, Err(Ok(Error::FutureDatedReading)));
}

#[test]
fn submit_attestation_fails_for_a_stale_reading() {
    let fixture = Fixture::new();
    let (device_id, signing_key) = fixture.register_device(1);

    let reading_hash = BytesN::from_array(&fixture.env, &[1u8; 32]);
    let recorded_at = NOW - MAX_READING_AGE - 1;
    let signature = fixture.sign(&signing_key, &device_id, &reading_hash, recorded_at);

    let result = fixture.client().try_submit_attestation(
        &device_id,
        &fixture.owner,
        &reading_hash,
        &recorded_at,
        &Bytes::new(&fixture.env),
        &signature,
    );

    assert_eq!(result, Err(Ok(Error::StaleReading)));
}

#[test]
fn submit_attestation_accepts_a_reading_exactly_at_the_freshness_boundary() {
    let fixture = Fixture::new();
    let (device_id, signing_key) = fixture.register_device(1);

    let reading_hash = BytesN::from_array(&fixture.env, &[1u8; 32]);
    let recorded_at = NOW - MAX_READING_AGE;
    let signature = fixture.sign(&signing_key, &device_id, &reading_hash, recorded_at);

    let attestation_id = fixture.client().submit_attestation(
        &device_id,
        &fixture.owner,
        &reading_hash,
        &recorded_at,
        &Bytes::new(&fixture.env),
        &signature,
    );

    assert_eq!(attestation_id, 1);
}

#[test]
fn submit_attestation_fails_for_a_duplicate_submission() {
    let fixture = Fixture::new();
    let (device_id, signing_key) = fixture.register_device(1);

    let reading_hash = BytesN::from_array(&fixture.env, &[1u8; 32]);
    let recorded_at = NOW - 10;
    let signature = fixture.sign(&signing_key, &device_id, &reading_hash, recorded_at);
    let issuer_reference = Bytes::new(&fixture.env);

    fixture.client().submit_attestation(
        &device_id,
        &fixture.owner,
        &reading_hash,
        &recorded_at,
        &issuer_reference,
        &signature,
    );

    let result = fixture.client().try_submit_attestation(
        &device_id,
        &fixture.owner,
        &reading_hash,
        &recorded_at,
        &issuer_reference,
        &signature,
    );

    assert_eq!(result, Err(Ok(Error::DuplicateAttestation)));
    assert!(fixture.stored_attestation(2).is_none());
}

#[test]
fn submit_attestation_publishes_an_attestation_submitted_event() {
    let fixture = Fixture::new();
    let (device_id, signing_key) = fixture.register_device(1);

    let reading_hash = BytesN::from_array(&fixture.env, &[1u8; 32]);
    let recorded_at = NOW - 10;
    let signature = fixture.sign(&signing_key, &device_id, &reading_hash, recorded_at);

    let attestation_id = fixture.client().submit_attestation(
        &device_id,
        &fixture.owner,
        &reading_hash,
        &recorded_at,
        &Bytes::new(&fixture.env),
        &signature,
    );

    let expected = AttestationSubmitted {
        attestation_id,
        device_id: device_id.clone(),
        passport_id: fixture.owner.clone(),
        reading_hash: reading_hash.clone(),
        recorded_at,
    };

    assert_eq!(
        *fixture.env.events().all().events().last().unwrap(),
        expected.to_xdr(&fixture.env, &fixture.contract_id)
    );
}

#[test]
fn submit_attestation_does_not_publish_an_event_when_it_fails() {
    let fixture = Fixture::new();

    let unknown_id = BytesN::from_array(&fixture.env, &[0u8; 32]);
    let result = fixture.client().try_submit_attestation(
        &unknown_id,
        &fixture.owner,
        &BytesN::from_array(&fixture.env, &[1u8; 32]),
        &(NOW - 10),
        &Bytes::new(&fixture.env),
        &BytesN::from_array(&fixture.env, &[0u8; 64]),
    );

    assert_eq!(result, Err(Ok(Error::DeviceNotFound)));
    assert!(fixture.env.events().all().events().is_empty());
}

// --- get_attestations_for_patient / get_attestations_for_device ---

#[test]
fn get_attestations_for_patient_returns_empty_for_an_unknown_patient() {
    let fixture = Fixture::new();
    let stranger = Address::generate(&fixture.env);

    assert!(fixture
        .client()
        .get_attestations_for_patient(&stranger)
        .is_empty());
}

#[test]
fn get_attestations_for_device_returns_empty_for_an_unknown_device() {
    let fixture = Fixture::new();
    let unknown_id = BytesN::from_array(&fixture.env, &[0u8; 32]);

    assert!(fixture
        .client()
        .get_attestations_for_device(&unknown_id)
        .is_empty());
}

#[test]
fn get_attestations_for_patient_aggregates_across_the_patients_devices() {
    let fixture = Fixture::new();
    let (device_a, key_a) = fixture.register_device(1);
    let (device_b, key_b) = fixture.register_device(2);

    let reading_hash = BytesN::from_array(&fixture.env, &[1u8; 32]);
    let recorded_at_a = NOW - 100;
    let signature_a = fixture.sign(&key_a, &device_a, &reading_hash, recorded_at_a);
    fixture.client().submit_attestation(
        &device_a,
        &fixture.owner,
        &reading_hash,
        &recorded_at_a,
        &Bytes::new(&fixture.env),
        &signature_a,
    );

    let recorded_at_b = NOW - 50;
    let signature_b = fixture.sign(&key_b, &device_b, &reading_hash, recorded_at_b);
    fixture.client().submit_attestation(
        &device_b,
        &fixture.owner,
        &reading_hash,
        &recorded_at_b,
        &Bytes::new(&fixture.env),
        &signature_b,
    );

    let attestations = fixture
        .client()
        .get_attestations_for_patient(&fixture.owner);
    assert_eq!(attestations.len(), 2);
    assert_eq!(attestations.get(0).unwrap().device_id, device_a);
    assert_eq!(attestations.get(1).unwrap().device_id, device_b);
}

#[test]
fn get_attestations_for_device_returns_only_that_devices_history() {
    let fixture = Fixture::new();
    let (device_a, key_a) = fixture.register_device(1);
    let (device_b, key_b) = fixture.register_device(2);

    let reading_hash = BytesN::from_array(&fixture.env, &[1u8; 32]);
    let recorded_at = NOW - 100;
    let signature_a = fixture.sign(&key_a, &device_a, &reading_hash, recorded_at);
    fixture.client().submit_attestation(
        &device_a,
        &fixture.owner,
        &reading_hash,
        &recorded_at,
        &Bytes::new(&fixture.env),
        &signature_a,
    );

    let signature_b = fixture.sign(&key_b, &device_b, &reading_hash, recorded_at);
    fixture.client().submit_attestation(
        &device_b,
        &fixture.owner,
        &reading_hash,
        &recorded_at,
        &Bytes::new(&fixture.env),
        &signature_b,
    );

    let attestations = fixture.client().get_attestations_for_device(&device_a);
    assert_eq!(attestations.len(), 1);
    assert_eq!(attestations.get(0).unwrap().device_id, device_a);
}
