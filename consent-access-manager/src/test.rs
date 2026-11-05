use soroban_sdk::testutils::{
    Address as _, AuthorizedFunction, AuthorizedInvocation, Events as _, Ledger, MockAuth,
    MockAuthInvoke,
};
use soroban_sdk::{Address, Env, Event as _, IntoVal, InvokeError, Symbol, Vec};

use crate::storage::{read_access_request, DataKey};
use crate::{
    AccessApproved, AccessRejected, AccessRequested, AccessRevoked, ConsentAccessManager,
    ConsentAccessManagerClient, Error, RecordScope,
};

const ONE_DAY: u64 = 86_400;
const REQUESTED_AT: u64 = 1_700_000_000;

struct Fixture {
    env: Env,
    contract_id: Address,
    provider_id: Address,
    passport_id: Address,
}

impl Fixture {
    fn new() -> Self {
        let env = Env::default();
        env.ledger().set_timestamp(REQUESTED_AT);

        let contract_id = env.register(ConsentAccessManager, ());
        let provider_id = Address::generate(&env);
        let passport_id = Address::generate(&env);

        Fixture {
            env,
            contract_id,
            provider_id,
            passport_id,
        }
    }

    fn client(&self) -> ConsentAccessManagerClient<'_> {
        ConsentAccessManagerClient::new(&self.env, &self.contract_id)
    }

    fn stored_request(&self, access_id: u64) -> Option<crate::AccessRequest> {
        self.env.as_contract(&self.contract_id, || {
            read_access_request(&self.env, access_id)
        })
    }

    fn create_and_approve_request(
        &self,
        provider_id: &Address,
        record_scope: RecordScope,
        duration_seconds: u64,
    ) -> u64 {
        let access_id = self.client().request_access(
            provider_id,
            &self.passport_id,
            &record_scope,
            &duration_seconds,
        );
        self.client().approve_access(&self.passport_id, &access_id);
        access_id
    }

    fn patient_index(&self) -> Vec<u64> {
        self.env.as_contract(&self.contract_id, || {
            self.env
                .storage()
                .persistent()
                .get::<DataKey, Vec<u64>>(&DataKey::PatientIndex(self.passport_id.clone()))
                .unwrap_or(Vec::new(&self.env))
        })
    }
}

#[test]
fn contract_registers_and_builds_a_client() {
    let env = Env::default();
    let contract_id = env.register(ConsentAccessManager, ());
    let _client = ConsentAccessManagerClient::new(&env, &contract_id);
}

#[test]
fn request_access_creates_a_pending_request() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );

    assert_eq!(access_id, 1);

    let request = fixture.stored_request(access_id).unwrap();
    assert_eq!(request.access_id, 1);
    assert_eq!(request.provider_id, fixture.provider_id);
    assert_eq!(request.passport_id, fixture.passport_id);
    assert_eq!(request.record_scope, RecordScope::LabResultsOnly);
    assert_eq!(request.duration_seconds, ONE_DAY);
    assert!(!request.approved);
    assert!(!request.revoked);
    assert_eq!(request.expires_at, 0, "expiry is unset until approval");
    assert_eq!(request.created_at, REQUESTED_AT);
}

#[test]
fn request_access_is_authorized_by_the_requesting_provider() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::AllRecords,
        &ONE_DAY,
    );

    assert_eq!(
        fixture.env.auths(),
        [(
            fixture.provider_id.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    fixture.contract_id.clone(),
                    Symbol::new(&fixture.env, "request_access"),
                    (
                        fixture.provider_id.clone(),
                        fixture.passport_id.clone(),
                        RecordScope::AllRecords,
                        ONE_DAY,
                    )
                        .into_val(&fixture.env),
                )),
                sub_invocations: [].into(),
            }
        )]
    );
}

#[test]
fn request_access_fails_without_the_providers_authorization() {
    let fixture = Fixture::new();
    let impostor = Address::generate(&fixture.env);

    // Authorization from anybody other than `provider_id` must not satisfy the
    // provider's `require_auth`.
    fixture.env.mock_auths(&[MockAuth {
        address: &impostor,
        invoke: &MockAuthInvoke {
            contract: &fixture.contract_id,
            fn_name: "request_access",
            args: (
                fixture.provider_id.clone(),
                fixture.passport_id.clone(),
                RecordScope::AllRecords,
                ONE_DAY,
            )
                .into_val(&fixture.env),
            sub_invokes: &[],
        },
    }]);

    let result = fixture.client().try_request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::AllRecords,
        &ONE_DAY,
    );

    assert_eq!(result, Err(Err(InvokeError::Abort)));
    assert!(
        fixture.stored_request(1).is_none(),
        "an unauthorized call must not persist a request"
    );
}

#[test]
fn request_access_rejects_a_zero_duration() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let result = fixture.client().try_request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::AllRecords,
        &0,
    );

    assert_eq!(result, Err(Ok(Error::InvalidDuration)));
    assert!(
        fixture.stored_request(1).is_none(),
        "a rejected request must not consume an access id"
    );
}

#[test]
fn request_access_allocates_sequential_ids_and_indexes_them_by_patient() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let client = fixture.client();
    let first = client.request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );
    let second = client.request_access(
        &Address::generate(&fixture.env),
        &fixture.passport_id,
        &RecordScope::PrescriptionsOnly,
        &(7 * ONE_DAY),
    );

    assert_eq!((first, second), (1, 2));
    assert_eq!(
        fixture.patient_index(),
        soroban_sdk::vec![&fixture.env, 1, 2]
    );
}

#[test]
fn request_access_keeps_each_patients_index_separate() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let other_passport_id = Address::generate(&fixture.env);
    let client = fixture.client();
    client.request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );
    client.request_access(
        &fixture.provider_id,
        &other_passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );

    assert_eq!(fixture.patient_index(), soroban_sdk::vec![&fixture.env, 1]);
}

// --- approve_access ---

#[test]
fn approve_access_activates_a_pending_request() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );

    let approved_at = REQUESTED_AT + 500;
    fixture.env.ledger().set_timestamp(approved_at);
    fixture
        .client()
        .approve_access(&fixture.passport_id, &access_id);

    let request = fixture.stored_request(access_id).unwrap();
    assert!(request.approved);
    assert!(!request.revoked);
    assert!(!request.rejected);
    assert_eq!(
        request.expires_at,
        approved_at + ONE_DAY,
        "expires_at must be computed from the approval time, not the request time"
    );
}

#[test]
fn approve_access_fails_without_the_passports_authorization() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );

    let impostor = Address::generate(&fixture.env);
    fixture.env.mock_auths(&[MockAuth {
        address: &impostor,
        invoke: &MockAuthInvoke {
            contract: &fixture.contract_id,
            fn_name: "approve_access",
            args: (fixture.passport_id.clone(), access_id).into_val(&fixture.env),
            sub_invokes: &[],
        },
    }]);

    let result = fixture
        .client()
        .try_approve_access(&fixture.passport_id, &access_id);

    assert_eq!(result, Err(Err(InvokeError::Abort)));
    assert!(!fixture.stored_request(access_id).unwrap().approved);
}

#[test]
fn approve_access_fails_for_an_already_revoked_request() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );
    fixture
        .client()
        .revoke_access(&fixture.passport_id, &access_id);

    let result = fixture
        .client()
        .try_approve_access(&fixture.passport_id, &access_id);

    assert_eq!(result, Err(Ok(Error::AlreadyRevoked)));
    assert!(!fixture.stored_request(access_id).unwrap().approved);
}

#[test]
fn approve_access_fails_for_an_already_rejected_request() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );
    fixture
        .client()
        .reject_access(&fixture.passport_id, &access_id);

    let result = fixture
        .client()
        .try_approve_access(&fixture.passport_id, &access_id);

    assert_eq!(result, Err(Ok(Error::AlreadyRejected)));
}

#[test]
fn approve_access_fails_for_a_nonexistent_access_id() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let result = fixture
        .client()
        .try_approve_access(&fixture.passport_id, &42);

    assert_eq!(result, Err(Ok(Error::RequestNotFound)));
}

#[test]
fn approve_access_fails_when_caller_does_not_own_the_request() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );

    let other_passport_id = Address::generate(&fixture.env);
    let result = fixture
        .client()
        .try_approve_access(&other_passport_id, &access_id);

    assert_eq!(result, Err(Ok(Error::NotOwner)));
    assert!(!fixture.stored_request(access_id).unwrap().approved);
}

// --- reject_access ---

#[test]
fn reject_access_marks_a_pending_request_rejected() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );
    fixture
        .client()
        .reject_access(&fixture.passport_id, &access_id);

    let request = fixture.stored_request(access_id).unwrap();
    assert!(request.rejected);
    assert!(!request.approved);
    assert!(!request.revoked);
}

#[test]
fn reject_access_fails_for_an_already_approved_request() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );

    let result = fixture
        .client()
        .try_reject_access(&fixture.passport_id, &access_id);

    assert_eq!(result, Err(Ok(Error::AlreadyApproved)));
    assert!(fixture.stored_request(access_id).unwrap().approved);
    assert!(!fixture.stored_request(access_id).unwrap().rejected);
}

#[test]
fn reject_access_fails_without_the_passports_authorization() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );

    let impostor = Address::generate(&fixture.env);
    fixture.env.mock_auths(&[MockAuth {
        address: &impostor,
        invoke: &MockAuthInvoke {
            contract: &fixture.contract_id,
            fn_name: "reject_access",
            args: (fixture.passport_id.clone(), access_id).into_val(&fixture.env),
            sub_invokes: &[],
        },
    }]);

    let result = fixture
        .client()
        .try_reject_access(&fixture.passport_id, &access_id);

    assert_eq!(result, Err(Err(InvokeError::Abort)));
    assert!(!fixture.stored_request(access_id).unwrap().rejected);
}

#[test]
fn reject_access_fails_when_caller_does_not_own_the_request() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );

    let other_passport_id = Address::generate(&fixture.env);
    let result = fixture
        .client()
        .try_reject_access(&other_passport_id, &access_id);

    assert_eq!(result, Err(Ok(Error::NotOwner)));
}

#[test]
fn reject_access_fails_for_a_nonexistent_access_id() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let result = fixture
        .client()
        .try_reject_access(&fixture.passport_id, &42);

    assert_eq!(result, Err(Ok(Error::RequestNotFound)));
}

#[test]
fn reject_access_fails_for_an_already_rejected_request() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );
    fixture
        .client()
        .reject_access(&fixture.passport_id, &access_id);

    let result = fixture
        .client()
        .try_reject_access(&fixture.passport_id, &access_id);

    assert_eq!(result, Err(Ok(Error::AlreadyRejected)));
}

// --- revoke_access ---

#[test]
fn revoke_access_revokes_an_active_grant() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );
    fixture
        .client()
        .revoke_access(&fixture.passport_id, &access_id);

    let request = fixture.stored_request(access_id).unwrap();
    assert!(request.revoked);
    assert!(request.approved, "revocation does not clear approved");
}

#[test]
fn revoke_access_revokes_a_pending_unapproved_request() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );
    fixture
        .client()
        .revoke_access(&fixture.passport_id, &access_id);

    assert!(fixture.stored_request(access_id).unwrap().revoked);
}

#[test]
fn revoke_access_is_idempotent_for_an_already_revoked_grant() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );
    fixture
        .client()
        .revoke_access(&fixture.passport_id, &access_id);

    let result = fixture
        .client()
        .try_revoke_access(&fixture.passport_id, &access_id);

    assert_eq!(result, Ok(Ok(())));
    assert!(fixture.stored_request(access_id).unwrap().revoked);
}

#[test]
fn revoke_access_fails_without_the_passports_authorization() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );

    let impostor = Address::generate(&fixture.env);
    fixture.env.mock_auths(&[MockAuth {
        address: &impostor,
        invoke: &MockAuthInvoke {
            contract: &fixture.contract_id,
            fn_name: "revoke_access",
            args: (fixture.passport_id.clone(), access_id).into_val(&fixture.env),
            sub_invokes: &[],
        },
    }]);

    let result = fixture
        .client()
        .try_revoke_access(&fixture.passport_id, &access_id);

    assert_eq!(result, Err(Err(InvokeError::Abort)));
    assert!(!fixture.stored_request(access_id).unwrap().revoked);
}

#[test]
fn revoke_access_fails_when_caller_does_not_own_the_request() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );

    let other_passport_id = Address::generate(&fixture.env);
    let result = fixture
        .client()
        .try_revoke_access(&other_passport_id, &access_id);

    assert_eq!(result, Err(Ok(Error::NotOwner)));
}

#[test]
fn revoke_access_fails_for_a_nonexistent_access_id() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let result = fixture
        .client()
        .try_revoke_access(&fixture.passport_id, &42);

    assert_eq!(result, Err(Ok(Error::RequestNotFound)));
}

// --- check_access ---

#[test]
fn check_access_returns_true_for_an_active_matching_grant() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );

    assert!(fixture.client().check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::LabResultsOnly,
    ));
}

#[test]
fn check_access_returns_false_for_an_expired_grant() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );

    fixture
        .env
        .ledger()
        .set_timestamp(REQUESTED_AT + ONE_DAY + 1);

    assert!(!fixture.client().check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::LabResultsOnly,
    ));
}

#[test]
fn check_access_returns_false_for_a_revoked_grant() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );
    fixture
        .client()
        .revoke_access(&fixture.passport_id, &access_id);

    assert!(!fixture.client().check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::LabResultsOnly,
    ));
}

#[test]
fn check_access_all_records_grant_satisfies_a_narrower_scope_query() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::AllRecords,
        ONE_DAY,
    );

    assert!(fixture.client().check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::PrescriptionsOnly,
    ));
}

#[test]
fn check_access_returns_false_for_a_non_matching_scope() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );

    assert!(!fixture.client().check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::PrescriptionsOnly,
    ));
}

#[test]
fn check_access_returns_false_when_no_request_exists() {
    let fixture = Fixture::new();

    assert!(!fixture.client().check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::LabResultsOnly,
    ));
}

#[test]
fn check_access_returns_false_for_an_unapproved_pending_request() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );

    assert!(!fixture.client().check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::LabResultsOnly,
    ));
}

// --- get_active_permissions ---

#[test]
fn get_active_permissions_returns_empty_for_a_patient_with_no_grants() {
    let fixture = Fixture::new();

    assert!(fixture
        .client()
        .get_active_permissions(&fixture.passport_id)
        .is_empty());
}

#[test]
fn get_active_permissions_filters_out_expired_revoked_and_unapproved_entries() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    // access_id 1: pending, never approved.
    fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );

    // access_id 2: approved, then revoked.
    let revoked_id = fixture.create_and_approve_request(
        &Address::generate(&fixture.env),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );
    fixture
        .client()
        .revoke_access(&fixture.passport_id, &revoked_id);

    // access_id 3: approved, then left to expire.
    fixture.create_and_approve_request(
        &Address::generate(&fixture.env),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );
    fixture
        .env
        .ledger()
        .set_timestamp(REQUESTED_AT + ONE_DAY + 1);

    // access_id 4: approved after the time advance, still active.
    let active_provider = Address::generate(&fixture.env);
    let active_id = fixture.create_and_approve_request(
        &active_provider,
        RecordScope::PrescriptionsOnly,
        ONE_DAY,
    );

    let active = fixture
        .client()
        .get_active_permissions(&fixture.passport_id);

    assert_eq!(active.len(), 1);
    assert_eq!(active.get(0).unwrap().access_id, active_id);
    assert_eq!(active.get(0).unwrap().provider_id, active_provider);
}

#[test]
fn get_active_permissions_returns_multiple_active_grants_in_creation_order() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let first_id = fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );
    let second_id = fixture.create_and_approve_request(
        &Address::generate(&fixture.env),
        RecordScope::PrescriptionsOnly,
        7 * ONE_DAY,
    );

    let active = fixture
        .client()
        .get_active_permissions(&fixture.passport_id);

    assert_eq!(active.len(), 2);
    assert_eq!(active.get(0).unwrap().access_id, first_id);
    assert_eq!(active.get(1).unwrap().access_id, second_id);
}

// --- lazy expiry boundary (shared is_active helper) ---

#[test]
fn check_access_flips_from_active_to_expired_at_the_ledger_boundary() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );

    fixture
        .env
        .ledger()
        .set_timestamp(REQUESTED_AT + ONE_DAY - 1);
    assert!(
        fixture.client().check_access(
            &fixture.passport_id,
            &fixture.provider_id,
            &RecordScope::LabResultsOnly,
        ),
        "must still be active the instant before expires_at"
    );

    fixture.env.ledger().set_timestamp(REQUESTED_AT + ONE_DAY);
    assert!(
        !fixture.client().check_access(
            &fixture.passport_id,
            &fixture.provider_id,
            &RecordScope::LabResultsOnly,
        ),
        "must be expired once now reaches expires_at"
    );
}

// --- events ---

#[test]
fn request_access_publishes_an_access_requested_event() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );

    let expected = AccessRequested {
        access_id,
        passport_id: fixture.passport_id.clone(),
        provider_id: fixture.provider_id.clone(),
        record_scope: RecordScope::LabResultsOnly,
    };

    assert_eq!(
        fixture.env.events().all(),
        [expected.to_xdr(&fixture.env, &fixture.contract_id)]
    );
}

#[test]
fn request_access_does_not_publish_an_event_when_it_fails() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let result = fixture.client().try_request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::AllRecords,
        &0,
    );

    assert_eq!(result, Err(Ok(Error::InvalidDuration)));
    assert!(fixture.env.events().all().events().is_empty());
}

#[test]
fn approve_access_publishes_an_access_approved_event() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );
    fixture
        .client()
        .approve_access(&fixture.passport_id, &access_id);

    let expected = AccessApproved {
        access_id,
        passport_id: fixture.passport_id.clone(),
        provider_id: fixture.provider_id.clone(),
    };

    assert_eq!(
        fixture.env.events().all(),
        [expected.to_xdr(&fixture.env, &fixture.contract_id)]
    );
}

#[test]
fn approve_access_does_not_publish_an_event_when_it_fails() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let result = fixture
        .client()
        .try_approve_access(&fixture.passport_id, &42);

    assert_eq!(result, Err(Ok(Error::RequestNotFound)));
    assert!(fixture.env.events().all().events().is_empty());
}

#[test]
fn reject_access_publishes_an_access_rejected_event() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );
    fixture
        .client()
        .reject_access(&fixture.passport_id, &access_id);

    let expected = AccessRejected {
        access_id,
        passport_id: fixture.passport_id.clone(),
        provider_id: fixture.provider_id.clone(),
    };

    assert_eq!(
        fixture.env.events().all(),
        [expected.to_xdr(&fixture.env, &fixture.contract_id)]
    );
}

#[test]
fn reject_access_does_not_publish_an_event_when_it_fails() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );

    let result = fixture
        .client()
        .try_reject_access(&fixture.passport_id, &access_id);

    assert_eq!(result, Err(Ok(Error::AlreadyApproved)));
    assert!(fixture.env.events().all().events().is_empty());
}

#[test]
fn revoke_access_publishes_an_access_revoked_event() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let access_id = fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );

    let revoked_at = REQUESTED_AT + 500;
    fixture.env.ledger().set_timestamp(revoked_at);
    fixture
        .client()
        .revoke_access(&fixture.passport_id, &access_id);

    let expected = AccessRevoked {
        access_id,
        passport_id: fixture.passport_id.clone(),
        provider_id: fixture.provider_id.clone(),
        revoked_at,
    };

    assert_eq!(
        fixture.env.events().all(),
        [expected.to_xdr(&fixture.env, &fixture.contract_id)]
    );
}

#[test]
fn revoke_access_does_not_publish_an_event_when_it_fails() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let result = fixture
        .client()
        .try_revoke_access(&fixture.passport_id, &42);

    assert_eq!(result, Err(Ok(Error::RequestNotFound)));
    assert!(fixture.env.events().all().events().is_empty());
}

// --- integration scenarios: full consent lifecycle ---

#[test]
fn lifecycle_approve_then_revoke_updates_access_and_emits_events_in_order() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();
    let client = fixture.client();

    let access_id = client.request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );
    let requested = AccessRequested {
        access_id,
        passport_id: fixture.passport_id.clone(),
        provider_id: fixture.provider_id.clone(),
        record_scope: RecordScope::LabResultsOnly,
    };
    assert_eq!(
        fixture.env.events().all(),
        [requested.to_xdr(&fixture.env, &fixture.contract_id)]
    );

    client.approve_access(&fixture.passport_id, &access_id);
    let approved = AccessApproved {
        access_id,
        passport_id: fixture.passport_id.clone(),
        provider_id: fixture.provider_id.clone(),
    };
    assert_eq!(
        fixture.env.events().all(),
        [approved.to_xdr(&fixture.env, &fixture.contract_id)]
    );

    assert!(client.check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::LabResultsOnly,
    ));
    let active = client.get_active_permissions(&fixture.passport_id);
    assert_eq!(active.len(), 1);
    assert_eq!(active.get(0).unwrap().access_id, access_id);

    let revoked_at = REQUESTED_AT + 500;
    fixture.env.ledger().set_timestamp(revoked_at);
    client.revoke_access(&fixture.passport_id, &access_id);
    let revoked = AccessRevoked {
        access_id,
        passport_id: fixture.passport_id.clone(),
        provider_id: fixture.provider_id.clone(),
        revoked_at,
    };
    assert_eq!(
        fixture.env.events().all(),
        [revoked.to_xdr(&fixture.env, &fixture.contract_id)]
    );

    assert!(!client.check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::LabResultsOnly,
    ));
    assert!(client
        .get_active_permissions(&fixture.passport_id)
        .is_empty());
}

#[test]
fn lifecycle_rejection_denies_access_and_emits_events_in_order() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();
    let client = fixture.client();

    let access_id = client.request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::PrescriptionsOnly,
        &ONE_DAY,
    );
    let requested = AccessRequested {
        access_id,
        passport_id: fixture.passport_id.clone(),
        provider_id: fixture.provider_id.clone(),
        record_scope: RecordScope::PrescriptionsOnly,
    };
    assert_eq!(
        fixture.env.events().all(),
        [requested.to_xdr(&fixture.env, &fixture.contract_id)]
    );

    client.reject_access(&fixture.passport_id, &access_id);
    let rejected = AccessRejected {
        access_id,
        passport_id: fixture.passport_id.clone(),
        provider_id: fixture.provider_id.clone(),
    };
    assert_eq!(
        fixture.env.events().all(),
        [rejected.to_xdr(&fixture.env, &fixture.contract_id)]
    );

    assert!(!client.check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::PrescriptionsOnly,
    ));
    assert!(client
        .get_active_permissions(&fixture.passport_id)
        .is_empty());
}

#[test]
fn lifecycle_natural_expiry_denies_access_without_a_revocation() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();
    let client = fixture.client();

    let short_duration = 60;
    let access_id = client.request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::VaccinationRecordsOnly,
        &short_duration,
    );
    client.approve_access(&fixture.passport_id, &access_id);
    let approved = AccessApproved {
        access_id,
        passport_id: fixture.passport_id.clone(),
        provider_id: fixture.provider_id.clone(),
    };
    assert_eq!(
        fixture.env.events().all(),
        [approved.to_xdr(&fixture.env, &fixture.contract_id)]
    );

    let expires_at = REQUESTED_AT + short_duration;
    fixture.env.ledger().set_timestamp(expires_at - 1);
    assert!(client.check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::VaccinationRecordsOnly,
    ));

    fixture.env.ledger().set_timestamp(expires_at);
    assert!(!client.check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::VaccinationRecordsOnly,
    ));
    assert!(client
        .get_active_permissions(&fixture.passport_id)
        .is_empty());
    assert!(
        fixture.env.events().all().events().is_empty(),
        "natural expiry is lazy: read-only checks must not emit an event"
    );
}

// --- edge cases: multi-provider and scope isolation ---

#[test]
fn revoking_one_providers_grant_does_not_affect_another_providers_grant() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let provider_a = fixture.provider_id.clone();
    let provider_b = Address::generate(&fixture.env);
    let access_a =
        fixture.create_and_approve_request(&provider_a, RecordScope::LabResultsOnly, ONE_DAY);
    let access_b =
        fixture.create_and_approve_request(&provider_b, RecordScope::PrescriptionsOnly, ONE_DAY);

    assert!(fixture.client().check_access(
        &fixture.passport_id,
        &provider_a,
        &RecordScope::LabResultsOnly,
    ));
    assert!(fixture.client().check_access(
        &fixture.passport_id,
        &provider_b,
        &RecordScope::PrescriptionsOnly,
    ));

    fixture
        .client()
        .revoke_access(&fixture.passport_id, &access_a);

    assert!(!fixture.client().check_access(
        &fixture.passport_id,
        &provider_a,
        &RecordScope::LabResultsOnly,
    ));
    assert!(
        fixture.client().check_access(
            &fixture.passport_id,
            &provider_b,
            &RecordScope::PrescriptionsOnly,
        ),
        "revoking one provider's grant must not affect another provider's grant"
    );

    let active = fixture
        .client()
        .get_active_permissions(&fixture.passport_id);
    assert_eq!(active.len(), 1);
    assert_eq!(active.get(0).unwrap().access_id, access_b);
}

#[test]
fn lab_results_and_prescriptions_grants_are_scope_isolated() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let lab_provider = fixture.provider_id.clone();
    let prescription_provider = Address::generate(&fixture.env);
    fixture.create_and_approve_request(&lab_provider, RecordScope::LabResultsOnly, ONE_DAY);
    fixture.create_and_approve_request(
        &prescription_provider,
        RecordScope::PrescriptionsOnly,
        ONE_DAY,
    );

    assert!(fixture.client().check_access(
        &fixture.passport_id,
        &lab_provider,
        &RecordScope::LabResultsOnly,
    ));
    assert!(!fixture.client().check_access(
        &fixture.passport_id,
        &lab_provider,
        &RecordScope::PrescriptionsOnly,
    ));

    assert!(fixture.client().check_access(
        &fixture.passport_id,
        &prescription_provider,
        &RecordScope::PrescriptionsOnly,
    ));
    assert!(!fixture.client().check_access(
        &fixture.passport_id,
        &prescription_provider,
        &RecordScope::LabResultsOnly,
    ));
}

#[test]
fn emergency_summary_grant_does_not_cover_insurance_data() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::EmergencySummaryOnly,
        ONE_DAY,
    );

    assert!(fixture.client().check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::EmergencySummaryOnly,
    ));
    assert!(!fixture.client().check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::InsuranceDataOnly,
    ));
}

#[test]
fn duplicate_active_requests_create_independent_grants() {
    let fixture = Fixture::new();
    fixture.env.mock_all_auths();

    let first_id = fixture.create_and_approve_request(
        &fixture.provider_id.clone(),
        RecordScope::LabResultsOnly,
        ONE_DAY,
    );

    // Re-requesting the same provider/scope pair is allowed; it allocates a
    // new request rather than replacing or reusing the active one.
    let second_id = fixture.client().request_access(
        &fixture.provider_id,
        &fixture.passport_id,
        &RecordScope::LabResultsOnly,
        &ONE_DAY,
    );
    assert_ne!(first_id, second_id);
    fixture
        .client()
        .approve_access(&fixture.passport_id, &second_id);

    let active = fixture
        .client()
        .get_active_permissions(&fixture.passport_id);
    assert_eq!(active.len(), 2);
    assert_eq!(active.get(0).unwrap().access_id, first_id);
    assert_eq!(active.get(1).unwrap().access_id, second_id);

    fixture
        .client()
        .revoke_access(&fixture.passport_id, &first_id);
    assert!(
        fixture.client().check_access(
            &fixture.passport_id,
            &fixture.provider_id,
            &RecordScope::LabResultsOnly,
        ),
        "the second independent grant must remain active"
    );

    fixture
        .client()
        .revoke_access(&fixture.passport_id, &second_id);
    assert!(!fixture.client().check_access(
        &fixture.passport_id,
        &fixture.provider_id,
        &RecordScope::LabResultsOnly,
    ));
}
