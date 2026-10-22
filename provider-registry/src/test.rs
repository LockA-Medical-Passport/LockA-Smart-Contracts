use soroban_sdk::testutils::{Address as _, Events as _, Ledger};
use soroban_sdk::{symbol_short, Address, BytesN, Env, Event as _, InvokeError, Symbol};

use crate::storage::{read_admin, read_provider};
use crate::{
    AdminTransferred, Error, Provider, ProviderRegistered, ProviderRegistry,
    ProviderRegistryClient, ProviderStatus, ProviderStatusChanged, ProviderType, ProviderVerified,
};

const NOW: u64 = 1_700_000_000;

struct Fixture {
    env: Env,
    contract_id: Address,
    admin: Address,
}

impl Fixture {
    fn new() -> Self {
        let env = Env::default();
        env.ledger().set_timestamp(NOW);

        let contract_id = env.register(ProviderRegistry, ());
        let admin = Address::generate(&env);

        Fixture {
            env,
            contract_id,
            admin,
        }
    }

    fn with_auth() -> Self {
        let fixture = Self::new();
        fixture.env.mock_all_auths();
        fixture
    }

    fn client(&self) -> ProviderRegistryClient<'_> {
        ProviderRegistryClient::new(&self.env, &self.contract_id)
    }

    fn initialized() -> Self {
        let fixture = Self::with_auth();
        fixture.client().initialize(&fixture.admin);
        fixture
    }

    fn stored_admin(&self) -> Result<Address, Error> {
        self.env
            .as_contract(&self.contract_id, || read_admin(&self.env))
    }

    fn stored_provider(&self, provider_id: u64) -> Option<Provider> {
        self.env
            .as_contract(&self.contract_id, || read_provider(&self.env, provider_id))
    }

    fn license_hash(&self) -> BytesN<32> {
        BytesN::from_array(&self.env, &[7u8; 32])
    }

    fn country(&self) -> Symbol {
        symbol_short!("NG")
    }

    fn register(&self, wallet: &Address) -> u64 {
        self.client().register_provider(
            wallet,
            &ProviderType::Clinic,
            &self.license_hash(),
            &self.country(),
        )
    }

    fn register_fresh(&self) -> u64 {
        let wallet = Address::generate(&self.env);
        self.register(&wallet)
    }

    fn verify(&self, provider_id: u64) {
        self.client().verify_provider(&self.admin, &provider_id);
    }

    fn verified_provider(&self) -> u64 {
        let provider_id = self.register_fresh();
        self.verify(provider_id);
        provider_id
    }

    fn events(&self) -> soroban_sdk::testutils::ContractEvents {
        self.env.events().all()
    }
}

#[test]
fn contract_registers_and_builds_a_client() {
    let env = Env::default();
    let contract_id = env.register(ProviderRegistry, ());
    let _client = ProviderRegistryClient::new(&env, &contract_id);
}

// --- initialize ---

#[test]
fn initialize_stores_the_admin() {
    let fixture = Fixture::with_auth();

    fixture.client().initialize(&fixture.admin);

    assert_eq!(fixture.stored_admin(), Ok(fixture.admin.clone()));
}

#[test]
fn initialize_rejects_a_second_call() {
    let fixture = Fixture::initialized();
    let other_admin = Address::generate(&fixture.env);

    let result = fixture.client().try_initialize(&other_admin);

    assert_eq!(result, Err(Ok(Error::AlreadyInitialized)));
    assert_eq!(fixture.stored_admin(), Ok(fixture.admin.clone()));
}

#[test]
fn read_admin_returns_not_initialized_before_initialize() {
    let fixture = Fixture::with_auth();
    assert_eq!(fixture.stored_admin(), Err(Error::NotInitialized));
}

// --- transfer_admin ---

#[test]
fn transfer_admin_hands_control_to_the_new_admin() {
    let fixture = Fixture::initialized();
    let new_admin = Address::generate(&fixture.env);

    fixture.client().transfer_admin(&fixture.admin, &new_admin);

    assert_eq!(fixture.stored_admin(), Ok(new_admin));
}

#[test]
fn transfer_admin_rejects_a_non_admin_caller() {
    let fixture = Fixture::initialized();
    let outsider = Address::generate(&fixture.env);
    let new_admin = Address::generate(&fixture.env);

    let result = fixture.client().try_transfer_admin(&outsider, &new_admin);

    assert_eq!(result, Err(Ok(Error::NotAdmin)));
    assert_eq!(fixture.stored_admin(), Ok(fixture.admin.clone()));
}

#[test]
fn transfer_admin_rejects_transferring_to_the_same_admin() {
    let fixture = Fixture::initialized();

    let result = fixture
        .client()
        .try_transfer_admin(&fixture.admin, &fixture.admin);

    assert_eq!(result, Err(Ok(Error::SameAdmin)));
    assert_eq!(fixture.stored_admin(), Ok(fixture.admin.clone()));
}

#[test]
fn transfer_admin_publishes_an_admin_transferred_event() {
    let fixture = Fixture::initialized();
    let new_admin = Address::generate(&fixture.env);

    fixture.client().transfer_admin(&fixture.admin, &new_admin);

    let expected = AdminTransferred {
        old_admin: fixture.admin.clone(),
        new_admin,
    };

    assert_eq!(
        fixture.events(),
        [expected.to_xdr(&fixture.env, &fixture.contract_id)]
    );
}

// --- register_provider ---

#[test]
fn register_provider_stores_a_pending_provider_with_defaults() {
    let fixture = Fixture::initialized();
    let wallet = Address::generate(&fixture.env);

    let provider_id = fixture.register(&wallet);

    assert_eq!(provider_id, 1);
    let provider = fixture.stored_provider(provider_id).unwrap();
    assert_eq!(provider.provider_id, provider_id);
    assert_eq!(provider.provider_wallet_address, wallet);
    assert_eq!(provider.provider_type, ProviderType::Clinic);
    assert_eq!(provider.license_hash, fixture.license_hash());
    assert_eq!(provider.country, fixture.country());
    assert_eq!(provider.status, ProviderStatus::Pending);
    assert_eq!(provider.verified_by, None);
    assert_eq!(provider.registered_at, NOW);
}

#[test]
fn register_provider_requires_the_provider_wallets_authorization() {
    let fixture = Fixture::new();
    let wallet = Address::generate(&fixture.env);

    let result = fixture.client().try_register_provider(
        &wallet,
        &ProviderType::Clinic,
        &fixture.license_hash(),
        &fixture.country(),
    );

    assert_eq!(result, Err(Err(InvokeError::Abort)));
    assert_eq!(fixture.stored_provider(1), None);
}

#[test]
fn register_provider_publishes_a_provider_registered_event() {
    let fixture = Fixture::initialized();
    let wallet = Address::generate(&fixture.env);

    let provider_id = fixture.register(&wallet);

    let expected = ProviderRegistered {
        provider_id,
        provider_wallet_address: wallet,
        provider_type: ProviderType::Clinic,
        country: fixture.country(),
    };

    assert_eq!(
        fixture.events(),
        [expected.to_xdr(&fixture.env, &fixture.contract_id)]
    );
}

#[test]
fn register_provider_rejects_an_already_registered_wallet() {
    let fixture = Fixture::initialized();
    let wallet = Address::generate(&fixture.env);
    fixture.register(&wallet);

    let result = fixture.client().try_register_provider(
        &wallet,
        &ProviderType::Hospital,
        &fixture.license_hash(),
        &fixture.country(),
    );

    assert_eq!(result, Err(Ok(Error::WalletAlreadyRegistered)));
    assert!(fixture.events().events().is_empty());
}

#[test]
fn register_provider_rejects_a_wallet_registered_even_after_revocation() {
    let fixture = Fixture::initialized();
    let wallet = Address::generate(&fixture.env);
    let provider_id = fixture.register(&wallet);
    fixture.verify(provider_id);
    fixture
        .client()
        .revoke_provider(&fixture.admin, &provider_id);

    let result = fixture.client().try_register_provider(
        &wallet,
        &ProviderType::Hospital,
        &fixture.license_hash(),
        &fixture.country(),
    );

    assert_eq!(result, Err(Ok(Error::WalletAlreadyRegistered)));
}

// --- verify_provider ---

#[test]
fn verify_provider_marks_a_pending_provider_verified() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.register_fresh();

    fixture.verify(provider_id);

    let provider = fixture.stored_provider(provider_id).unwrap();
    assert_eq!(provider.status, ProviderStatus::Verified);
    assert_eq!(provider.verified_by, Some(fixture.admin.clone()));
}

#[test]
fn verify_provider_rejects_a_non_admin_caller() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.register_fresh();
    let outsider = Address::generate(&fixture.env);

    let result = fixture
        .client()
        .try_verify_provider(&outsider, &provider_id);

    assert_eq!(result, Err(Ok(Error::NotAdmin)));
    assert_eq!(
        fixture.stored_provider(provider_id).unwrap().status,
        ProviderStatus::Pending
    );
}

#[test]
fn verify_provider_rejects_a_non_pending_provider() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();

    let result = fixture
        .client()
        .try_verify_provider(&fixture.admin, &provider_id);

    assert_eq!(result, Err(Ok(Error::InvalidStatusTransition)));
}

#[test]
fn verify_provider_rejects_an_unknown_provider() {
    let fixture = Fixture::initialized();

    let result = fixture.client().try_verify_provider(&fixture.admin, &999);

    assert_eq!(result, Err(Ok(Error::ProviderNotFound)));
}

#[test]
fn verify_provider_publishes_a_provider_verified_event() {
    let fixture = Fixture::initialized();
    let wallet = Address::generate(&fixture.env);
    let provider_id = fixture.register(&wallet);

    fixture.verify(provider_id);

    let expected = ProviderVerified {
        provider_id,
        provider_wallet_address: wallet,
        verified_by: fixture.admin.clone(),
    };

    assert_eq!(
        fixture.events(),
        [expected.to_xdr(&fixture.env, &fixture.contract_id)]
    );
}

#[test]
fn verify_provider_does_not_publish_an_event_when_it_fails() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();

    let result = fixture
        .client()
        .try_verify_provider(&fixture.admin, &provider_id);

    assert_eq!(result, Err(Ok(Error::InvalidStatusTransition)));
    assert!(fixture.events().events().is_empty());
}

// --- suspend_provider ---

#[test]
fn suspend_provider_suspends_a_verified_provider() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();

    fixture
        .client()
        .suspend_provider(&fixture.admin, &provider_id);

    assert_eq!(
        fixture.stored_provider(provider_id).unwrap().status,
        ProviderStatus::Suspended
    );
}

#[test]
fn suspend_provider_rejects_a_non_admin_caller() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();
    let outsider = Address::generate(&fixture.env);

    let result = fixture
        .client()
        .try_suspend_provider(&outsider, &provider_id);

    assert_eq!(result, Err(Ok(Error::NotAdmin)));
    assert_eq!(
        fixture.stored_provider(provider_id).unwrap().status,
        ProviderStatus::Verified
    );
}

#[test]
fn suspend_provider_rejects_a_provider_that_is_not_verified() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.register_fresh();

    let result = fixture
        .client()
        .try_suspend_provider(&fixture.admin, &provider_id);

    assert_eq!(result, Err(Ok(Error::InvalidStatusTransition)));
}

#[test]
fn suspend_provider_publishes_a_status_changed_event() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();

    fixture
        .client()
        .suspend_provider(&fixture.admin, &provider_id);

    let expected = ProviderStatusChanged {
        provider_id,
        old_status: ProviderStatus::Verified,
        new_status: ProviderStatus::Suspended,
        changed_by: fixture.admin.clone(),
    };

    assert_eq!(
        fixture.events(),
        [expected.to_xdr(&fixture.env, &fixture.contract_id)]
    );
}

// --- reinstate_provider ---

#[test]
fn reinstate_provider_restores_a_suspended_provider() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();
    fixture
        .client()
        .suspend_provider(&fixture.admin, &provider_id);

    fixture
        .client()
        .reinstate_provider(&fixture.admin, &provider_id);

    let provider = fixture.stored_provider(provider_id).unwrap();
    assert_eq!(provider.status, ProviderStatus::Verified);
}

#[test]
fn reinstate_provider_preserves_the_original_verified_by() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();
    let new_admin = Address::generate(&fixture.env);
    fixture.client().transfer_admin(&fixture.admin, &new_admin);
    fixture.client().suspend_provider(&new_admin, &provider_id);

    fixture
        .client()
        .reinstate_provider(&new_admin, &provider_id);

    let provider = fixture.stored_provider(provider_id).unwrap();
    assert_eq!(provider.status, ProviderStatus::Verified);
    assert_eq!(provider.verified_by, Some(fixture.admin.clone()));
}

#[test]
fn reinstate_provider_rejects_a_non_admin_caller() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();
    fixture
        .client()
        .suspend_provider(&fixture.admin, &provider_id);
    let outsider = Address::generate(&fixture.env);

    let result = fixture
        .client()
        .try_reinstate_provider(&outsider, &provider_id);

    assert_eq!(result, Err(Ok(Error::NotAdmin)));
    assert_eq!(
        fixture.stored_provider(provider_id).unwrap().status,
        ProviderStatus::Suspended
    );
}

#[test]
fn reinstate_provider_rejects_a_provider_that_is_not_suspended() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.register_fresh();

    let result = fixture
        .client()
        .try_reinstate_provider(&fixture.admin, &provider_id);

    assert_eq!(result, Err(Ok(Error::InvalidStatusTransition)));
}

#[test]
fn reinstate_provider_publishes_a_status_changed_event() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();
    fixture
        .client()
        .suspend_provider(&fixture.admin, &provider_id);

    fixture
        .client()
        .reinstate_provider(&fixture.admin, &provider_id);

    let expected = ProviderStatusChanged {
        provider_id,
        old_status: ProviderStatus::Suspended,
        new_status: ProviderStatus::Verified,
        changed_by: fixture.admin.clone(),
    };

    assert_eq!(
        fixture.events(),
        [expected.to_xdr(&fixture.env, &fixture.contract_id)]
    );
}

// --- revoke_provider ---

#[test]
fn revoke_provider_revokes_a_pending_provider() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.register_fresh();

    fixture
        .client()
        .revoke_provider(&fixture.admin, &provider_id);

    assert_eq!(
        fixture.stored_provider(provider_id).unwrap().status,
        ProviderStatus::Revoked
    );
}

#[test]
fn revoke_provider_revokes_a_verified_provider() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();

    fixture
        .client()
        .revoke_provider(&fixture.admin, &provider_id);

    assert_eq!(
        fixture.stored_provider(provider_id).unwrap().status,
        ProviderStatus::Revoked
    );
}

#[test]
fn revoke_provider_revokes_a_suspended_provider() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();
    fixture
        .client()
        .suspend_provider(&fixture.admin, &provider_id);

    fixture
        .client()
        .revoke_provider(&fixture.admin, &provider_id);

    assert_eq!(
        fixture.stored_provider(provider_id).unwrap().status,
        ProviderStatus::Revoked
    );
}

#[test]
fn revoke_provider_rejects_an_already_revoked_provider() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.register_fresh();
    fixture
        .client()
        .revoke_provider(&fixture.admin, &provider_id);

    let result = fixture
        .client()
        .try_revoke_provider(&fixture.admin, &provider_id);

    assert_eq!(result, Err(Ok(Error::InvalidStatusTransition)));
}

#[test]
fn revoke_provider_rejects_a_non_admin_caller() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.register_fresh();
    let outsider = Address::generate(&fixture.env);

    let result = fixture
        .client()
        .try_revoke_provider(&outsider, &provider_id);

    assert_eq!(result, Err(Ok(Error::NotAdmin)));
    assert_eq!(
        fixture.stored_provider(provider_id).unwrap().status,
        ProviderStatus::Pending
    );
}

#[test]
fn revoke_provider_publishes_a_status_changed_event() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.register_fresh();

    fixture
        .client()
        .revoke_provider(&fixture.admin, &provider_id);

    let expected = ProviderStatusChanged {
        provider_id,
        old_status: ProviderStatus::Pending,
        new_status: ProviderStatus::Revoked,
        changed_by: fixture.admin.clone(),
    };

    assert_eq!(
        fixture.events(),
        [expected.to_xdr(&fixture.env, &fixture.contract_id)]
    );
}

// --- read-only views ---

#[test]
fn get_provider_returns_the_exact_stored_record() {
    let fixture = Fixture::initialized();
    let wallet = Address::generate(&fixture.env);
    let provider_id = fixture.register(&wallet);
    let stored = fixture.stored_provider(provider_id).unwrap();

    assert_eq!(fixture.client().get_provider(&provider_id), Some(stored));
}

#[test]
fn get_provider_returns_none_for_an_unknown_id() {
    let fixture = Fixture::initialized();

    assert_eq!(fixture.client().get_provider(&999), None);
}

#[test]
fn get_provider_by_wallet_resolves_a_registered_wallet() {
    let fixture = Fixture::initialized();
    let wallet = Address::generate(&fixture.env);
    let provider_id = fixture.register(&wallet);

    assert_eq!(
        fixture.client().get_provider_by_wallet(&wallet),
        fixture.stored_provider(provider_id)
    );
}

#[test]
fn get_provider_by_wallet_returns_none_for_an_unregistered_wallet() {
    let fixture = Fixture::initialized();
    let wallet = Address::generate(&fixture.env);

    assert_eq!(fixture.client().get_provider_by_wallet(&wallet), None);
}

#[test]
fn is_provider_verified_reflects_the_current_status() {
    let fixture = Fixture::initialized();

    let pending = fixture.register_fresh();
    let verified = fixture.verified_provider();
    let suspended = fixture.verified_provider();
    fixture
        .client()
        .suspend_provider(&fixture.admin, &suspended);
    let revoked = fixture.verified_provider();
    fixture.client().revoke_provider(&fixture.admin, &revoked);

    assert!(!fixture.client().is_provider_verified(&pending));
    assert!(fixture.client().is_provider_verified(&verified));
    assert!(!fixture.client().is_provider_verified(&suspended));
    assert!(!fixture.client().is_provider_verified(&revoked));
    assert!(!fixture.client().is_provider_verified(&999));
}

// --- admin authorization across all admin-gated functions ---

#[test]
fn a_provider_cannot_verify_itself_or_change_its_own_status() {
    let fixture = Fixture::initialized();
    let wallet = Address::generate(&fixture.env);
    let provider_id = fixture.register(&wallet);

    let results = [
        fixture
            .client()
            .try_verify_provider(&wallet, &provider_id)
            .err(),
        fixture
            .client()
            .try_suspend_provider(&wallet, &provider_id)
            .err(),
        fixture
            .client()
            .try_reinstate_provider(&wallet, &provider_id)
            .err(),
        fixture
            .client()
            .try_revoke_provider(&wallet, &provider_id)
            .err(),
    ];

    for result in results {
        assert_eq!(result, Some(Ok(Error::NotAdmin)));
    }
    assert_eq!(
        fixture.stored_provider(provider_id).unwrap().status,
        ProviderStatus::Pending
    );
}

#[test]
fn after_transfer_only_the_new_admin_can_gate_status_changes() {
    let fixture = Fixture::initialized();
    let new_admin = Address::generate(&fixture.env);
    let provider_id = fixture.register_fresh();
    fixture.client().transfer_admin(&fixture.admin, &new_admin);

    let old_admin_results = [
        fixture
            .client()
            .try_verify_provider(&fixture.admin, &provider_id)
            .err(),
        fixture
            .client()
            .try_suspend_provider(&fixture.admin, &provider_id)
            .err(),
        fixture
            .client()
            .try_reinstate_provider(&fixture.admin, &provider_id)
            .err(),
        fixture
            .client()
            .try_revoke_provider(&fixture.admin, &provider_id)
            .err(),
    ];
    for result in old_admin_results {
        assert_eq!(result, Some(Ok(Error::NotAdmin)));
    }

    fixture.client().verify_provider(&new_admin, &provider_id);
    assert_eq!(
        fixture.stored_provider(provider_id).unwrap().status,
        ProviderStatus::Verified
    );
}

#[test]
fn admin_gated_functions_fail_with_not_initialized_before_initialize() {
    let fixture = Fixture::with_auth();
    let provider_id = 1;

    assert_eq!(
        fixture
            .client()
            .try_verify_provider(&fixture.admin, &provider_id)
            .err(),
        Some(Ok(Error::NotInitialized))
    );
    assert_eq!(
        fixture
            .client()
            .try_suspend_provider(&fixture.admin, &provider_id)
            .err(),
        Some(Ok(Error::NotInitialized))
    );
    assert_eq!(
        fixture
            .client()
            .try_reinstate_provider(&fixture.admin, &provider_id)
            .err(),
        Some(Ok(Error::NotInitialized))
    );
    assert_eq!(
        fixture
            .client()
            .try_revoke_provider(&fixture.admin, &provider_id)
            .err(),
        Some(Ok(Error::NotInitialized))
    );
    assert_eq!(
        fixture
            .client()
            .try_transfer_admin(&fixture.admin, &Address::generate(&fixture.env))
            .err(),
        Some(Ok(Error::NotInitialized))
    );
}

#[test]
fn an_unrelated_address_is_rejected_by_every_admin_gated_function() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();
    let outsider = Address::generate(&fixture.env);

    assert_eq!(
        fixture
            .client()
            .try_verify_provider(&outsider, &provider_id)
            .err(),
        Some(Ok(Error::NotAdmin))
    );
    assert_eq!(
        fixture
            .client()
            .try_suspend_provider(&outsider, &provider_id)
            .err(),
        Some(Ok(Error::NotAdmin))
    );
    assert_eq!(
        fixture
            .client()
            .try_reinstate_provider(&outsider, &provider_id)
            .err(),
        Some(Ok(Error::NotAdmin))
    );
    assert_eq!(
        fixture
            .client()
            .try_revoke_provider(&outsider, &provider_id)
            .err(),
        Some(Ok(Error::NotAdmin))
    );
    assert_eq!(
        fixture
            .client()
            .try_transfer_admin(&outsider, &Address::generate(&fixture.env))
            .err(),
        Some(Ok(Error::NotAdmin))
    );
}

// --- full lifecycle integration scenarios ---

#[test]
fn lifecycle_register_then_verify_becomes_verified() {
    let fixture = Fixture::initialized();
    let wallet = Address::generate(&fixture.env);

    let provider_id = fixture.register(&wallet);

    let registered = ProviderRegistered {
        provider_id,
        provider_wallet_address: wallet.clone(),
        provider_type: ProviderType::Clinic,
        country: fixture.country(),
    };
    assert_eq!(
        fixture.events(),
        [registered.to_xdr(&fixture.env, &fixture.contract_id)]
    );
    assert!(!fixture.client().is_provider_verified(&provider_id));

    fixture.verify(provider_id);

    let verified = ProviderVerified {
        provider_id,
        provider_wallet_address: wallet,
        verified_by: fixture.admin.clone(),
    };
    assert_eq!(
        fixture.events(),
        [verified.to_xdr(&fixture.env, &fixture.contract_id)]
    );
    assert!(fixture.client().is_provider_verified(&provider_id));
}

#[test]
fn lifecycle_suspend_then_reinstate_toggles_verification() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();
    assert!(fixture.client().is_provider_verified(&provider_id));

    fixture
        .client()
        .suspend_provider(&fixture.admin, &provider_id);
    let suspended = ProviderStatusChanged {
        provider_id,
        old_status: ProviderStatus::Verified,
        new_status: ProviderStatus::Suspended,
        changed_by: fixture.admin.clone(),
    };
    assert_eq!(
        fixture.events(),
        [suspended.to_xdr(&fixture.env, &fixture.contract_id)]
    );
    assert!(!fixture.client().is_provider_verified(&provider_id));

    fixture
        .client()
        .reinstate_provider(&fixture.admin, &provider_id);
    let reinstated = ProviderStatusChanged {
        provider_id,
        old_status: ProviderStatus::Suspended,
        new_status: ProviderStatus::Verified,
        changed_by: fixture.admin.clone(),
    };
    assert_eq!(
        fixture.events(),
        [reinstated.to_xdr(&fixture.env, &fixture.contract_id)]
    );
    assert!(fixture.client().is_provider_verified(&provider_id));
}

#[test]
fn lifecycle_revocation_from_suspended_is_terminal() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.verified_provider();
    fixture
        .client()
        .suspend_provider(&fixture.admin, &provider_id);

    fixture
        .client()
        .revoke_provider(&fixture.admin, &provider_id);
    let revoked = ProviderStatusChanged {
        provider_id,
        old_status: ProviderStatus::Suspended,
        new_status: ProviderStatus::Revoked,
        changed_by: fixture.admin.clone(),
    };
    assert_eq!(
        fixture.events(),
        [revoked.to_xdr(&fixture.env, &fixture.contract_id)]
    );
    assert!(!fixture.client().is_provider_verified(&provider_id));

    assert_eq!(
        fixture
            .client()
            .try_verify_provider(&fixture.admin, &provider_id)
            .err(),
        Some(Ok(Error::InvalidStatusTransition))
    );
    assert_eq!(
        fixture
            .client()
            .try_suspend_provider(&fixture.admin, &provider_id)
            .err(),
        Some(Ok(Error::InvalidStatusTransition))
    );
    assert_eq!(
        fixture
            .client()
            .try_reinstate_provider(&fixture.admin, &provider_id)
            .err(),
        Some(Ok(Error::InvalidStatusTransition))
    );
    assert_eq!(
        fixture
            .client()
            .try_revoke_provider(&fixture.admin, &provider_id)
            .err(),
        Some(Ok(Error::InvalidStatusTransition))
    );
}

#[test]
fn lifecycle_pending_application_can_be_revoked_directly() {
    let fixture = Fixture::initialized();
    let provider_id = fixture.register_fresh();

    fixture
        .client()
        .revoke_provider(&fixture.admin, &provider_id);

    let revoked = ProviderStatusChanged {
        provider_id,
        old_status: ProviderStatus::Pending,
        new_status: ProviderStatus::Revoked,
        changed_by: fixture.admin.clone(),
    };
    assert_eq!(
        fixture.events(),
        [revoked.to_xdr(&fixture.env, &fixture.contract_id)]
    );
    assert!(!fixture.client().is_provider_verified(&provider_id));
    assert_eq!(
        fixture
            .client()
            .try_verify_provider(&fixture.admin, &provider_id)
            .err(),
        Some(Ok(Error::InvalidStatusTransition))
    );
}
