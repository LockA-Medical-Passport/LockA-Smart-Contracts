use soroban_sdk::{contracttype, Address, BytesN, Symbol};

/// The categories of healthcare provider this registry can hold.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderType {
    /// A hospital.
    Hospital,
    /// A clinic.
    Clinic,
    /// An individual doctor.
    Doctor,
    /// A diagnostic laboratory.
    Laboratory,
    /// A pharmacy.
    Pharmacy,
    /// An insurance company.
    InsuranceCompany,
    /// A public health agency.
    PublicHealthAgency,
}

/// A provider's verification lifecycle state.
///
/// Allowed transitions: `Pending -> Verified`, `Pending -> Revoked` (rejecting
/// an unverified applicant), `Verified -> Suspended`, `Verified -> Revoked`,
/// `Suspended -> Verified` (reinstatement), `Suspended -> Revoked`. `Revoked`
/// is terminal — no transitions are allowed out of it.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderStatus {
    /// The provider has registered but has not yet been verified.
    Pending,
    /// The provider has been verified and is in good standing.
    Verified,
    /// The provider has been temporarily suspended.
    Suspended,
    /// The provider has been permanently revoked.
    Revoked,
}

/// A registered healthcare provider.
///
/// `license_hash` is a hash/commitment of the provider's off-chain license
/// document rather than the document itself, so sensitive material never
/// touches ledger storage. A provider begins in [`ProviderStatus::Pending`]
/// with `verified_by == None`; both are populated by an admin during
/// verification.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provider {
    /// Unique, monotonically-allocated identifier for this provider.
    pub provider_id: u64,
    /// The Stellar wallet address that controls this provider entry.
    pub provider_wallet_address: Address,
    /// The provider's category.
    pub provider_type: ProviderType,
    /// Hash/commitment of the provider's off-chain license document.
    pub license_hash: BytesN<32>,
    /// The country the provider is licensed in.
    pub country: Symbol,
    /// The provider's current verification lifecycle state.
    pub status: ProviderStatus,
    /// The admin that verified the provider, or `None` while pending.
    pub verified_by: Option<Address>,
    /// Ledger timestamp at which the provider registered.
    pub registered_at: u64,
}

/// Returns whether transitioning a provider's status from `from` to `to` is allowed.
pub fn is_valid_transition(from: &ProviderStatus, to: &ProviderStatus) -> bool {
    matches!(
        (from, to),
        (ProviderStatus::Pending, ProviderStatus::Verified)
            | (ProviderStatus::Pending, ProviderStatus::Revoked)
            | (ProviderStatus::Verified, ProviderStatus::Suspended)
            | (ProviderStatus::Verified, ProviderStatus::Revoked)
            | (ProviderStatus::Suspended, ProviderStatus::Verified)
            | (ProviderStatus::Suspended, ProviderStatus::Revoked)
    )
}

#[cfg(test)]
mod tests {
    use super::{is_valid_transition, ProviderStatus, ProviderType};
    use soroban_sdk::{symbol_short, Env};

    #[test]
    fn provider_type_round_trips_through_storage() {
        let env = Env::default();
        let contract_id = env.register(crate::ProviderRegistry, ());

        env.as_contract(&contract_id, || {
            let key = symbol_short!("ptype");
            env.storage()
                .persistent()
                .set(&key, &ProviderType::Laboratory);

            let loaded: ProviderType = env.storage().persistent().get(&key).unwrap();
            assert_eq!(loaded, ProviderType::Laboratory);
        });
    }

    #[test]
    fn valid_transitions_are_accepted() {
        assert!(is_valid_transition(
            &ProviderStatus::Pending,
            &ProviderStatus::Verified
        ));
        assert!(is_valid_transition(
            &ProviderStatus::Pending,
            &ProviderStatus::Revoked
        ));
        assert!(is_valid_transition(
            &ProviderStatus::Verified,
            &ProviderStatus::Suspended
        ));
        assert!(is_valid_transition(
            &ProviderStatus::Verified,
            &ProviderStatus::Revoked
        ));
        assert!(is_valid_transition(
            &ProviderStatus::Suspended,
            &ProviderStatus::Verified
        ));
        assert!(is_valid_transition(
            &ProviderStatus::Suspended,
            &ProviderStatus::Revoked
        ));
    }

    #[test]
    fn invalid_transitions_are_rejected() {
        let statuses = [
            ProviderStatus::Pending,
            ProviderStatus::Verified,
            ProviderStatus::Suspended,
            ProviderStatus::Revoked,
        ];
        let valid = [
            (ProviderStatus::Pending, ProviderStatus::Verified),
            (ProviderStatus::Pending, ProviderStatus::Revoked),
            (ProviderStatus::Verified, ProviderStatus::Suspended),
            (ProviderStatus::Verified, ProviderStatus::Revoked),
            (ProviderStatus::Suspended, ProviderStatus::Verified),
            (ProviderStatus::Suspended, ProviderStatus::Revoked),
        ];

        let mut checked = 0;
        for from in &statuses {
            for to in &statuses {
                let is_valid = valid
                    .iter()
                    .any(|(v_from, v_to)| v_from == from && v_to == to);
                assert_eq!(
                    is_valid_transition(from, to),
                    is_valid,
                    "transition {:?} -> {:?} did not match expected validity",
                    from,
                    to
                );
                checked += 1;
            }
        }

        assert_eq!(
            checked, 16,
            "expected all 16 (from, to) combinations to be checked"
        );
    }
}
