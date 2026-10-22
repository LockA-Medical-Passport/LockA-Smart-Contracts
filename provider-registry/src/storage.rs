//! Persistence for [`Provider`] values and the contract admin: the storage key
//! scheme and the helper functions used to read and write them.

use soroban_sdk::{contracttype, Address, Env};

use crate::error::Error;
use crate::types::Provider;

/// Storage key scheme used by this contract.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataKey {
    /// A single registered provider, keyed by its `provider_id`.
    Provider(u64),
    /// Reverse lookup from a wallet address to the `provider_id` it controls.
    WalletIndex(Address),
    /// Monotonic counter used to allocate the next `provider_id`.
    NextProviderId,
    /// The trusted verifying authority that gates provider verification,
    /// suspension, reinstatement, and revocation.
    Admin,
}

// Provider records and the admin slot must outlive normal temporary-storage
// windows. The network caps these values, so the SDK only extends a value when
// it is below the threshold and never beyond the network's configured maximum.
const TTL_THRESHOLD: u32 = 2_592_000;
const TTL_BUMP: u32 = 5_184_000;

fn bump_ttl(env: &Env, key: &DataKey) {
    env.storage()
        .persistent()
        .extend_ttl(key, TTL_THRESHOLD, TTL_BUMP);
}

/// Reads a registered provider by its `provider_id`, if it exists.
pub fn read_provider(env: &Env, provider_id: u64) -> Option<Provider> {
    let key = DataKey::Provider(provider_id);
    let provider = env.storage().persistent().get(&key);
    if provider.is_some() {
        bump_ttl(env, &key);
    }
    provider
}

/// Persists (or overwrites) a provider record under its `provider_id`, and
/// indexes its wallet address for reverse lookup.
pub fn write_provider(env: &Env, provider: &Provider) {
    let storage = env.storage().persistent();

    let provider_key = DataKey::Provider(provider.provider_id);
    storage.set(&provider_key, provider);
    bump_ttl(env, &provider_key);

    let wallet_key = DataKey::WalletIndex(provider.provider_wallet_address.clone());
    storage.set(&wallet_key, &provider.provider_id);
    bump_ttl(env, &wallet_key);
}

/// Allocates and returns the next unused `provider_id`, starting at `1`.
pub fn next_provider_id(env: &Env) -> u64 {
    let key = DataKey::NextProviderId;
    let storage = env.storage().persistent();

    let next = storage.get::<DataKey, u64>(&key).unwrap_or(0) + 1;
    storage.set(&key, &next);
    bump_ttl(env, &key);

    next
}

/// Resolves a wallet address to its associated `provider_id`, if one exists.
pub fn read_provider_id_by_wallet(env: &Env, wallet: &Address) -> Option<u64> {
    let key = DataKey::WalletIndex(wallet.clone());
    let provider_id = env.storage().persistent().get(&key);
    if provider_id.is_some() {
        bump_ttl(env, &key);
    }
    provider_id
}

/// Returns the stored admin, or [`Error::NotInitialized`] if
/// [`crate::ProviderRegistry::initialize`] has not been called yet.
pub(crate) fn read_admin(env: &Env) -> Result<Address, Error> {
    let key = DataKey::Admin;
    let admin = env
        .storage()
        .persistent()
        .get::<DataKey, Address>(&key)
        .ok_or(Error::NotInitialized)?;
    bump_ttl(env, &key);
    Ok(admin)
}

/// Persists `admin` under the dedicated admin slot.
pub(crate) fn write_admin(env: &Env, admin: &Address) {
    let key = DataKey::Admin;
    env.storage().persistent().set(&key, admin);
    bump_ttl(env, &key);
}

/// Returns whether the contract has been initialized with an admin.
pub(crate) fn has_admin(env: &Env) -> bool {
    env.storage().persistent().has(&DataKey::Admin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProviderStatus, ProviderType};
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{symbol_short, BytesN};

    fn sample_provider(env: &Env, provider_id: u64, wallet: &Address) -> Provider {
        Provider {
            provider_id,
            provider_wallet_address: wallet.clone(),
            provider_type: ProviderType::Clinic,
            license_hash: BytesN::from_array(env, &[3u8; 32]),
            country: symbol_short!("NG"),
            status: ProviderStatus::Pending,
            verified_by: None,
            registered_at: 42,
        }
    }

    #[test]
    fn writes_then_reads_a_provider() {
        let env = Env::default();
        let contract_id = env.register(crate::ProviderRegistry, ());

        env.as_contract(&contract_id, || {
            let wallet = Address::generate(&env);
            let provider = sample_provider(&env, 1, &wallet);
            write_provider(&env, &provider);

            assert_eq!(read_provider(&env, 1), Some(provider));
        });
    }

    #[test]
    fn write_provider_populates_the_wallet_index() {
        let env = Env::default();
        let contract_id = env.register(crate::ProviderRegistry, ());

        env.as_contract(&contract_id, || {
            let wallet = Address::generate(&env);
            let provider = sample_provider(&env, 7, &wallet);
            write_provider(&env, &provider);

            assert_eq!(read_provider_id_by_wallet(&env, &wallet), Some(7));
        });
    }

    #[test]
    fn read_provider_returns_none_for_unknown_id() {
        let env = Env::default();
        let contract_id = env.register(crate::ProviderRegistry, ());

        env.as_contract(&contract_id, || {
            assert_eq!(read_provider(&env, 999), None);
        });
    }

    #[test]
    fn read_provider_id_by_wallet_returns_none_for_unindexed_wallet() {
        let env = Env::default();
        let contract_id = env.register(crate::ProviderRegistry, ());

        env.as_contract(&contract_id, || {
            let wallet = Address::generate(&env);
            assert_eq!(read_provider_id_by_wallet(&env, &wallet), None);
        });
    }

    #[test]
    fn next_provider_id_increments_monotonically() {
        let env = Env::default();
        let contract_id = env.register(crate::ProviderRegistry, ());

        env.as_contract(&contract_id, || {
            assert_eq!(next_provider_id(&env), 1);
            assert_eq!(next_provider_id(&env), 2);
            assert_eq!(next_provider_id(&env), 3);
        });
    }

    #[test]
    fn write_then_read_admin() {
        let env = Env::default();
        let contract_id = env.register(crate::ProviderRegistry, ());

        env.as_contract(&contract_id, || {
            let admin = Address::generate(&env);
            write_admin(&env, &admin);

            assert!(has_admin(&env));
            assert_eq!(read_admin(&env), Ok(admin));
        });
    }

    #[test]
    fn read_admin_returns_not_initialized_before_initialization() {
        let env = Env::default();
        let contract_id = env.register(crate::ProviderRegistry, ());

        env.as_contract(&contract_id, || {
            assert!(!has_admin(&env));
            assert_eq!(read_admin(&env), Err(Error::NotInitialized));
        });
    }
}
