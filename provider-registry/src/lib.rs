#![no_std]

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, Symbol};

mod error;
mod events;
mod storage;
mod types;

pub use error::Error;
pub use events::{AdminTransferred, ProviderRegistered, ProviderStatusChanged, ProviderVerified};
pub use storage::DataKey;
pub use types::{is_valid_transition, Provider, ProviderStatus, ProviderType};

use types::Provider as ProviderRecord;

#[contract]
pub struct ProviderRegistry;

/// Requires that `admin` is authenticated and matches the stored admin.
fn require_admin(env: &Env, admin: &Address) -> Result<(), Error> {
    admin.require_auth();

    let stored = storage::read_admin(env)?;
    if &stored != admin {
        return Err(Error::NotAdmin);
    }

    Ok(())
}

/// Loads a provider, returning [`Error::ProviderNotFound`] when it does not
/// exist.
fn load_provider(env: &Env, provider_id: u64) -> Result<ProviderRecord, Error> {
    storage::read_provider(env, provider_id).ok_or(Error::ProviderNotFound)
}

/// Shared implementation for admin-driven transitions that only change the
/// provider's status. Validates the transition, persists the new status, and
/// publishes [`ProviderStatusChanged`]. Leaves `verified_by` untouched.
fn change_status(
    env: &Env,
    admin: &Address,
    provider_id: u64,
    expected_from: Option<ProviderStatus>,
    new_status: ProviderStatus,
) -> Result<(), Error> {
    let mut provider = load_provider(env, provider_id)?;
    let old_status = provider.status.clone();
    if expected_from.is_some_and(|expected| expected != old_status)
        || !is_valid_transition(&old_status, &new_status)
    {
        return Err(Error::InvalidStatusTransition);
    }

    provider.status = new_status.clone();
    storage::write_provider(env, &provider);

    ProviderStatusChanged {
        provider_id: provider.provider_id,
        old_status,
        new_status,
        changed_by: admin.clone(),
    }
    .publish(env);

    Ok(())
}

#[contractimpl]
impl ProviderRegistry {
    /// Initializes the contract with the trusted verifying authority.
    ///
    /// Callable exactly once. `admin` must authorize the call. Fails with
    /// [`Error::AlreadyInitialized`] if the contract already has an admin.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        admin.require_auth();

        if storage::has_admin(&env) {
            return Err(Error::AlreadyInitialized);
        }

        storage::write_admin(&env, &admin);
        Ok(())
    }

    /// Transfers admin control of the registry to `new_admin`.
    ///
    /// `current_admin` must authorize the call and match the stored admin,
    /// otherwise [`Error::NotAdmin`] is returned. Transferring to the current
    /// admin is rejected with [`Error::SameAdmin`] rather than silently doing
    /// nothing.
    pub fn transfer_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), Error> {
        current_admin.require_auth();

        let stored = storage::read_admin(&env)?;
        if stored != current_admin {
            return Err(Error::NotAdmin);
        }
        if new_admin == current_admin {
            return Err(Error::SameAdmin);
        }

        storage::write_admin(&env, &new_admin);

        AdminTransferred {
            old_admin: current_admin,
            new_admin,
        }
        .publish(&env);

        Ok(())
    }

    /// Registers a new provider, starting in [`ProviderStatus::Pending`].
    ///
    /// The provider's wallet must authorize the call, so only the wallet owner
    /// can self-register. Returns the newly allocated `provider_id`. Fails with
    /// [`Error::WalletAlreadyRegistered`] if the wallet is already linked to a
    /// provider.
    pub fn register_provider(
        env: Env,
        provider_wallet_address: Address,
        provider_type: ProviderType,
        license_hash: BytesN<32>,
        country: Symbol,
    ) -> Result<u64, Error> {
        provider_wallet_address.require_auth();

        if storage::read_provider_id_by_wallet(&env, &provider_wallet_address).is_some() {
            return Err(Error::WalletAlreadyRegistered);
        }

        let provider_id = storage::next_provider_id(&env);
        let provider = ProviderRecord {
            provider_id,
            provider_wallet_address: provider_wallet_address.clone(),
            provider_type: provider_type.clone(),
            license_hash,
            country: country.clone(),
            status: ProviderStatus::Pending,
            verified_by: None,
            registered_at: env.ledger().timestamp(),
        };
        storage::write_provider(&env, &provider);

        ProviderRegistered {
            provider_id,
            provider_wallet_address,
            provider_type,
            country,
        }
        .publish(&env);

        Ok(provider_id)
    }

    /// Verifies a pending provider, marking it eligible to request access.
    ///
    /// Only the stored admin can verify. Fails with [`Error::ProviderNotFound`]
    /// if the provider does not exist, or [`Error::InvalidStatusTransition`]
    /// if it is not currently [`ProviderStatus::Pending`]. On success records
    /// `admin` as the provider's `verified_by`.
    pub fn verify_provider(env: Env, admin: Address, provider_id: u64) -> Result<(), Error> {
        require_admin(&env, &admin)?;

        let mut provider = load_provider(&env, provider_id)?;
        if provider.status != ProviderStatus::Pending
            || !is_valid_transition(&provider.status, &ProviderStatus::Verified)
        {
            return Err(Error::InvalidStatusTransition);
        }

        provider.status = ProviderStatus::Verified;
        provider.verified_by = Some(admin.clone());
        storage::write_provider(&env, &provider);

        ProviderVerified {
            provider_id: provider.provider_id,
            provider_wallet_address: provider.provider_wallet_address,
            verified_by: admin,
        }
        .publish(&env);

        Ok(())
    }

    /// Reinstates a suspended provider back to [`ProviderStatus::Verified`].
    ///
    /// Only the stored admin can reinstate. The original `verified_by` record
    /// is preserved. Fails with [`Error::ProviderNotFound`] if the provider
    /// does not exist, or [`Error::InvalidStatusTransition`] if it is not
    /// currently [`ProviderStatus::Suspended`].
    pub fn reinstate_provider(env: Env, admin: Address, provider_id: u64) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        change_status(
            &env,
            &admin,
            provider_id,
            Some(ProviderStatus::Suspended),
            ProviderStatus::Verified,
        )
    }

    /// Temporarily suspends a verified provider.
    ///
    /// Only the stored admin can suspend. Fails with
    /// [`Error::ProviderNotFound`] if the provider does not exist, or
    /// [`Error::InvalidStatusTransition`] if it is not currently
    /// [`ProviderStatus::Verified`].
    pub fn suspend_provider(env: Env, admin: Address, provider_id: u64) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        change_status(
            &env,
            &admin,
            provider_id,
            Some(ProviderStatus::Verified),
            ProviderStatus::Suspended,
        )
    }

    /// Permanently revokes a provider's standing.
    ///
    /// Only the stored admin can revoke. Revocation is legal from `Pending`,
    /// `Verified`, or `Suspended`; an already-revoked provider fails with
    /// [`Error::InvalidStatusTransition`]. Fails with
    /// [`Error::ProviderNotFound`] if the provider does not exist.
    pub fn revoke_provider(env: Env, admin: Address, provider_id: u64) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        change_status(&env, &admin, provider_id, None, ProviderStatus::Revoked)
    }

    /// Returns the provider stored under `provider_id`, or `None` if it does
    /// not exist. Read-only: no authorization is required.
    pub fn get_provider(env: Env, provider_id: u64) -> Option<Provider> {
        storage::read_provider(&env, provider_id)
    }

    /// Returns the provider linked to `wallet_address`, or `None` if the
    /// wallet has no provider entry. Read-only: no authorization is required.
    pub fn get_provider_by_wallet(env: Env, wallet_address: Address) -> Option<Provider> {
        let provider_id = storage::read_provider_id_by_wallet(&env, &wallet_address)?;
        storage::read_provider(&env, provider_id)
    }

    /// Returns `true` only when `provider_id` exists and is currently
    /// [`ProviderStatus::Verified`]. Returns `false` for pending, suspended,
    /// revoked, or non-existent providers. Read-only: no authorization is
    /// required.
    pub fn is_provider_verified(env: Env, provider_id: u64) -> bool {
        matches!(
            storage::read_provider(&env, provider_id),
            Some(provider) if provider.status == ProviderStatus::Verified
        )
    }
}

#[cfg(test)]
mod test;
