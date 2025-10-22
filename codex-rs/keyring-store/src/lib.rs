use anyhow::Error as AnyhowError;
use keyring::Entry;
use keyring::Error as KeyringError;
use std::fmt;
#[derive(Debug)]
pub struct CredentialStoreError(AnyhowError);

impl CredentialStoreError {
    pub fn new(error: impl Into<AnyhowError>) -> Self {
        Self(error.into())
    }
    pub fn message(&self) -> String {
        self.0.to_string()
    }
    pub fn into_error(self) -> AnyhowError {
        self.0
    }
}

impl From<KeyringError> for CredentialStoreError {
    fn from(error: KeyringError) -> Self {
        Self::new(error)
    }
}

impl fmt::Display for CredentialStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CredentialStoreError {}

/// Basic keyring-backed credential store used across Codex crates.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultKeyringStore;

impl DefaultKeyringStore {
    #[inline]
    pub fn load(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<String>, CredentialStoreError> {
        let entry = Entry::new(service, account)?;
        match entry.get_password() {
            Ok(password) => Ok(Some(password)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    #[inline]
    pub fn save(
        &self,
        service: &str,
        account: &str,
        value: &str,
    ) -> Result<(), CredentialStoreError> {
        let entry = Entry::new(service, account)?;
        entry.set_password(value)?;
        Ok(())
    }

    #[inline]
    pub fn delete(&self, service: &str, account: &str) -> Result<bool, CredentialStoreError> {
        let entry = Entry::new(service, account)?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(KeyringError::NoEntry) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}
