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

/// Shared credential store abstraction for keyring-backed implementations.
pub trait KeyringStore: Send + Sync {
    fn load(&self, service: &str, account: &str) -> Result<Option<String>, CredentialStoreError>;
    fn save(&self, service: &str, account: &str, value: &str) -> Result<(), CredentialStoreError>;
    fn delete(&self, service: &str, account: &str) -> Result<bool, CredentialStoreError>;
}

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

impl KeyringStore for DefaultKeyringStore {
    fn load(&self, service: &str, account: &str) -> Result<Option<String>, CredentialStoreError> {
        DefaultKeyringStore::load(self, service, account)
    }

    fn save(&self, service: &str, account: &str, value: &str) -> Result<(), CredentialStoreError> {
        DefaultKeyringStore::save(self, service, account, value)
    }

    fn delete(&self, service: &str, account: &str) -> Result<bool, CredentialStoreError> {
        DefaultKeyringStore::delete(self, service, account)
    }
}

pub mod testing {
    use super::CredentialStoreError;
    use keyring::Error as KeyringError;
    use keyring::credential::CredentialApi as _;
    use keyring::mock::MockCredential;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::PoisonError;

    #[derive(Default, Clone)]
    pub struct MockKeyringStore {
        credentials: Arc<Mutex<HashMap<String, Arc<MockCredential>>>>,
    }

    impl MockKeyringStore {
        fn get_credential(&self, account: &str) -> Option<Arc<MockCredential>> {
            let guard = self
                .credentials
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            guard.get(account).cloned()
        }

        fn get_or_create_credential(&self, account: &str) -> Arc<MockCredential> {
            let mut guard = self
                .credentials
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            guard
                .entry(account.to_string())
                .or_insert_with(|| Arc::new(MockCredential::default()))
                .clone()
        }

        #[inline]
        pub fn load(
            &self,
            _service: &str,
            account: &str,
        ) -> Result<Option<String>, CredentialStoreError> {
            let credential = self.get_credential(account);

            let Some(credential) = credential else {
                return Ok(None);
            };

            match credential.get_password() {
                Ok(password) => Ok(Some(password)),
                Err(KeyringError::NoEntry) => Ok(None),
                Err(error) => Err(CredentialStoreError::new(error)),
            }
        }

        #[inline]
        pub fn save(
            &self,
            _service: &str,
            account: &str,
            value: &str,
        ) -> Result<(), CredentialStoreError> {
            let credential = self.get_or_create_credential(account);
            credential
                .set_password(value)
                .map_err(CredentialStoreError::new)?;
            Ok(())
        }

        #[inline]
        pub fn delete(&self, _service: &str, account: &str) -> Result<bool, CredentialStoreError> {
            let credential = self.get_credential(account);

            let Some(credential) = credential else {
                return Ok(false);
            };

            match credential.delete_credential() {
                Ok(()) => {
                    let mut guard = self
                        .credentials
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    guard.remove(account);
                    Ok(true)
                }
                Err(KeyringError::NoEntry) => {
                    let mut guard = self
                        .credentials
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    guard.remove(account);
                    Ok(false)
                }
                Err(error) => Err(CredentialStoreError::new(error)),
            }
        }

        pub fn saved_value(&self, account: &str) -> Option<String> {
            let credential = self.get_credential(account)?;
            credential.get_password().ok()
        }

        pub fn set_error(&self, account: &str, error: KeyringError) {
            let credential = self.get_or_create_credential(account);
            credential.set_error(error);
        }

        pub fn contains(&self, account: &str) -> bool {
            let guard = self
                .credentials
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            guard.contains_key(account)
        }
    }

    impl crate::KeyringStore for MockKeyringStore {
        fn load(
            &self,
            service: &str,
            account: &str,
        ) -> Result<Option<String>, crate::CredentialStoreError> {
            Self::load(self, service, account)
        }

        fn save(
            &self,
            service: &str,
            account: &str,
            value: &str,
        ) -> Result<(), crate::CredentialStoreError> {
            Self::save(self, service, account, value)
        }

        fn delete(
            &self,
            service: &str,
            account: &str,
        ) -> Result<bool, crate::CredentialStoreError> {
            Self::delete(self, service, account)
        }
    }
}

pub use testing::MockKeyringStore;
