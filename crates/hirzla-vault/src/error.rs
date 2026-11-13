//! The single error type of `hirzla-vault`. Messages never carry content or key material.

/// Errors returned by `hirzla-vault`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// The file is not a Hirzla vault.
    #[error("not a Hirzla vault")]
    NotAVault,
    /// The vault uses a format version this build does not read.
    #[error("unsupported vault format version")]
    UnsupportedVersion,
    /// The vault is corrupted, truncated or has been tampered with.
    #[error("the vault is corrupted or has been tampered with")]
    Corrupt,
    /// The vault could not be unlocked.
    #[error("unlock failed")]
    Unlock,
    /// The request is invalid (bad parameter, field not allowed, missing required field).
    #[error("invalid request")]
    InvalidInput,
    /// No such locker, secret or attachment.
    #[error("not found")]
    NotFound,
    /// The vault needs a feature of a later step (hardware unlock, rotation, sync).
    #[error("not supported by this version")]
    Unsupported,
    /// The file already exists.
    #[error("the file already exists")]
    AlreadyExists,
    /// The vault path goes through a symbolic link (on any component), which is refused.
    #[error("the vault path must not go through a symbolic link")]
    SymlinkInPath,
    /// Storage failure.
    #[error("storage error")]
    Storage,
    /// Cryptographic failure.
    #[error("cryptographic failure")]
    Crypto,
}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        #[cfg(test)]
        if let rusqlite::Error::SqliteFailure(f, _) = &e {
            diagnostics::record(f.extended_code);
        }
        match e {
            rusqlite::Error::SqliteFailure(f, _)
                if f.extended_code == rusqlite::ffi::SQLITE_CANTOPEN_SYMLINK =>
            {
                VaultError::SymlinkInPath
            }
            rusqlite::Error::SqliteFailure(f, _)
                if matches!(
                    f.code,
                    rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt
                ) =>
            {
                VaultError::Corrupt
            }
            _ => VaultError::Storage,
        }
    }
}

impl From<crate::cbor::CborError> for VaultError {
    fn from(_: crate::cbor::CborError) -> Self {
        VaultError::Corrupt
    }
}

impl From<hirzla_crypto::Error> for VaultError {
    fn from(_: hirzla_crypto::Error) -> Self {
        VaultError::Crypto
    }
}

/// Test-only diagnostics: the extended SQLite result code behind the last storage error of
/// this thread. The public error never carries it.
#[cfg(test)]
pub(crate) mod diagnostics {
    use std::cell::Cell;

    thread_local! {
        static LAST: Cell<Option<i32>> = const { Cell::new(None) };
    }

    pub(crate) fn record(code: i32) {
        LAST.with(|c| c.set(Some(code)));
    }

    /// Extended SQLite result code of the last storage error on this thread.
    pub(crate) fn last_sqlite_code() -> Option<i32> {
        LAST.with(Cell::get)
    }
}
