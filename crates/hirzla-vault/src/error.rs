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
    /// A KeePass (KDBX) database could not be read for import.
    #[error("KeePass database refused")]
    Kdbx(KdbxRefusal),
    /// An encrypted locker export could not be written or read (ADR 0077).
    #[error("locker export refused")]
    Export(ExportRefusal),
}

/// Why a locker export was refused (ADR 0077). Says no more than needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExportRefusal {
    /// Not an export file (no magic).
    NotExport,
    /// An export of a version this build does not read.
    Unsupported,
    /// The password is wrong, or the manifest was altered (the cause is not given).
    WrongKey,
    /// The file is malformed, was altered after its manifest, or carries a secret the vault
    /// would refuse.
    Malformed,
    /// A size exceeds the bounds of the format.
    TooLarge,
    /// The export password chosen by the user is below the floor.
    WeakPassword,
}

/// Why a KeePass database was refused by the import (ADR 0025). Says no more than needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdbxRefusal {
    /// Not a KeePass database (no KeePass signature).
    NotKdbx,
    /// A KeePass database this reader does not handle (KDBX 2 or earlier, Twofish, ArcFour
    /// inner stream, cost beyond the bounds, unknown field).
    Unsupported,
    /// The password or key file is wrong, or the header was altered (the cause is not
    /// given).
    WrongKey,
    /// The database is malformed or was altered after its header.
    Malformed,
    /// A size exceeds the bounds of this reader.
    TooLarge,
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
