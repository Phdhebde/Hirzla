//! The only value types an audit event may carry (`docs/evenements.md` § 2).
//!
//! Every type here is fixed-size or drawn from a closed list: an identifier drawn at random,
//! a digest, an IP address, a code, a counter or a flag. None can hold free text or arbitrary
//! bytes, so no event can carry a password, a note, a title, a key or any other secret. The
//! [`AuditField`] trait is sealed: no other crate can add a field type.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::cbor::{self, Fields, Value};
use crate::Error;

/// What an identifier designates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdKind {
    /// An audit log.
    Log,
    /// A member (`docs/format.md` § 3).
    Member,
    /// A device of a member (ADR 0011).
    Device,
    /// A locker.
    Locker,
    /// A secret, inside its locker.
    Secret,
    /// A server administration account.
    Account,
}

/// A field value, as exporters see it. Every variant is fixed-size or a closed code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldValue {
    /// A random 16-byte identifier.
    Id(IdKind, [u8; 16]),
    /// A SHA-384 digest: operation identifier or key fingerprint.
    Digest48([u8; 48]),
    /// A SHA3-256 digest: audit entry hash.
    Digest32([u8; 32]),
    /// An IP address, as the server sees it in its sessions.
    Ip(IpAddr),
    /// A value of a closed list: its code and its export name.
    Code(u8, &'static str),
    /// A counter.
    Count(u64),
    /// A flag.
    Flag(bool),
    /// An optional field left out.
    Absent,
}

/// A named field of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// Key in the event map (`docs/evenements.md`).
    pub key: u64,
    /// Export name.
    pub name: &'static str,
    /// Value.
    pub value: FieldValue,
}

mod sealed {
    use crate::cbor::Value;
    use crate::Error;

    pub trait Sealed: Sized {
        fn to_cbor(&self) -> Option<Value>;
        fn from_cbor(v: Option<&Value>) -> Result<Self, Error>;
    }
}

use sealed::Sealed;

/// A type an event field may have. Sealed: see the module documentation.
pub trait AuditField: Sealed {
    /// The value as exporters see it.
    fn field_value(&self) -> FieldValue;
    /// A placeholder value, for documentation and tests.
    fn example() -> Self;
}

pub(crate) fn put<T: AuditField>(map: &mut Vec<(u64, Value)>, key: u64, v: &T) {
    if let Some(value) = v.to_cbor() {
        map.push((key, value));
    }
}

pub(crate) fn take<T: AuditField>(fields: &Fields<'_>, key: u64) -> Result<T, Error> {
    T::from_cbor(fields.opt(key))
}

fn required(v: Option<&Value>) -> Result<&Value, Error> {
    v.ok_or(Error::Malformed)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    s
}

macro_rules! id16 {
    ($(#[$doc:meta])* $name:ident, $kind:expr) => {
        $(#[$doc])*
        ///
        /// Drawn at random by its creator; public metadata, never a secret.
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Wraps 16 bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                $name(bytes)
            }

            /// Draws a fresh identifier from the system random generator.
            ///
            /// # Errors
            /// [`Error::Crypto`] if the generator fails.
            pub fn random() -> Result<Self, Error> {
                Ok($name(hirzla_crypto::util::random_array()?))
            }

            /// The 16 bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex(&self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex(&self.0))
            }
        }

        impl Sealed for $name {
            fn to_cbor(&self) -> Option<Value> {
                Some(Value::bytes(&self.0))
            }
            fn from_cbor(v: Option<&Value>) -> Result<Self, Error> {
                Ok($name(cbor::fixed(required(v)?)?))
            }
        }

        impl AuditField for $name {
            fn field_value(&self) -> FieldValue {
                FieldValue::Id($kind, self.0)
            }
            fn example() -> Self {
                $name([$kind as u8 + 1; 16])
            }
        }
    };
}

id16!(
    /// Identifier of an audit log.
    LogId,
    IdKind::Log
);
id16!(
    /// Identifier of a member.
    MemberId,
    IdKind::Member
);
id16!(
    /// Identifier of a device.
    DeviceId,
    IdKind::Device
);
id16!(
    /// Identifier of a locker.
    LockerId,
    IdKind::Locker
);
id16!(
    /// Identifier of a secret (`secret_id`, `docs/format.md` § 7.2). Revealing it to the
    /// server is a choice of the site (ADR 0021).
    SecretId,
    IdKind::Secret
);
id16!(
    /// Identifier of a server administration account.
    AccountId,
    IdKind::Account
);

macro_rules! digest {
    ($(#[$doc:meta])* $name:ident, $len:literal, $variant:ident, $fill:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Wraps the digest bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                $name(bytes)
            }

            /// The digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex(&self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex(&self.0))
            }
        }

        impl Sealed for $name {
            fn to_cbor(&self) -> Option<Value> {
                Some(Value::bytes(&self.0))
            }
            fn from_cbor(v: Option<&Value>) -> Result<Self, Error> {
                Ok($name(cbor::fixed(required(v)?)?))
            }
        }

        impl AuditField for $name {
            fn field_value(&self) -> FieldValue {
                FieldValue::$variant(self.0)
            }
            fn example() -> Self {
                $name([$fill; $len])
            }
        }
    };
}

digest!(
    /// Identifier of an operation: SHA-384 of the encoded operation (`docs/format.md` § 7.1).
    OpId,
    48,
    Digest48,
    0x0a
);
digest!(
    /// Fingerprint of a public key: SHA-384 of its encoding.
    KeyFingerprint,
    48,
    Digest48,
    0x0b
);
digest!(
    /// Hash of an audit entry: the link of the chain (SHA3-256, `docs/evenements.md` § 3).
    EntryHash,
    32,
    Digest32,
    0x0c
);

impl KeyFingerprint {
    /// Fingerprint of a hybrid verifying key.
    #[must_use]
    pub fn of(key: &hirzla_crypto::sign::VerifyingKey) -> Self {
        KeyFingerprint(hirzla_crypto::util::sha384(key.as_bytes()))
    }
}

impl EntryHash {
    /// The all-zero value, `prev` of the first entry of a log.
    pub const ZERO: EntryHash = EntryHash([0; 32]);
}

impl Sealed for IpAddr {
    fn to_cbor(&self) -> Option<Value> {
        Some(match self {
            IpAddr::V4(a) => Value::bytes(&a.octets()),
            IpAddr::V6(a) => Value::bytes(&a.octets()),
        })
    }
    fn from_cbor(v: Option<&Value>) -> Result<Self, Error> {
        let b = cbor::bytes(required(v)?)?;
        if let Ok(a) = <[u8; 4]>::try_from(b) {
            Ok(IpAddr::V4(Ipv4Addr::from(a)))
        } else if let Ok(a) = <[u8; 16]>::try_from(b) {
            Ok(IpAddr::V6(Ipv6Addr::from(a)))
        } else {
            Err(Error::Malformed)
        }
    }
}

impl AuditField for IpAddr {
    fn field_value(&self) -> FieldValue {
        FieldValue::Ip(*self)
    }
    fn example() -> Self {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
    }
}

/// A counter or a sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Count(pub u64);

impl Sealed for Count {
    fn to_cbor(&self) -> Option<Value> {
        Some(Value::Uint(self.0))
    }
    fn from_cbor(v: Option<&Value>) -> Result<Self, Error> {
        Ok(Count(cbor::uint(required(v)?)?))
    }
}

impl AuditField for Count {
    fn field_value(&self) -> FieldValue {
        FieldValue::Count(self.0)
    }
    fn example() -> Self {
        Count(3)
    }
}

impl Sealed for bool {
    fn to_cbor(&self) -> Option<Value> {
        Some(Value::Bool(*self))
    }
    fn from_cbor(v: Option<&Value>) -> Result<Self, Error> {
        cbor::boolean(required(v)?)
    }
}

impl AuditField for bool {
    fn field_value(&self) -> FieldValue {
        FieldValue::Flag(*self)
    }
    fn example() -> Self {
        true
    }
}

impl<T: AuditField> Sealed for Option<T> {
    fn to_cbor(&self) -> Option<Value> {
        self.as_ref().and_then(Sealed::to_cbor)
    }
    fn from_cbor(v: Option<&Value>) -> Result<Self, Error> {
        match v {
            None => Ok(None),
            Some(v) => T::from_cbor(Some(v)).map(Some),
        }
    }
}

impl<T: AuditField> AuditField for Option<T> {
    fn field_value(&self) -> FieldValue {
        match self {
            Some(v) => v.field_value(),
            None => FieldValue::Absent,
        }
    }
    fn example() -> Self {
        Some(T::example())
    }
}

/// Defines a closed list encoded as a small unsigned integer.
macro_rules! code_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident = $code:literal, $export:literal;)+ }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vdoc])* $variant,)+
        }

        impl $name {
            /// Every value, in code order.
            pub const ALL: &'static [$name] = &[$($name::$variant,)+];

            /// The code stored in the log.
            #[must_use]
            pub const fn code(self) -> u8 {
                match self { $($name::$variant => $code,)+ }
            }

            /// The export name.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self { $($name::$variant => $export,)+ }
            }

            /// The value of a code, if it exists.
            #[must_use]
            pub fn from_code(code: u64) -> Option<Self> {
                match code { $($code => Some($name::$variant),)+ _ => None }
            }
        }

        impl Sealed for $name {
            fn to_cbor(&self) -> Option<Value> {
                Some(Value::Uint(u64::from(self.code())))
            }
            fn from_cbor(v: Option<&Value>) -> Result<Self, Error> {
                $name::from_code(cbor::uint(required(v)?)?).ok_or(Error::Malformed)
            }
        }

        impl AuditField for $name {
            fn field_value(&self) -> FieldValue {
                FieldValue::Code(self.code(), self.name())
            }
            fn example() -> Self {
                $name::ALL[0]
            }
        }
    };
}

code_enum!(
    /// Role in a locker (`docs/sync-protocol.md` § 7.1, same codes).
    Role {
        /// `Owner`.
        Owner = 1, "owner";
        /// `Manager`.
        Manager = 2, "manager";
        /// `Editor`.
        Editor = 3, "editor";
        /// `Reader`.
        Reader = 4, "reader";
        /// `BlindUser`.
        BlindUser = 5, "blind_user";
        /// `Auditor`.
        Auditor = 6, "auditor";
    }
);

code_enum!(
    /// Why a session authentication was refused.
    AuthFailure {
        /// The signature did not verify.
        BadSignature = 1, "bad_signature";
        /// Unknown device.
        UnknownDevice = 2, "unknown_device";
        /// Revoked device or member.
        Revoked = 3, "revoked";
        /// Expired or replayed challenge.
        Expired = 4, "expired";
        /// Invalid device certificate.
        BadCertificate = 5, "bad_certificate";
        /// Protocol violation.
        Protocol = 6, "protocol";
    }
);

code_enum!(
    /// Class of an operation (`docs/format.md` § 7.1).
    OpClass {
        /// Data operation: its type is sealed.
        Data = 1, "data";
        /// Control operation.
        Control = 2, "control";
    }
);

code_enum!(
    /// Type of a control operation (`docs/sync-protocol.md` § 7.2, same codes).
    ControlKind {
        /// `LockerCreate`.
        LockerCreate = 10, "locker_create";
        /// `Grant`.
        Grant = 11, "grant";
        /// `Revoke`.
        Revoke = 12, "revoke";
        /// `Rotate`.
        Rotate = 13, "rotate";
        /// `EnvelopeAdd`.
        EnvelopeAdd = 14, "envelope_add";
        /// `QuarantineAccept`.
        QuarantineAccept = 15, "quarantine_accept";
        /// `QuarantineReject`.
        QuarantineReject = 16, "quarantine_reject";
        /// `Compact`.
        Compact = 17, "compact";
        /// `Policy`.
        Policy = 18, "policy";
        /// `DeviceAdd`.
        DeviceAdd = 20, "device_add";
        /// `DeviceRemove`.
        DeviceRemove = 21, "device_remove";
    }
);

code_enum!(
    /// Why the server refused an operation.
    RejectReason {
        /// The signature did not verify.
        BadSignature = 1, "bad_signature";
        /// The author had no right to emit it (`docs/sync-protocol.md` § 9).
        NotAuthorized = 2, "not_authorized";
        /// Broken or forked author chain.
        BrokenChain = 3, "broken_chain";
        /// Malformed operation.
        Malformed = 4, "malformed";
        /// Unknown locker.
        UnknownLocker = 5, "unknown_locker";
        /// Quota exceeded.
        Quota = 6, "quota";
    }
);

code_enum!(
    /// Unlock method (`docs/format.md` § 4.2, same codes; 6 is recovery).
    UnlockMethod {
        /// Master password.
        Password = 1, "password";
        /// TPM 2.0.
        Tpm = 2, "tpm";
        /// Secure Enclave.
        SecureEnclave = 3, "secure_enclave";
        /// FIDO2 `hmac-secret`.
        Fido2 = 4, "fido2";
        /// Windows Hello.
        WindowsHello = 5, "windows_hello";
        /// Recovery shares or phrase.
        Recovery = 6, "recovery";
        /// Android Keystore: StrongBox HMAC after a fingerprint (ADR 0080).
        AndroidKeystore = 7, "android_keystore";
    }
);

code_enum!(
    /// Why the vault was locked.
    LockCause {
        /// At the user's request.
        User = 1, "user";
        /// Idle timeout.
        Idle = 2, "idle";
        /// The operating system session was locked.
        SessionLocked = 3, "session_locked";
        /// The core stopped.
        Shutdown = 4, "shutdown";
    }
);

code_enum!(
    /// How a secret was used on a device. The value itself never enters the log.
    UsageAction {
        /// Shown on screen.
        Reveal = 1, "reveal";
        /// Copied to the clipboard.
        Copy = 2, "copy";
        /// Filled by the extension, on the verified domain.
        Fill = 3, "fill";
        /// TOTP code computed.
        Totp = 4, "totp";
        /// Passkey signature (ADR 0010).
        PasskeySign = 5, "passkey_sign";
        /// SSH agent signature (ADR 0010).
        SshSign = 6, "ssh_sign";
        /// Used by a machine member without disclosure (`BlindUser`).
        BlindUse = 7, "blind_use";
    }
);

code_enum!(
    /// A server policy family.
    PolicyKind {
        /// Accounts and authentication.
        Accounts = 1, "accounts";
        /// Sessions.
        Sessions = 2, "sessions";
        /// Retention.
        Retention = 3, "retention";
        /// Exports.
        Export = 4, "export";
        /// Audit.
        Audit = 5, "audit";
    }
);

code_enum!(
    /// Export format of the audit log.
    ExportFormat {
        /// Native signed file (`docs/evenements.md` § 5).
        Native = 1, "native";
        /// JSON lines.
        Json = 2, "json";
        /// CEF.
        Cef = 3, "cef";
        /// Syslog over TLS.
        Syslog = 4, "syslog";
    }
);
