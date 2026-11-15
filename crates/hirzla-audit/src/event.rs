//! The event catalogue (`docs/evenements.md` § 4).
//!
//! Every field has a type from [`crate::field`]: identifiers, digests, IP addresses, codes,
//! counters, flags. No event can hold free text or arbitrary bytes, hence no secret.

use std::net::IpAddr;

use crate::cbor::{self, Fields, Value};
use crate::field::{
    put, take, AccountId, AuditField, AuthFailure, ControlKind, Count, DeviceId, EntryHash,
    ExportFormat, Field, KeyFingerprint, LockCause, LockerId, LogId, MemberId, OpClass, OpId,
    PolicyKind, RejectReason, Role, SecretId, UnlockMethod, UsageAction,
};
use crate::Error;

/// Which log may record an event (ADR 0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The server log only (`hirzlad`).
    Server,
    /// A device's local log only (`hirzla-core`).
    Device,
    /// Either log.
    Any,
}

impl Origin {
    /// Whether a log kept by `keeper` may record an event of this origin.
    #[must_use]
    pub fn allows(self, keeper: crate::Keeper) -> bool {
        matches!(
            (self, keeper),
            (Origin::Any, _)
                | (Origin::Server, crate::Keeper::Server)
                | (Origin::Device, crate::Keeper::Device)
        )
    }
}

/// Severity, mapped to syslog and CEF by the exporters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Routine activity.
    Info,
    /// A change of rights, keys or configuration.
    Notice,
    /// A refusal or a failure.
    Warning,
    /// A sign of compromise.
    Alert,
}

macro_rules! events {
    ($(
        $(#[$doc:meta])*
        $variant:ident = $code:literal, $name:literal, $origin:ident, $severity:ident {
            $($(#[$fdoc:meta])* $field:ident : $ty:ty = $key:literal,)*
        }
    )+) => {
        /// An audit event. Never contains a secret value.
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum Event {
            $(
                $(#[$doc])*
                $variant {
                    $($(#[$fdoc])* $field: $ty,)*
                },
            )+
        }

        /// The type of an [`Event`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum EventKind {
            $($(#[$doc])* $variant,)+
        }

        impl EventKind {
            /// Every event type, in catalogue order.
            pub const ALL: &'static [EventKind] = &[$(EventKind::$variant,)+];

            /// The code stored in the log.
            #[must_use]
            pub const fn code(self) -> u16 {
                match self { $(EventKind::$variant => $code,)+ }
            }

            /// The export name.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self { $(EventKind::$variant => $name,)+ }
            }

            /// Which log may record it.
            #[must_use]
            pub const fn origin(self) -> Origin {
                match self { $(EventKind::$variant => Origin::$origin,)+ }
            }

            /// Its severity.
            #[must_use]
            pub const fn severity(self) -> Severity {
                match self { $(EventKind::$variant => Severity::$severity,)+ }
            }

            /// The type of a code, if it exists.
            #[must_use]
            pub fn from_code(code: u64) -> Option<Self> {
                match code { $($code => Some(EventKind::$variant),)+ _ => None }
            }

            /// An event of this type with placeholder values, for documentation and tests.
            #[must_use]
            pub fn example(self) -> Event {
                match self {
                    $(EventKind::$variant => Event::$variant {
                        $($field: <$ty as AuditField>::example(),)*
                    },)+
                }
            }
        }

        impl Event {
            /// Its type.
            #[must_use]
            pub fn kind(&self) -> EventKind {
                match self { $(Event::$variant { .. } => EventKind::$variant,)+ }
            }

            /// Its fields, in key order, absent optional fields included.
            #[must_use]
            pub fn fields(&self) -> Vec<Field> {
                match self {
                    $(Event::$variant { $($field,)* } => vec![
                        $(Field { key: $key, name: stringify!($field), value: $field.field_value() },)*
                    ],)+
                }
            }

            pub(crate) fn to_value(&self) -> Value {
                let mut map = vec![(1, Value::Uint(u64::from(self.kind().code())))];
                match self {
                    $(Event::$variant { $($field,)* } => {
                        $(put(&mut map, $key, $field);)*
                    })+
                }
                Value::Map(map)
            }

            pub(crate) fn from_value(v: &Value) -> Result<Self, Error> {
                let Value::Map(map) = v else { return Err(Error::Malformed) };
                let code = map
                    .iter()
                    .find(|(k, _)| *k == 1)
                    .map(|(_, v)| cbor::uint(v))
                    .ok_or(Error::Malformed)??;
                let kind = EventKind::from_code(code).ok_or(Error::UnsupportedVersion)?;
                match kind {
                    $(EventKind::$variant => {
                        let f = Fields::new(v, &[1, $($key,)*])?;
                        Ok(Event::$variant { $($field: take::<$ty>(&f, $key)?,)* })
                    })+
                }
            }
        }
    };
}

events! {
    // --- Sessions (server) -------------------------------------------------------------
    /// A device opened an authenticated session.
    SessionOpened = 1, "session_opened", Server, Info {
        /// Member.
        member: MemberId = 2,
        /// Device.
        device: DeviceId = 3,
        /// Source address.
        ip: IpAddr = 4,
    }
    /// A session closed.
    SessionClosed = 2, "session_closed", Server, Info {
        /// Member.
        member: MemberId = 2,
        /// Device.
        device: DeviceId = 3,
    }
    /// A session authentication was refused.
    AuthenticationFailed = 3, "authentication_failed", Server, Warning {
        /// Claimed device, when it parsed.
        device: Option<DeviceId> = 2,
        /// Source address.
        ip: IpAddr = 3,
        /// Reason.
        reason: AuthFailure = 4,
    }

    // --- Synchronisation (server) ------------------------------------------------------
    /// The server accepted an operation.
    OperationAccepted = 10, "operation_accepted", Server, Info {
        /// Locker.
        locker: LockerId = 2,
        /// Operation.
        op: OpId = 3,
        /// Author member.
        member: MemberId = 4,
        /// Author device.
        device: DeviceId = 5,
        /// Class.
        class: OpClass = 6,
        /// Type of a control operation; absent for a data operation, whose type is sealed.
        control: Option<ControlKind> = 7,
    }
    /// The server refused an operation.
    OperationRejected = 11, "operation_rejected", Server, Warning {
        /// Locker.
        locker: LockerId = 2,
        /// Operation.
        op: OpId = 3,
        /// Author device.
        device: DeviceId = 4,
        /// Reason.
        reason: RejectReason = 5,
    }
    /// An operation went to quarantine (`docs/roles.md`).
    OperationQuarantined = 12, "operation_quarantined", Server, Notice {
        /// Locker.
        locker: LockerId = 2,
        /// Operation.
        op: OpId = 3,
        /// Author device.
        device: DeviceId = 4,
    }
    /// A quarantined operation was accepted or rejected.
    QuarantineResolved = 13, "quarantine_resolved", Server, Notice {
        /// Locker.
        locker: LockerId = 2,
        /// Operation.
        op: OpId = 3,
        /// Accepted (true) or rejected (false).
        accepted: bool = 4,
        /// Rejected by default after the delay.
        automatic: bool = 5,
    }
    /// A device pulled a locker.
    LockerPulled = 14, "locker_pulled", Server, Info {
        /// Locker.
        locker: LockerId = 2,
        /// Member.
        member: MemberId = 3,
        /// Device.
        device: DeviceId = 4,
    }

    // --- Rights and devices (server, from accepted control operations) -----------------
    /// A role was granted or changed.
    RoleGranted = 20, "role_granted", Server, Notice {
        /// Locker.
        locker: LockerId = 2,
        /// Member receiving the role.
        member: MemberId = 3,
        /// Role.
        role: Role = 4,
        /// Granting member.
        by: MemberId = 5,
    }
    /// A member left or was removed from a locker.
    RoleRevoked = 21, "role_revoked", Server, Notice {
        /// Locker.
        locker: LockerId = 2,
        /// Member removed.
        member: MemberId = 3,
        /// Removing member (the member itself when leaving).
        by: MemberId = 4,
    }
    /// A locker key rotated.
    LockerKeyRotated = 22, "locker_key_rotated", Server, Info {
        /// Locker.
        locker: LockerId = 2,
        /// Member whose device rotated it.
        by: MemberId = 3,
    }
    /// A device was certified and added.
    DeviceAdded = 23, "device_added", Server, Notice {
        /// Member.
        member: MemberId = 2,
        /// Device.
        device: DeviceId = 3,
        /// Fingerprint of the device signing key.
        key: KeyFingerprint = 4,
    }
    /// A device was revoked.
    DeviceRevoked = 24, "device_revoked", Server, Notice {
        /// Member.
        member: MemberId = 2,
        /// Device.
        device: DeviceId = 3,
    }
    /// The owner removal quorum of a locker changed.
    QuorumChanged = 25, "quorum_changed", Server, Notice {
        /// Locker.
        locker: LockerId = 2,
        /// New quorum.
        quorum: Count = 3,
    }

    // --- Use on a device (device log) --------------------------------------------------
    /// The vault was unlocked.
    VaultUnlocked = 30, "vault_unlocked", Device, Info {
        /// Device.
        device: DeviceId = 2,
        /// Method.
        method: UnlockMethod = 3,
    }
    /// An unlock attempt failed.
    UnlockFailed = 31, "unlock_failed", Device, Warning {
        /// Device.
        device: DeviceId = 2,
        /// Method.
        method: UnlockMethod = 3,
        /// Consecutive failures so far.
        attempts: Count = 4,
    }
    /// The vault was locked.
    VaultLocked = 32, "vault_locked", Device, Info {
        /// Device.
        device: DeviceId = 2,
        /// Cause.
        cause: LockCause = 3,
    }
    /// A secret was used. The value never enters the log.
    SecretUsed = 33, "secret_used", Device, Info {
        /// Locker.
        locker: LockerId = 2,
        /// Secret; absent unless the site chose to reveal it to the server (ADR 0021).
        secret: Option<SecretId> = 3,
        /// Member.
        member: MemberId = 4,
        /// Device.
        device: DeviceId = 5,
        /// How.
        action: UsageAction = 6,
    }
    /// A locker was exported (encrypted export file).
    LockerExported = 34, "locker_exported", Device, Notice {
        /// Locker.
        locker: LockerId = 2,
        /// Member.
        member: MemberId = 3,
        /// Device.
        device: DeviceId = 4,
    }
    /// A decoy credential was used: sign of theft.
    DecoyTriggered = 35, "decoy_triggered", Server, Alert {
        /// Locker.
        locker: LockerId = 2,
        /// Decoy secret, when known.
        secret: Option<SecretId> = 3,
        /// Source address, when known.
        ip: Option<IpAddr> = 4,
    }

    // --- Administration (server) -------------------------------------------------------
    /// An administrator logged in to the administration interface.
    AdminLogin = 40, "admin_login", Server, Notice {
        /// Account.
        account: AccountId = 2,
        /// Source address.
        ip: IpAddr = 3,
    }
    /// An administrator login was refused.
    AdminLoginFailed = 41, "admin_login_failed", Server, Warning {
        /// Source address.
        ip: IpAddr = 2,
    }
    /// A member account was created.
    AccountCreated = 42, "account_created", Server, Notice {
        /// Administrator.
        account: AccountId = 2,
        /// Member.
        member: MemberId = 3,
    }
    /// A member account was disabled.
    AccountDisabled = 43, "account_disabled", Server, Notice {
        /// Administrator.
        account: AccountId = 2,
        /// Member.
        member: MemberId = 3,
    }
    /// A server policy changed.
    PolicyChanged = 44, "policy_changed", Server, Notice {
        /// Administrator.
        account: AccountId = 2,
        /// Policy family.
        policy: PolicyKind = 3,
    }

    // --- The log itself ----------------------------------------------------------------
    /// First entry of every log.
    LogStarted = 50, "log_started", Any, Notice {
        /// Log this one continues, if any.
        previous_log: Option<LogId> = 2,
        /// Last entry hash of that log.
        previous_head: Option<EntryHash> = 3,
    }
    /// The log was reopened after a stop.
    LogResumed = 51, "log_resumed", Any, Notice {
        /// An incomplete trailing record, left by a crash, was cut.
        torn_tail: bool = 2,
        /// Entries found after the last checkpoint, now covered by the keeper's signature.
        uncovered: Count = 3,
    }
    /// Someone consulted the log.
    AuditViewed = 52, "audit_viewed", Server, Info {
        /// Member (auditor, owner or manager of a locker).
        member: Option<MemberId> = 2,
        /// Administration account.
        account: Option<AccountId> = 3,
        /// Number of lockers in the view; 0 for the whole log.
        lockers: Count = 4,
    }
    /// The log was exported.
    AuditExported = 53, "audit_exported", Any, Info {
        /// Format.
        format: ExportFormat = 2,
        /// First sequence number exported.
        first: Count = 3,
        /// Last sequence number exported.
        last: Count = 4,
    }
    /// The server verified and stored a part of a device log.
    DeviceLogIngested = 54, "device_log_ingested", Server, Info {
        /// Member.
        member: MemberId = 2,
        /// Device.
        device: DeviceId = 3,
        /// Device log.
        log: LogId = 4,
        /// Last sequence number covered by the device checkpoint.
        last: Count = 5,
        /// Head of the device log at that sequence number.
        head: EntryHash = 6,
    }
}

impl Event {
    /// The locker this event concerns, if any: what scopes an owner's or auditor's view.
    #[must_use]
    pub fn locker(&self) -> Option<LockerId> {
        self.fields().into_iter().find_map(|f| match f.value {
            crate::field::FieldValue::Id(crate::field::IdKind::Locker, b) => {
                Some(LockerId::from_bytes(b))
            }
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests;
