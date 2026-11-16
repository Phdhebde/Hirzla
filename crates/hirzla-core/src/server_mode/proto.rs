//! Server mode operations of the local API (`docs/api-locale.md` § 15): version 4, operation
//! codes 40 to 49 (49: device revocation, ADR 0059), 90 to 98 (approvals and quarantine,
//! ADR 0044 and 0045) and 120 to 122 (display names, ADR 0069), error codes 40 to 49 and
//! 90 to 93. Same frames, same CBOR profile and same strict decoding as the rest of the API
//! (`crate::proto`).

pub use hirzla_access::profile::{valid_display_name, MAX_DISPLAY_NAME};
pub use hirzla_access::Role;
use hirzla_vault::cbor::{
    self, array_max, boolean, bytes_max, fixed, text_max, uint, Fields, Value,
};
use hirzla_vault::model::{Id16, OpId, MAX_SERVER_URL};
use zeroize::Zeroizing;

use crate::proto::ErrorCode;

/// Version of the protocol that carries the server mode operations.
pub const SERVER_VERSION: u64 = 4;
/// Operation codes reserved for the server mode.
pub const SERVER_OPS: std::ops::RangeInclusive<u64> = 40..=49;
/// Operation codes of the approvals and the quarantine, also version 4 (ADR 0044, 0045).
pub const GOVERNANCE_OPS: std::ops::RangeInclusive<u64> = 90..=99;
/// Operation codes of the member directory, also version 4 (ADR 0069). 120 to 129 are
/// reserved for the server mode.
pub const DIRECTORY_OPS: std::ops::RangeInclusive<u64> = 120..=129;
/// Shortest text searched in the directory, in bytes (`sync-protocol.md` § 11.11).
pub const MIN_SEARCH: usize = hirzla_sync::net::proto::MIN_FIND_QUERY;
/// Most members in the result of a search.
pub const MAX_FOUND: usize = hirzla_sync::net::proto::MAX_FOUND;
/// Longest text object accepted (`sync-protocol.md` § 11.10).
pub const MAX_TEXT: usize = hirzla_sync::text::MAX_TEXT;
/// Most pending approval requests (`format.md` § 15.2).
pub const MAX_REQUESTS: usize = 64;
/// Largest site CA file, in bytes.
pub const MAX_ROOTS: usize = 64 * 1024;
/// Largest shared locker name, in bytes.
pub const MAX_LOCKER_NAME: usize = 256;
/// Most lockers or members in a reply.
pub const MAX_LIST: usize = 4096;
/// Length of a fingerprint (`format.md` § 3.1).
pub const FINGERPRINT_LEN: usize = 20;
/// Longest fingerprint accepted as typed (spaces and dashes are removed).
const MAX_TYPED_FINGERPRINT: usize = 64;
/// Largest encoded `MemberKeys`.
const MAX_MEMBER_KEYS: usize = 4096;

/// Server mode operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerOp {
    /// State of the server mode.
    ServerStatus = 40,
    /// Public identity to give to the server administrator.
    ServerIdentity = 41,
    /// Join a server.
    ServerJoin = 42,
    /// Confirm the server fingerprint compared out of band.
    ServerConfirm = 43,
    /// Synchronise every shared locker.
    ServerSync = 44,
    /// Create a shared locker.
    SharedLockerCreate = 45,
    /// Grant a role (new member or role change).
    RoleGrant = 46,
    /// Remove a member.
    RoleRevoke = 47,
    /// Members and roles of a shared locker.
    LockerMembers = 48,
    /// Revoke another device of the member (ADR 0059).
    DeviceRevoke = 49,
    /// Prepare an approval request (ADR 0044).
    QuorumPrepare = 90,
    /// Read an approval request before signing it.
    QuorumInspect = 91,
    /// Sign an approval request.
    QuorumApprove = 92,
    /// Add an approval to a pending request.
    QuorumCollect = 93,
    /// Publish the operation of a request whose quorum is met.
    QuorumApply = 94,
    /// Pending requests.
    QuorumList = 95,
    /// Drop a pending request.
    QuorumCancel = 96,
    /// Quarantined operations of a locker (ADR 0045).
    QuarantineList = 97,
    /// Accept or reject quarantined operations.
    QuarantineDecide = 98,
    /// Set or withdraw the display name of the member (ADR 0069).
    ProfileSet = 120,
    /// Search the members of the server by display name.
    MemberSearch = 121,
    /// Record that the fingerprint of a member was compared out of band.
    MemberVerify = 122,
}

impl ServerOp {
    const ALL: [ServerOp; 22] = [
        ServerOp::ServerStatus,
        ServerOp::ServerIdentity,
        ServerOp::ServerJoin,
        ServerOp::ServerConfirm,
        ServerOp::ServerSync,
        ServerOp::SharedLockerCreate,
        ServerOp::RoleGrant,
        ServerOp::RoleRevoke,
        ServerOp::LockerMembers,
        ServerOp::DeviceRevoke,
        ServerOp::QuorumPrepare,
        ServerOp::QuorumInspect,
        ServerOp::QuorumApprove,
        ServerOp::QuorumCollect,
        ServerOp::QuorumApply,
        ServerOp::QuorumList,
        ServerOp::QuorumCancel,
        ServerOp::QuarantineList,
        ServerOp::QuarantineDecide,
        ServerOp::ProfileSet,
        ServerOp::MemberSearch,
        ServerOp::MemberVerify,
    ];

    /// The operation from its number.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<ServerOp> {
        ServerOp::ALL.into_iter().find(|o| *o as u64 == n)
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ServerOp::ServerStatus => "server_status",
            ServerOp::ServerIdentity => "server_identity",
            ServerOp::ServerJoin => "server_join",
            ServerOp::ServerConfirm => "server_confirm",
            ServerOp::ServerSync => "server_sync",
            ServerOp::SharedLockerCreate => "shared_locker_create",
            ServerOp::RoleGrant => "role_grant",
            ServerOp::RoleRevoke => "role_revoke",
            ServerOp::LockerMembers => "locker_members",
            ServerOp::DeviceRevoke => "device_revoke",
            ServerOp::QuorumPrepare => "quorum_prepare",
            ServerOp::QuorumInspect => "quorum_inspect",
            ServerOp::QuorumApprove => "quorum_approve",
            ServerOp::QuorumCollect => "quorum_collect",
            ServerOp::QuorumApply => "quorum_apply",
            ServerOp::QuorumList => "quorum_list",
            ServerOp::QuorumCancel => "quorum_cancel",
            ServerOp::QuarantineList => "quarantine_list",
            ServerOp::QuarantineDecide => "quarantine_decide",
            ServerOp::ProfileSet => "profile_set",
            ServerOp::MemberSearch => "member_search",
            ServerOp::MemberVerify => "member_verify",
        }
    }
}

/// Error codes of the server mode (40 to 49, 90 to 93). The general codes of § 7 keep their
/// numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerCode {
    /// A general code of § 7.
    General(ErrorCode),
    /// 40: no server joined.
    NotJoined,
    /// 41: a server is already joined.
    AlreadyJoined,
    /// 42: the server fingerprint is not verified yet.
    ServerUnverified,
    /// 43: the fingerprint does not match the key received or pinned.
    FingerprintMismatch,
    /// 44: connection, TLS or server authentication impossible.
    ServerUnreachable,
    /// 45: the server refused, with its code (`sync-protocol.md` § 11.7).
    ServerRefused(u64),
    /// 46: the member's role does not allow the action, or it needs a quorum.
    Forbidden,
    /// 47: member unknown to the server directory.
    UnknownMember,
    /// 48: transparency proof missing or invalid for the key received.
    KeyLogRejected,
    /// 49: the device is already revoked (ADR 0059).
    AlreadyRevoked,
    /// 90: approval or request refused (ADR 0044).
    ApprovalInvalid,
    /// 91: the approvals collected do not reach the quorum: counted, required.
    QuorumNotMet(u64, u64),
    /// 92: writes to the locker are frozen (ADR 0045, `transparence.md` § 6.5).
    LockerFrozen,
    /// 93: invitation link malformed, altered or of an unknown version (ADR 0046).
    InvitationInvalid,
}

impl ServerCode {
    /// Status number on the wire.
    #[must_use]
    pub fn status(self) -> u64 {
        match self {
            ServerCode::General(c) => c as u64,
            ServerCode::NotJoined => 40,
            ServerCode::AlreadyJoined => 41,
            ServerCode::ServerUnverified => 42,
            ServerCode::FingerprintMismatch => 43,
            ServerCode::ServerUnreachable => 44,
            ServerCode::ServerRefused(_) => 45,
            ServerCode::Forbidden => 46,
            ServerCode::UnknownMember => 47,
            ServerCode::KeyLogRejected => 48,
            ServerCode::AlreadyRevoked => 49,
            ServerCode::ApprovalInvalid => 90,
            ServerCode::QuorumNotMet(..) => 91,
            ServerCode::LockerFrozen => 92,
            ServerCode::InvitationInvalid => 93,
        }
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ServerCode::General(c) => c.name(),
            ServerCode::NotJoined => "not_joined",
            ServerCode::AlreadyJoined => "already_joined",
            ServerCode::ServerUnverified => "server_unverified",
            ServerCode::FingerprintMismatch => "fingerprint_mismatch",
            ServerCode::ServerUnreachable => "server_unreachable",
            ServerCode::ServerRefused(_) => "server_refused",
            ServerCode::Forbidden => "forbidden",
            ServerCode::UnknownMember => "unknown_member",
            ServerCode::KeyLogRejected => "keylog_rejected",
            ServerCode::AlreadyRevoked => "already_revoked",
            ServerCode::ApprovalInvalid => "approval_invalid",
            ServerCode::QuorumNotMet(..) => "quorum_not_met",
            ServerCode::LockerFrozen => "locker_frozen",
            ServerCode::InvitationInvalid => "invitation_invalid",
        }
    }
}

impl From<ErrorCode> for ServerCode {
    fn from(c: ErrorCode) -> Self {
        ServerCode::General(c)
    }
}

/// A server mode request.
#[derive(Clone, PartialEq, Eq)]
pub enum ServerRequest {
    /// 40.
    ServerStatus,
    /// 41.
    ServerIdentity,
    /// 42.
    ServerJoin {
        /// `hirzla://host[:port]`.
        url: String,
        /// PEM certificates of the site CA.
        roots: Vec<u8>,
        /// Fingerprint from the invitation, normalised.
        fingerprint: Option<String>,
    },
    /// 42, with an invitation link (ADR 0046).
    ServerJoinLink {
        /// `hirzla-invitation:…`, whitespace allowed.
        link: String,
    },
    /// 43.
    ServerConfirm {
        /// Fingerprint compared out of band, normalised.
        fingerprint: String,
    },
    /// 44.
    ServerSync,
    /// 45.
    SharedLockerCreate {
        /// Name of the locker.
        name: Zeroizing<String>,
    },
    /// 46.
    RoleGrant {
        /// Locker.
        locker: Id16,
        /// Member.
        member: Id16,
        /// Role.
        role: Role,
        /// Expected member fingerprint, normalised.
        fingerprint: Option<String>,
    },
    /// 47.
    RoleRevoke {
        /// Locker.
        locker: Id16,
        /// Member.
        member: Id16,
    },
    /// 48.
    LockerMembers {
        /// Locker.
        locker: Id16,
    },
    /// 49.
    DeviceRevoke {
        /// Another device of the member.
        device: Id16,
    },
    /// 90.
    QuorumPrepare {
        /// Locker.
        locker: Id16,
        /// Action.
        action: QuorumAction,
        /// Member targeted (actions 1 and 2).
        target: Option<Id16>,
        /// New role code (action 2) or new quorum (action 3).
        detail: Option<u64>,
    },
    /// 91.
    QuorumInspect {
        /// `hirzla-demande:…`.
        offer: String,
    },
    /// 92.
    QuorumApprove {
        /// `hirzla-demande:…`.
        offer: String,
    },
    /// 93.
    QuorumCollect {
        /// `hirzla-accord:…`.
        token: String,
    },
    /// 94.
    QuorumApply {
        /// Request identifier.
        request: Id16,
    },
    /// 95.
    QuorumList {
        /// Only this locker, if given.
        locker: Option<Id16>,
    },
    /// 96.
    QuorumCancel {
        /// Request identifier.
        request: Id16,
    },
    /// 97.
    QuarantineList {
        /// Locker.
        locker: Id16,
    },
    /// 98.
    QuarantineDecide {
        /// Locker.
        locker: Id16,
        /// Operations, sorted without duplicate.
        ops: Vec<OpId>,
        /// Accept (or reject).
        accept: bool,
    },
    /// 120.
    ProfileSet {
        /// Display name, valid (`format.md` § 3.7); empty to withdraw it.
        name: String,
    },
    /// 121.
    MemberSearch {
        /// Text searched in the display names, [`MIN_SEARCH`] to [`MAX_DISPLAY_NAME`] bytes.
        text: String,
    },
    /// 122.
    MemberVerify {
        /// Member.
        member: Id16,
        /// Fingerprint compared out of band, normalised.
        fingerprint: String,
    },
}

/// An action that takes approvals (`sync-protocol.md` § 7.7, `ApprovalRequest.action`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumAction {
    /// 1: remove an `Owner`.
    OwnerRemoval = 1,
    /// 2: change the role of an `Owner`.
    OwnerRoleChange = 2,
    /// 3: change the quorum.
    Policy = 3,
}

impl QuorumAction {
    /// The action from its code.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<QuorumAction> {
        [
            QuorumAction::OwnerRemoval,
            QuorumAction::OwnerRoleChange,
            QuorumAction::Policy,
        ]
        .into_iter()
        .find(|a| *a as u64 == n)
    }
}

/// A pending approval request (`docs/api-locale.md` § 15.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumState {
    /// Request identifier.
    pub request: Id16,
    /// Locker.
    pub locker: Id16,
    /// Action.
    pub action: QuorumAction,
    /// Member targeted.
    pub target: Option<Id16>,
    /// New role or quorum.
    pub detail: Option<u64>,
    /// Members counted: the initiator first, then the approvers.
    pub counted: Vec<Id16>,
    /// Quorum in force.
    pub required: u64,
    /// The text to hand to the other owners.
    pub offer: String,
    /// When it was prepared, wall clock milliseconds.
    pub created_ms: u64,
}

/// A quarantined operation, as an `Owner` judges it (ADR 0045). Never a secret value.
#[derive(Clone, PartialEq, Eq)]
pub struct QuarantinedOp {
    /// Operation.
    pub op_id: OpId,
    /// Author member.
    pub member: Id16,
    /// Author device.
    pub device: Id16,
    /// 1 concurrent with a removal, 2 fork.
    pub cause: u64,
    /// 1 data, 2 control.
    pub class: u64,
    /// Wall clock time the author announced (readable data only).
    pub wall_ms: Option<u64>,
    /// Title of the secret (readable data only).
    pub title: Option<Zeroizing<String>>,
    /// Secret concerned (readable data only).
    pub secret: Option<Id16>,
    /// First local reception.
    pub received_ms: u64,
    /// Automatic rejection due.
    pub due_ms: u64,
}

impl std::fmt::Debug for ServerRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServerRequest::{}", self.op().name())
    }
}

/// State of one shared locker (`docs/api-locale.md` § 15.2).
#[derive(Clone, PartialEq, Eq)]
pub struct LockerStatus {
    /// Locker.
    pub id: Id16,
    /// Name, once readable.
    pub name: Option<Zeroizing<String>>,
    /// Role of the member, if any.
    pub role: Option<Role>,
    /// Last `server_seq` received.
    pub cursor: u64,
    /// Local operations not acknowledged by the server.
    pub unsent: u64,
    /// Operations pending (status 0).
    pub pending: u64,
    /// Operations in quarantine (status 2).
    pub quarantined: u64,
    /// Whether the server still serves the locker.
    pub access: bool,
    /// Writes frozen: a removal announced in the key log was not received (ADR 0045).
    pub frozen: bool,
}

impl std::fmt::Debug for LockerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the name of the locker: it is confidential metadata.
        f.debug_struct("LockerStatus")
            .field("role", &self.role)
            .field("cursor", &self.cursor)
            .field("unsent", &self.unsent)
            .field("pending", &self.pending)
            .field("quarantined", &self.quarantined)
            .field("access", &self.access)
            .field("frozen", &self.frozen)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for QuarantinedOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the title of the secret: it is confidential metadata.
        f.debug_struct("QuarantinedOp")
            .field("cause", &self.cause)
            .field("class", &self.class)
            .field("received_ms", &self.received_ms)
            .field("due_ms", &self.due_ms)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ServerReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The variant only: replies carry locker names and titles (confidential metadata).
        let name = match self {
            Self::Done => "Done",
            Self::Status { .. } => "Status",
            Self::Identity { .. } => "Identity",
            Self::Joined { .. } => "Joined",
            Self::Confirmed { .. } => "Confirmed",
            Self::Synced(_) => "Synced",
            Self::LockerCreated(_) => "LockerCreated",
            Self::Granted { .. } => "Granted",
            Self::Members { .. } => "Members",
            Self::Request(_) => "Request",
            Self::Inspected { .. } => "Inspected",
            Self::Approved(_) => "Approved",
            Self::Requests(_) => "Requests",
            Self::Quarantine { .. } => "Quarantine",
            Self::DeviceRevoked { .. } => "DeviceRevoked",
            Self::Found { .. } => "Found",
        };
        f.debug_struct(name).finish_non_exhaustive()
    }
}

/// What one synchronisation did for one locker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
    /// Locker.
    pub locker: Id16,
    /// Operations received.
    pub received: u64,
    /// Operations sent and accepted (or already known).
    pub sent: u64,
    /// Operations the server refused.
    pub refused: u64,
    /// Whether the server still serves the locker.
    pub access: bool,
}

/// Most alerts in a reply (`docs/api-locale.md` § 15.2).
pub const MAX_ALERTS: usize = 4096;

/// Why the local key log is suspect (`transparence.md` § 6.7), as `ServerStatus` gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspectReason {
    /// 1: the recomputed root differs from the signed one.
    RootMismatch = 1,
    /// 2: a signed head is smaller than one already verified.
    SizeDecrease = 2,
    /// 3: an entry breaks a rule R1 to R5.
    RuleViolation = 3,
    /// 4: a peer head does not match the local entries.
    PeerHead = 4,
    /// 5: a peer head is larger than what the server serves.
    Unserved = 5,
    /// 6: an entry of an inclusion proof differs from the local one.
    ProofEntry = 6,
}

impl SuspectReason {
    const ALL: [SuspectReason; 6] = [
        SuspectReason::RootMismatch,
        SuspectReason::SizeDecrease,
        SuspectReason::RuleViolation,
        SuspectReason::PeerHead,
        SuspectReason::Unserved,
        SuspectReason::ProofEntry,
    ];

    /// The reason from its code.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<SuspectReason> {
        SuspectReason::ALL.into_iter().find(|r| *r as u64 == n)
    }
}

/// Kind of an alert of the key log watch (`transparence.md` § 6.4, § 6.5; ADR 0045).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    /// 1: a key inscribed for the member is not the member's key.
    ForeignMemberKey = 1,
    /// 2: a device unknown to the member is inscribed in its name.
    UnknownOwnDevice = 2,
    /// 3: a revocation unknown to the member is inscribed in its name.
    UnknownOwnRevocation = 3,
    /// 4: a removal inscribed for a locker was not received within the hour (locker frozen).
    WithheldRemoval = 4,
    /// 5: a removal this device issued is not inscribed within the hour.
    UninscribedRemoval = 5,
    /// 6: the certificate of this device is not inscribed within the hour.
    WithheldInscription = 6,
    /// 7: an operation waits for a dependency the server does not serve, for an hour.
    WithheldOperation = 7,
    /// 8: a display name unknown to the member is inscribed in its name (ADR 0069).
    UnknownOwnProfile = 8,
}

impl AlertKind {
    /// The kind from its code.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<AlertKind> {
        [
            AlertKind::ForeignMemberKey,
            AlertKind::UnknownOwnDevice,
            AlertKind::UnknownOwnRevocation,
            AlertKind::WithheldRemoval,
            AlertKind::UninscribedRemoval,
            AlertKind::WithheldInscription,
            AlertKind::WithheldOperation,
            AlertKind::UnknownOwnProfile,
        ]
        .into_iter()
        .find(|k| *k as u64 == n)
    }

    /// Whether the alert names an entry of the log (key 2).
    #[must_use]
    pub fn has_index(self) -> bool {
        (self as u64) <= 4 || self == AlertKind::UnknownOwnProfile
    }

    /// Whether the alert names a device (key 3).
    #[must_use]
    pub fn has_device(self) -> bool {
        matches!(
            self,
            AlertKind::UnknownOwnDevice
                | AlertKind::UnknownOwnRevocation
                | AlertKind::WithheldInscription
        )
    }

    /// Whether the alert names a locker (key 4).
    #[must_use]
    pub fn has_locker(self) -> bool {
        matches!(
            self,
            AlertKind::WithheldRemoval
                | AlertKind::UninscribedRemoval
                | AlertKind::WithheldOperation
        )
    }
}

/// An alert of the key log watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyLogAlert {
    /// Kind.
    pub kind: AlertKind,
    /// Rank of the entry in the log (kinds 1 to 4 and 8).
    pub index: Option<u64>,
    /// Device concerned (kinds 2, 3 and 6).
    pub device: Option<Id16>,
    /// Locker concerned (kinds 4, 5 and 7).
    pub locker: Option<Id16>,
}

/// State of the local key transparency log (`docs/api-locale.md` § 15.2, ADR 0041).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLogStatus {
    /// Why the log is suspect, if it is.
    pub suspect: Option<SuspectReason>,
    /// Local entries.
    pub entries: u64,
    /// Alerts about the member's own keys.
    pub alerts: Vec<KeyLogAlert>,
}

/// Why the current member may not do an action in a shared locker (ADR 0041).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// 1: the role does not allow it.
    RoleTooLow = 1,
    /// 2: a quorum of owners is required.
    QuorumRequired = 2,
    /// 3: the last owner can neither leave nor be demoted.
    LastOwner = 3,
    /// 4: the server no longer serves the locker to this member.
    AccessLost = 4,
}

impl Refusal {
    /// The refusal from its code.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<Refusal> {
        [
            Refusal::RoleTooLow,
            Refusal::QuorumRequired,
            Refusal::LastOwner,
            Refusal::AccessLost,
        ]
        .into_iter()
        .find(|r| *r as u64 == n)
    }
}

/// One member of a shared locker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    /// Member.
    pub member: Id16,
    /// Role.
    pub role: Role,
    /// Active devices.
    pub devices: u64,
    /// Fingerprint of the member key.
    pub fingerprint: String,
    /// Whether its admission carries a verified transparency proof.
    pub proven: bool,
    /// Roles the current member may change this member's role to.
    pub change_to: Vec<Role>,
    /// Why `change_to` is empty, when it is.
    pub change_refusal: Option<Refusal>,
    /// Why the current member may not remove this member, if so.
    pub remove_refusal: Option<Refusal>,
    /// Display name the member gave itself, verified against the key log (ADR 0069).
    pub name: Option<String>,
    /// Whether the user compared this fingerprint out of band.
    pub verified: bool,
}

/// One member found in the directory (ADR 0069). The name is what the holder of the key
/// calls itself: the fingerprint stays the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundInfo {
    /// Member.
    pub member: Id16,
    /// Display name, verified against the key log.
    pub name: String,
    /// Fingerprint of the member key.
    pub fingerprint: String,
    /// Whether the user compared this fingerprint out of band.
    pub verified: bool,
}

/// A server mode reply. Holds no secret: names of lockers are in erasing buffers.
#[derive(Clone, PartialEq, Eq)]
pub enum ServerReply {
    /// No result.
    Done,
    /// 40.
    Status {
        /// Joined server: address, identifier, fingerprint, verified.
        server: Option<(String, Id16, String, bool)>,
        /// Shared lockers.
        lockers: Vec<LockerStatus>,
        /// End of the last successful synchronisation since the vault was opened, wall clock
        /// milliseconds.
        last_sync_ms: Option<u64>,
        /// The local key log (present when joined).
        keylog: Option<KeyLogStatus>,
    },
    /// 41.
    Identity {
        /// Encoded `MemberKeys`.
        member_keys: Vec<u8>,
        /// Member fingerprint.
        fingerprint: String,
        /// Device.
        device: Id16,
        /// Control code of the device.
        control_code: String,
        /// Current display name of the member, if it has one (ADR 0069).
        name: Option<String>,
    },
    /// 42.
    Joined {
        /// Server identifier.
        server_id: Id16,
        /// Server fingerprint.
        fingerprint: String,
        /// Whether it was verified.
        verified: bool,
        /// Whether the server accepted `Auth`.
        account: bool,
    },
    /// 43.
    Confirmed {
        /// Whether the server accepted `Auth`.
        account: bool,
    },
    /// 44.
    Synced(Vec<SyncReport>),
    /// 45.
    LockerCreated(Id16),
    /// 46.
    Granted {
        /// Member fingerprint.
        fingerprint: String,
        /// Devices that received an envelope or were admitted.
        devices: u64,
        /// Display name of the member, if known and verified here (ADR 0069).
        name: Option<String>,
    },
    /// 48.
    Members {
        /// The current member.
        me: Id16,
        /// Members holding a role.
        members: Vec<MemberInfo>,
        /// Roles the current member may grant to a new member.
        grantable: Vec<Role>,
        /// Why `grantable` is empty, when it is.
        grant_refusal: Option<Refusal>,
        /// Quorum of owners in force (ADR 0044), once the state is known.
        quorum: Option<u64>,
    },
    /// 90, 93: a pending request.
    Request(QuorumState),
    /// 91.
    Inspected {
        /// Locker.
        locker: Id16,
        /// Its name, if readable here.
        name: Option<Zeroizing<String>>,
        /// Action.
        action: QuorumAction,
        /// Member targeted.
        target: Option<Id16>,
        /// Fingerprint of the target, if known here.
        target_fingerprint: Option<String>,
        /// New role or quorum.
        detail: Option<u64>,
        /// Initiator.
        issuer: Id16,
        /// Fingerprint of the initiator, if known here.
        issuer_fingerprint: Option<String>,
        /// Whether the current member may sign it.
        can_sign: bool,
        /// Display name of the target, if known and verified here (ADR 0069).
        target_name: Option<String>,
        /// Display name of the initiator, if known and verified here.
        issuer_name: Option<String>,
    },
    /// 92: the approval to hand back.
    Approved(String),
    /// 95.
    Requests(Vec<QuorumState>),
    /// 97.
    Quarantine {
        /// Quarantined operations.
        ops: Vec<QuarantinedOp>,
        /// Whether the current member may decide.
        can_decide: bool,
    },
    /// 49.
    DeviceRevoked {
        /// Lockers where the `DeviceRemove` was emitted.
        lockers: u64,
    },
    /// 121.
    Found {
        /// Members whose profile was verified against the key log.
        members: Vec<FoundInfo>,
        /// The server holds more matches than it returned.
        more: bool,
    },
}

/// Whether `frame` is a request of the server mode: its operation code (key 3) is in
/// [`SERVER_OPS`], [`GOVERNANCE_OPS`] or [`DIRECTORY_OPS`]. Anything else, readable or not, goes to the other decoders.
#[must_use]
pub fn is_server_request(frame: &[u8]) -> bool {
    let Ok(v) = cbor::decode(frame) else {
        return false;
    };
    let Ok(f) = Fields::new(&v, &[1, 2, 3, 4]) else {
        return false;
    };
    f.req(3).and_then(uint).is_ok_and(|op| {
        SERVER_OPS.contains(&op) || GOVERNANCE_OPS.contains(&op) || DIRECTORY_OPS.contains(&op)
    })
}

/// Normalises a typed fingerprint: spaces and dashes removed, upper case; then exactly 20
/// characters of the RFC 4648 base32 alphabet.
#[must_use]
pub fn normalise_fingerprint(typed: &str) -> Option<String> {
    if typed.len() > MAX_TYPED_FINGERPRINT {
        return None;
    }
    let s: String = typed
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let ok = s.len() == FINGERPRINT_LEN
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b));
    ok.then_some(s)
}

fn m<T>(r: Result<T, cbor::CborError>) -> Result<T, ServerCode> {
    r.map_err(|_| ServerCode::General(ErrorCode::Malformed))
}

fn fingerprint_arg(v: &Value) -> Result<String, ServerCode> {
    normalise_fingerprint(m(text_max(v, MAX_TYPED_FINGERPRINT))?)
        .ok_or(ServerCode::General(ErrorCode::InvalidInput))
}

fn role_arg(v: &Value) -> Result<Role, ServerCode> {
    Role::from_code(m(uint(v))?).ok_or(ServerCode::General(ErrorCode::InvalidInput))
}

impl ServerRequest {
    /// Its operation.
    #[must_use]
    pub fn op(&self) -> ServerOp {
        match self {
            ServerRequest::ServerStatus => ServerOp::ServerStatus,
            ServerRequest::ServerIdentity => ServerOp::ServerIdentity,
            ServerRequest::ServerJoin { .. } | ServerRequest::ServerJoinLink { .. } => {
                ServerOp::ServerJoin
            }
            ServerRequest::ServerConfirm { .. } => ServerOp::ServerConfirm,
            ServerRequest::ServerSync => ServerOp::ServerSync,
            ServerRequest::SharedLockerCreate { .. } => ServerOp::SharedLockerCreate,
            ServerRequest::RoleGrant { .. } => ServerOp::RoleGrant,
            ServerRequest::RoleRevoke { .. } => ServerOp::RoleRevoke,
            ServerRequest::LockerMembers { .. } => ServerOp::LockerMembers,
            ServerRequest::DeviceRevoke { .. } => ServerOp::DeviceRevoke,
            ServerRequest::QuorumPrepare { .. } => ServerOp::QuorumPrepare,
            ServerRequest::QuorumInspect { .. } => ServerOp::QuorumInspect,
            ServerRequest::QuorumApprove { .. } => ServerOp::QuorumApprove,
            ServerRequest::QuorumCollect { .. } => ServerOp::QuorumCollect,
            ServerRequest::QuorumApply { .. } => ServerOp::QuorumApply,
            ServerRequest::QuorumList { .. } => ServerOp::QuorumList,
            ServerRequest::QuorumCancel { .. } => ServerOp::QuorumCancel,
            ServerRequest::QuarantineList { .. } => ServerOp::QuarantineList,
            ServerRequest::QuarantineDecide { .. } => ServerOp::QuarantineDecide,
            ServerRequest::ProfileSet { .. } => ServerOp::ProfileSet,
            ServerRequest::MemberSearch { .. } => ServerOp::MemberSearch,
            ServerRequest::MemberVerify { .. } => ServerOp::MemberVerify,
        }
    }

    fn args(&self) -> Option<Value> {
        match self {
            ServerRequest::ServerStatus
            | ServerRequest::ServerIdentity
            | ServerRequest::ServerSync => None,
            ServerRequest::ServerJoin {
                url,
                roots,
                fingerprint,
            } => {
                let mut e = vec![(1, Value::text(url)), (2, Value::bytes(roots))];
                if let Some(f) = fingerprint {
                    e.push((3, Value::text(f)));
                }
                Some(Value::map(e))
            }
            ServerRequest::ServerJoinLink { link } => {
                Some(Value::map(vec![(4, Value::text(link))]))
            }
            ServerRequest::ServerConfirm { fingerprint } => {
                Some(Value::map(vec![(1, Value::text(fingerprint))]))
            }
            ServerRequest::SharedLockerCreate { name } => {
                Some(Value::map(vec![(1, Value::text(name))]))
            }
            ServerRequest::RoleGrant {
                locker,
                member,
                role,
                fingerprint,
            } => {
                let mut e = vec![
                    (1, Value::bytes(locker)),
                    (2, Value::bytes(member)),
                    (3, Value::Uint(role.code())),
                ];
                if let Some(f) = fingerprint {
                    e.push((4, Value::text(f)));
                }
                Some(Value::map(e))
            }
            ServerRequest::RoleRevoke { locker, member } => Some(Value::map(vec![
                (1, Value::bytes(locker)),
                (2, Value::bytes(member)),
            ])),
            ServerRequest::LockerMembers { locker } | ServerRequest::QuarantineList { locker } => {
                Some(Value::map(vec![(1, Value::bytes(locker))]))
            }
            ServerRequest::DeviceRevoke { device } => {
                Some(Value::map(vec![(1, Value::bytes(device))]))
            }
            ServerRequest::QuorumPrepare {
                locker,
                action,
                target,
                detail,
            } => {
                let mut e = vec![(1, Value::bytes(locker)), (2, Value::Uint(*action as u64))];
                if let Some(t) = target {
                    e.push((3, Value::bytes(t)));
                }
                if let Some(d) = detail {
                    e.push((4, Value::Uint(*d)));
                }
                Some(Value::map(e))
            }
            ServerRequest::QuorumInspect { offer } | ServerRequest::QuorumApprove { offer } => {
                Some(Value::map(vec![(1, Value::text(offer))]))
            }
            ServerRequest::QuorumCollect { token } => {
                Some(Value::map(vec![(1, Value::text(token))]))
            }
            ServerRequest::QuorumApply { request } | ServerRequest::QuorumCancel { request } => {
                Some(Value::map(vec![(1, Value::bytes(request))]))
            }
            ServerRequest::QuorumList { locker } => Some(Value::map(
                locker.iter().map(|l| (1, Value::bytes(l))).collect(),
            )),
            ServerRequest::QuarantineDecide {
                locker,
                ops,
                accept,
            } => Some(Value::map(vec![
                (1, Value::bytes(locker)),
                (
                    2,
                    Value::Array(ops.iter().map(|o| Value::bytes(o)).collect()),
                ),
                (3, Value::Bool(*accept)),
            ])),
            ServerRequest::ProfileSet { name } => Some(Value::map(vec![(1, Value::text(name))])),
            ServerRequest::MemberSearch { text } => Some(Value::map(vec![(1, Value::text(text))])),
            ServerRequest::MemberVerify {
                member,
                fingerprint,
            } => Some(Value::map(vec![
                (1, Value::bytes(member)),
                (2, Value::text(fingerprint)),
            ])),
        }
    }

    /// Encodes the request with identifier `id` (client side).
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(&self, id: u64) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![
            (1, Value::Uint(SERVER_VERSION)),
            (2, Value::Uint(id)),
            (3, Value::Uint(self.op() as u64)),
        ];
        if let Some(a) = self.args() {
            e.push((4, a));
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Strict decoding of a server mode request. Returns the identifier (0 if unreadable)
    /// with the code to answer on failure.
    ///
    /// # Errors
    /// `(id, code)`.
    pub fn decode(frame: &[u8]) -> Result<(u64, ServerRequest), (u64, ServerCode)> {
        let malformed = ServerCode::General(ErrorCode::Malformed);
        let v = cbor::decode(frame).map_err(|_| (0, malformed))?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(|_| (0, malformed))?;
        let id = f.req(2).and_then(uint).map_err(|_| (0, malformed))?;
        let version = f.req(1).and_then(uint).map_err(|_| (id, malformed))?;
        if version != SERVER_VERSION {
            return Err((id, ServerCode::General(ErrorCode::UnsupportedVersion)));
        }
        let op = f.req(3).and_then(uint).map_err(|_| (id, malformed))?;
        let op =
            ServerOp::from_u64(op).ok_or((id, ServerCode::General(ErrorCode::UnknownOperation)))?;
        Self::decode_args(op, f.opt(4))
            .map(|r| (id, r))
            .map_err(|c| (id, c))
    }

    fn decode_args(op: ServerOp, args: Option<&Value>) -> Result<ServerRequest, ServerCode> {
        let malformed = ServerCode::General(ErrorCode::Malformed);
        let none = |r: ServerRequest| match args {
            None => Ok(r),
            Some(_) => Err(malformed),
        };
        let args = || args.ok_or(malformed);
        let id16 = |f: &Fields<'_>, k| m(f.req(k).and_then(fixed::<16>));
        match op {
            ServerOp::ServerStatus => none(ServerRequest::ServerStatus),
            ServerOp::ServerIdentity => none(ServerRequest::ServerIdentity),
            ServerOp::ServerSync => none(ServerRequest::ServerSync),
            ServerOp::ServerJoin => {
                let f = m(Fields::new(args()?, &[1, 2, 3, 4]))?;
                if let Some(link) = f.opt(4) {
                    if f.opt(1).is_some() || f.opt(2).is_some() || f.opt(3).is_some() {
                        return Err(malformed);
                    }
                    return Ok(ServerRequest::ServerJoinLink {
                        link: m(text_max(link, MAX_TEXT))?.to_owned(),
                    });
                }
                Ok(ServerRequest::ServerJoin {
                    url: m(f.req(1).and_then(|u| text_max(u, MAX_SERVER_URL)))?.to_owned(),
                    roots: m(f.req(2).and_then(|r| bytes_max(r, MAX_ROOTS)))?.to_vec(),
                    fingerprint: f.opt(3).map(fingerprint_arg).transpose()?,
                })
            }
            ServerOp::ServerConfirm => {
                let f = m(Fields::new(args()?, &[1]))?;
                Ok(ServerRequest::ServerConfirm {
                    fingerprint: fingerprint_arg(m(f.req(1))?)?,
                })
            }
            ServerOp::SharedLockerCreate => {
                let f = m(Fields::new(args()?, &[1]))?;
                let name = m(f.req(1).and_then(|n| text_max(n, MAX_LOCKER_NAME)))?;
                if name.is_empty() {
                    return Err(ServerCode::General(ErrorCode::InvalidInput));
                }
                Ok(ServerRequest::SharedLockerCreate {
                    name: Zeroizing::new(name.to_owned()),
                })
            }
            ServerOp::RoleGrant => {
                let f = m(Fields::new(args()?, &[1, 2, 3, 4]))?;
                Ok(ServerRequest::RoleGrant {
                    locker: id16(&f, 1)?,
                    member: id16(&f, 2)?,
                    role: role_arg(m(f.req(3))?)?,
                    fingerprint: f.opt(4).map(fingerprint_arg).transpose()?,
                })
            }
            ServerOp::RoleRevoke => {
                let f = m(Fields::new(args()?, &[1, 2]))?;
                Ok(ServerRequest::RoleRevoke {
                    locker: id16(&f, 1)?,
                    member: id16(&f, 2)?,
                })
            }
            ServerOp::LockerMembers => {
                let f = m(Fields::new(args()?, &[1]))?;
                Ok(ServerRequest::LockerMembers {
                    locker: id16(&f, 1)?,
                })
            }
            ServerOp::QuarantineList => {
                let f = m(Fields::new(args()?, &[1]))?;
                Ok(ServerRequest::QuarantineList {
                    locker: id16(&f, 1)?,
                })
            }
            ServerOp::DeviceRevoke => {
                let f = m(Fields::new(args()?, &[1]))?;
                Ok(ServerRequest::DeviceRevoke {
                    device: id16(&f, 1)?,
                })
            }
            ServerOp::QuorumPrepare => {
                let f = m(Fields::new(args()?, &[1, 2, 3, 4]))?;
                Ok(ServerRequest::QuorumPrepare {
                    locker: id16(&f, 1)?,
                    action: QuorumAction::from_u64(m(f.req(2).and_then(uint))?)
                        .ok_or(ServerCode::General(ErrorCode::InvalidInput))?,
                    target: f
                        .opt(3)
                        .map(fixed::<16>)
                        .transpose()
                        .map_err(|_| malformed)?,
                    detail: f.opt(4).map(uint).transpose().map_err(|_| malformed)?,
                })
            }
            ServerOp::QuorumInspect | ServerOp::QuorumApprove | ServerOp::QuorumCollect => {
                let f = m(Fields::new(args()?, &[1]))?;
                let text = m(f.req(1).and_then(|t| text_max(t, MAX_TEXT)))?.to_owned();
                Ok(match op {
                    ServerOp::QuorumInspect => ServerRequest::QuorumInspect { offer: text },
                    ServerOp::QuorumApprove => ServerRequest::QuorumApprove { offer: text },
                    _ => ServerRequest::QuorumCollect { token: text },
                })
            }
            ServerOp::QuorumApply | ServerOp::QuorumCancel => {
                let f = m(Fields::new(args()?, &[1]))?;
                let request = id16(&f, 1)?;
                Ok(if op == ServerOp::QuorumApply {
                    ServerRequest::QuorumApply { request }
                } else {
                    ServerRequest::QuorumCancel { request }
                })
            }
            ServerOp::QuorumList => {
                let f = m(Fields::new(args()?, &[1]))?;
                Ok(ServerRequest::QuorumList {
                    locker: f
                        .opt(1)
                        .map(fixed::<16>)
                        .transpose()
                        .map_err(|_| malformed)?,
                })
            }
            ServerOp::QuarantineDecide => {
                let f = m(Fields::new(args()?, &[1, 2, 3]))?;
                let ops: Vec<OpId> = m(f.req(2).and_then(|a| array_max(a, MAX_LIST)))?
                    .iter()
                    .map(fixed::<48>)
                    .collect::<Result<_, _>>()
                    .map_err(|_| malformed)?;
                let mut sorted = ops.clone();
                sorted.sort_unstable();
                sorted.dedup();
                if ops.is_empty() || sorted.len() != ops.len() {
                    return Err(ServerCode::General(ErrorCode::InvalidInput));
                }
                Ok(ServerRequest::QuarantineDecide {
                    locker: id16(&f, 1)?,
                    ops: sorted,
                    accept: m(f.req(3).and_then(boolean))?,
                })
            }
            ServerOp::ProfileSet => {
                let f = m(Fields::new(args()?, &[1]))?;
                let name = m(f.req(1).and_then(|n| text_max(n, MAX_DISPLAY_NAME)))?;
                if !valid_display_name(name) {
                    return Err(ServerCode::General(ErrorCode::InvalidInput));
                }
                Ok(ServerRequest::ProfileSet {
                    name: name.to_owned(),
                })
            }
            ServerOp::MemberSearch => {
                let f = m(Fields::new(args()?, &[1]))?;
                let text = m(f.req(1).and_then(|n| text_max(n, MAX_DISPLAY_NAME)))?;
                if text.len() < MIN_SEARCH {
                    return Err(ServerCode::General(ErrorCode::InvalidInput));
                }
                Ok(ServerRequest::MemberSearch {
                    text: text.to_owned(),
                })
            }
            ServerOp::MemberVerify => {
                let f = m(Fields::new(args()?, &[1, 2]))?;
                Ok(ServerRequest::MemberVerify {
                    member: id16(&f, 1)?,
                    fingerprint: fingerprint_arg(m(f.req(2))?)?,
                })
            }
        }
    }
}

fn status_value(l: &LockerStatus) -> Value {
    let mut e = vec![(1, Value::bytes(&l.id))];
    if let Some(n) = &l.name {
        e.push((2, Value::text(n)));
    }
    if let Some(r) = l.role {
        e.push((3, Value::Uint(r.code())));
    }
    e.push((4, Value::Uint(l.cursor)));
    e.push((5, Value::Uint(l.unsent)));
    e.push((6, Value::Uint(l.pending)));
    e.push((7, Value::Uint(l.quarantined)));
    e.push((8, Value::Bool(l.access)));
    e.push((9, Value::Bool(l.frozen)));
    Value::map(e)
}

fn status_from(v: &Value) -> Result<LockerStatus, cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    Ok(LockerStatus {
        id: fixed::<16>(f.req(1)?)?,
        name: f
            .opt(2)
            .map(|n| text_max(n, MAX_LOCKER_NAME).map(|s| Zeroizing::new(s.to_owned())))
            .transpose()?,
        role: f
            .opt(3)
            .map(|r| uint(r).and_then(|c| Role::from_code(c).ok_or(cbor::CborError::Malformed)))
            .transpose()?,
        cursor: uint(f.req(4)?)?,
        unsent: uint(f.req(5)?)?,
        pending: uint(f.req(6)?)?,
        quarantined: uint(f.req(7)?)?,
        access: boolean(f.req(8)?)?,
        frozen: boolean(f.req(9)?)?,
    })
}

fn roles_value(roles: &[Role]) -> Value {
    Value::Array(roles.iter().map(|r| Value::Uint(r.code())).collect())
}

fn roles_from(v: &Value) -> Result<Vec<Role>, cbor::CborError> {
    array_max(v, 6)?
        .iter()
        .map(|r| uint(r).and_then(|c| Role::from_code(c).ok_or(cbor::CborError::Malformed)))
        .collect()
}

fn refusal_from(v: Option<&Value>) -> Result<Option<Refusal>, cbor::CborError> {
    v.map(|r| uint(r).and_then(|c| Refusal::from_u64(c).ok_or(cbor::CborError::Malformed)))
        .transpose()
}

fn member_value(mi: &MemberInfo) -> Value {
    let mut e = vec![
        (1, Value::bytes(&mi.member)),
        (2, Value::Uint(mi.role.code())),
        (3, Value::Uint(mi.devices)),
        (4, Value::text(&mi.fingerprint)),
        (5, Value::Bool(mi.proven)),
        (6, roles_value(&mi.change_to)),
    ];
    if let Some(r) = mi.change_refusal {
        e.push((7, Value::Uint(r as u64)));
    }
    if let Some(r) = mi.remove_refusal {
        e.push((8, Value::Uint(r as u64)));
    }
    opt_text(&mut e, 9, mi.name.as_deref());
    e.push((10, Value::Bool(mi.verified)));
    Value::map(e)
}

fn opt_text(e: &mut Vec<(u64, Value)>, k: u64, v: Option<&str>) {
    if let Some(v) = v {
        e.push((k, Value::text(v)));
    }
}

/// A display name in a reply: present only when the member has one, so never empty.
fn name_from(v: Option<&Value>) -> Result<Option<String>, cbor::CborError> {
    v.map(|n| {
        let n = text_max(n, MAX_DISPLAY_NAME)?;
        if n.is_empty() || !valid_display_name(n) {
            return Err(cbor::CborError::Malformed);
        }
        Ok(n.to_owned())
    })
    .transpose()
}

fn found_value(f: &FoundInfo) -> Value {
    Value::map(vec![
        (1, Value::bytes(&f.member)),
        (2, Value::text(&f.name)),
        (3, Value::text(&f.fingerprint)),
        (4, Value::Bool(f.verified)),
    ])
}

fn found_from(v: &Value) -> Result<FoundInfo, cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3, 4])?;
    Ok(FoundInfo {
        member: fixed::<16>(f.req(1)?)?,
        name: name_from(Some(f.req(2)?))?.ok_or(cbor::CborError::Malformed)?,
        fingerprint: text_max(f.req(3)?, FINGERPRINT_LEN)?.to_owned(),
        verified: boolean(f.req(4)?)?,
    })
}

fn member_from(v: &Value) -> Result<MemberInfo, cbor::CborError> {
    let i = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
    Ok(MemberInfo {
        member: fixed::<16>(i.req(1)?)?,
        role: Role::from_code(uint(i.req(2)?)?).ok_or(cbor::CborError::Malformed)?,
        devices: uint(i.req(3)?)?,
        fingerprint: text_max(i.req(4)?, FINGERPRINT_LEN)?.to_owned(),
        proven: boolean(i.req(5)?)?,
        change_to: roles_from(i.req(6)?)?,
        change_refusal: refusal_from(i.opt(7))?,
        remove_refusal: refusal_from(i.opt(8))?,
        name: name_from(i.opt(9))?,
        verified: boolean(i.req(10)?)?,
    })
}

fn keylog_value(k: &KeyLogStatus) -> Value {
    let mut e = vec![
        (1, Value::Bool(k.suspect.is_some())),
        (2, Value::Uint(k.entries)),
    ];
    if let Some(r) = k.suspect {
        e.push((3, Value::Uint(r as u64)));
    }
    e.push((
        4,
        Value::Array(
            k.alerts
                .iter()
                .map(|a| {
                    let mut f = vec![(1, Value::Uint(a.kind as u64))];
                    if let Some(i) = a.index {
                        f.push((2, Value::Uint(i)));
                    }
                    if let Some(d) = &a.device {
                        f.push((3, Value::bytes(d)));
                    }
                    if let Some(l) = &a.locker {
                        f.push((4, Value::bytes(l)));
                    }
                    Value::map(f)
                })
                .collect(),
        ),
    ));
    Value::map(e)
}

fn keylog_from(v: &Value) -> Result<KeyLogStatus, cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3, 4])?;
    let suspect = boolean(f.req(1)?)?;
    let reason = f
        .opt(3)
        .map(|r| uint(r).and_then(|c| SuspectReason::from_u64(c).ok_or(cbor::CborError::Malformed)))
        .transpose()?;
    if suspect != reason.is_some() {
        return Err(cbor::CborError::Malformed);
    }
    let mut alerts = Vec::new();
    for a in array_max(f.req(4)?, MAX_ALERTS)? {
        let g = Fields::new(a, &[1, 2, 3, 4])?;
        let kind = AlertKind::from_u64(uint(g.req(1)?)?).ok_or(cbor::CborError::Malformed)?;
        let index = g.opt(2).map(uint).transpose()?;
        let device = g.opt(3).map(fixed::<16>).transpose()?;
        let locker = g.opt(4).map(fixed::<16>).transpose()?;
        if index.is_some() != kind.has_index()
            || device.is_some() != kind.has_device()
            || locker.is_some() != kind.has_locker()
        {
            return Err(cbor::CborError::Malformed);
        }
        alerts.push(KeyLogAlert {
            kind,
            index,
            device,
            locker,
        });
    }
    Ok(KeyLogStatus {
        suspect: reason,
        entries: uint(f.req(2)?)?,
        alerts,
    })
}

fn opt_id(e: &mut Vec<(u64, Value)>, k: u64, v: Option<&Id16>) {
    if let Some(v) = v {
        e.push((k, Value::bytes(v)));
    }
}

fn opt_uint(e: &mut Vec<(u64, Value)>, k: u64, v: Option<u64>) {
    if let Some(v) = v {
        e.push((k, Value::Uint(v)));
    }
}

fn quorum_value(q: &QuorumState) -> Value {
    let mut e = vec![
        (1, Value::bytes(&q.request)),
        (2, Value::bytes(&q.locker)),
        (3, Value::Uint(q.action as u64)),
    ];
    opt_id(&mut e, 4, q.target.as_ref());
    opt_uint(&mut e, 5, q.detail);
    e.push((
        6,
        Value::Array(q.counted.iter().map(|m| Value::bytes(m)).collect()),
    ));
    e.push((7, Value::Uint(q.required)));
    e.push((8, Value::text(&q.offer)));
    e.push((9, Value::Uint(q.created_ms)));
    Value::map(e)
}

fn action_from(v: &Value) -> Result<QuorumAction, cbor::CborError> {
    QuorumAction::from_u64(uint(v)?).ok_or(cbor::CborError::Malformed)
}

fn quorum_from(v: &Value) -> Result<QuorumState, cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    Ok(QuorumState {
        request: fixed::<16>(f.req(1)?)?,
        locker: fixed::<16>(f.req(2)?)?,
        action: action_from(f.req(3)?)?,
        target: f.opt(4).map(fixed::<16>).transpose()?,
        detail: f.opt(5).map(uint).transpose()?,
        counted: array_max(f.req(6)?, 16)?
            .iter()
            .map(fixed::<16>)
            .collect::<Result<_, _>>()?,
        required: uint(f.req(7)?)?,
        offer: text_max(f.req(8)?, MAX_TEXT)?.to_owned(),
        created_ms: uint(f.req(9)?)?,
    })
}

fn quarantined_value(q: &QuarantinedOp) -> Value {
    let mut e = vec![
        (1, Value::bytes(&q.op_id)),
        (2, Value::bytes(&q.member)),
        (3, Value::bytes(&q.device)),
        (4, Value::Uint(q.cause)),
        (5, Value::Uint(q.class)),
    ];
    opt_uint(&mut e, 6, q.wall_ms);
    if let Some(t) = &q.title {
        e.push((7, Value::text(t)));
    }
    opt_id(&mut e, 8, q.secret.as_ref());
    e.push((9, Value::Uint(q.received_ms)));
    e.push((10, Value::Uint(q.due_ms)));
    Value::map(e)
}

fn quarantined_from(v: &Value) -> Result<QuarantinedOp, cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
    Ok(QuarantinedOp {
        op_id: fixed::<48>(f.req(1)?)?,
        member: fixed::<16>(f.req(2)?)?,
        device: fixed::<16>(f.req(3)?)?,
        cause: cbor::uint_in(f.req(4)?, 1..=2)?,
        class: cbor::uint_in(f.req(5)?, 1..=2)?,
        wall_ms: f.opt(6).map(uint).transpose()?,
        title: f
            .opt(7)
            .map(|t| text_max(t, 4096).map(|s| Zeroizing::new(s.to_owned())))
            .transpose()?,
        secret: f.opt(8).map(fixed::<16>).transpose()?,
        received_ms: uint(f.req(9)?)?,
        due_ms: uint(f.req(10)?)?,
    })
}

impl ServerReply {
    fn body(&self) -> Option<Value> {
        match self {
            ServerReply::Done => None,
            ServerReply::Status {
                server,
                lockers,
                last_sync_ms,
                keylog,
            } => {
                let mut e = vec![(1, Value::Bool(server.is_some()))];
                if let Some((url, id, fp, verified)) = server {
                    e.push((2, Value::text(url)));
                    e.push((3, Value::bytes(id)));
                    e.push((4, Value::text(fp)));
                    e.push((5, Value::Bool(*verified)));
                }
                e.push((6, Value::Array(lockers.iter().map(status_value).collect())));
                if let Some(t) = last_sync_ms {
                    e.push((7, Value::Uint(*t)));
                }
                if let Some(k) = keylog {
                    e.push((8, keylog_value(k)));
                }
                Some(Value::map(e))
            }
            ServerReply::Identity {
                member_keys,
                fingerprint,
                device,
                control_code,
                name,
            } => {
                let mut e = vec![
                    (1, Value::bytes(member_keys)),
                    (2, Value::text(fingerprint)),
                    (3, Value::bytes(device)),
                    (4, Value::text(control_code)),
                ];
                opt_text(&mut e, 5, name.as_deref());
                Some(Value::map(e))
            }
            ServerReply::Joined {
                server_id,
                fingerprint,
                verified,
                account,
            } => Some(Value::map(vec![
                (1, Value::bytes(server_id)),
                (2, Value::text(fingerprint)),
                (3, Value::Bool(*verified)),
                (4, Value::Bool(*account)),
            ])),
            ServerReply::Confirmed { account } => {
                Some(Value::map(vec![(1, Value::Bool(*account))]))
            }
            ServerReply::Synced(items) => Some(Value::map(vec![(
                1,
                Value::Array(
                    items
                        .iter()
                        .map(|r| {
                            Value::map(vec![
                                (1, Value::bytes(&r.locker)),
                                (2, Value::Uint(r.received)),
                                (3, Value::Uint(r.sent)),
                                (4, Value::Uint(r.refused)),
                                (5, Value::Bool(r.access)),
                            ])
                        })
                        .collect(),
                ),
            )])),
            ServerReply::LockerCreated(id) => Some(Value::map(vec![(1, Value::bytes(id))])),
            ServerReply::DeviceRevoked { lockers } => {
                Some(Value::map(vec![(1, Value::Uint(*lockers))]))
            }
            ServerReply::Granted {
                fingerprint,
                devices,
                name,
            } => {
                let mut e = vec![(1, Value::text(fingerprint)), (2, Value::Uint(*devices))];
                opt_text(&mut e, 3, name.as_deref());
                Some(Value::map(e))
            }
            ServerReply::Found { members, more } => Some(Value::map(vec![
                (1, Value::Array(members.iter().map(found_value).collect())),
                (2, Value::Bool(*more)),
            ])),
            ServerReply::Members {
                me,
                members,
                grantable,
                grant_refusal,
                quorum,
            } => {
                let mut e = vec![
                    (1, Value::Array(members.iter().map(member_value).collect())),
                    (2, Value::bytes(me)),
                    (3, roles_value(grantable)),
                ];
                if let Some(r) = grant_refusal {
                    e.push((4, Value::Uint(*r as u64)));
                }
                opt_uint(&mut e, 5, *quorum);
                Some(Value::map(e))
            }
            ServerReply::Request(q) => Some(quorum_value(q)),
            ServerReply::Requests(list) => Some(Value::map(vec![(
                1,
                Value::Array(list.iter().map(quorum_value).collect()),
            )])),
            ServerReply::Inspected {
                locker,
                name,
                action,
                target,
                target_fingerprint,
                detail,
                issuer,
                issuer_fingerprint,
                can_sign,
                target_name,
                issuer_name,
            } => {
                let mut e = vec![(1, Value::bytes(locker))];
                if let Some(n) = name {
                    e.push((2, Value::text(n)));
                }
                e.push((3, Value::Uint(*action as u64)));
                opt_id(&mut e, 4, target.as_ref());
                if let Some(f) = target_fingerprint {
                    e.push((5, Value::text(f)));
                }
                opt_uint(&mut e, 6, *detail);
                e.push((7, Value::bytes(issuer)));
                if let Some(f) = issuer_fingerprint {
                    e.push((8, Value::text(f)));
                }
                e.push((9, Value::Bool(*can_sign)));
                opt_text(&mut e, 10, target_name.as_deref());
                opt_text(&mut e, 11, issuer_name.as_deref());
                Some(Value::map(e))
            }
            ServerReply::Approved(token) => Some(Value::map(vec![(1, Value::text(token))])),
            ServerReply::Quarantine { ops, can_decide } => Some(Value::map(vec![
                (1, Value::Array(ops.iter().map(quarantined_value).collect())),
                (2, Value::Bool(*can_decide)),
            ])),
        }
    }

    /// Encodes a reply (success or refusal) to request `id`.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(
        id: u64,
        result: &Result<ServerReply, ServerCode>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![(1, Value::Uint(SERVER_VERSION)), (2, Value::Uint(id))];
        match result {
            Ok(r) => {
                e.push((3, Value::Uint(0)));
                if let Some(b) = r.body() {
                    e.push((4, b));
                }
            }
            Err(c) => {
                e.push((3, Value::Uint(c.status())));
                match c {
                    ServerCode::ServerRefused(code) => {
                        e.push((4, Value::map(vec![(1, Value::Uint(*code))])));
                    }
                    ServerCode::QuorumNotMet(counted, required) => {
                        e.push((
                            4,
                            Value::map(vec![
                                (1, Value::Uint(*counted)),
                                (2, Value::Uint(*required)),
                            ]),
                        ));
                    }
                    ServerCode::General(ErrorCode::UnsupportedVersion) => {
                        e.push((
                            4,
                            Value::map(vec![(2, Value::Array(vec![Value::Uint(SERVER_VERSION)]))]),
                        ));
                    }
                    _ => {}
                }
            }
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Decodes the reply to a server mode request of operation `op` (client side).
    ///
    /// # Errors
    /// [`ErrorCode::Malformed`].
    pub fn decode(
        op: ServerOp,
        frame: &[u8],
    ) -> Result<(u64, Result<ServerReply, ServerCode>), ErrorCode> {
        let bad = |_| ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(bad)?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(bad)?;
        let id = f.req(2).and_then(uint).map_err(bad)?;
        let status = f.req(3).and_then(uint).map_err(bad)?;
        let body = f.opt(4);
        let version = f.req(1).and_then(uint).map_err(bad)?;
        // A refusal of the connection itself (identifier 0) may carry another version.
        if version != SERVER_VERSION && !(id == 0 && status != 0) {
            return Err(ErrorCode::Malformed);
        }
        if status != 0 {
            let code = match status {
                40 => ServerCode::NotJoined,
                41 => ServerCode::AlreadyJoined,
                42 => ServerCode::ServerUnverified,
                43 => ServerCode::FingerprintMismatch,
                44 => ServerCode::ServerUnreachable,
                45 => {
                    let d = Fields::new(body.ok_or(ErrorCode::Malformed)?, &[1]).map_err(bad)?;
                    ServerCode::ServerRefused(d.req(1).and_then(uint).map_err(bad)?)
                }
                46 => ServerCode::Forbidden,
                47 => ServerCode::UnknownMember,
                48 => ServerCode::KeyLogRejected,
                49 => ServerCode::AlreadyRevoked,
                90 => ServerCode::ApprovalInvalid,
                91 => {
                    let d = Fields::new(body.ok_or(ErrorCode::Malformed)?, &[1, 2]).map_err(bad)?;
                    ServerCode::QuorumNotMet(
                        d.req(1).and_then(uint).map_err(bad)?,
                        d.req(2).and_then(uint).map_err(bad)?,
                    )
                }
                92 => ServerCode::LockerFrozen,
                93 => ServerCode::InvitationInvalid,
                n => ServerCode::General(ErrorCode::from_u64(n).ok_or(ErrorCode::Malformed)?),
            };
            return Ok((id, Err(code)));
        }
        let body = || body.ok_or(ErrorCode::Malformed);
        let text = |v: &Value, max| text_max(v, max).map(str::to_owned).map_err(bad);
        let reply = match op {
            ServerOp::RoleRevoke
            | ServerOp::QuorumApply
            | ServerOp::QuorumCancel
            | ServerOp::QuarantineDecide
            | ServerOp::ProfileSet
            | ServerOp::MemberVerify => {
                if f.opt(4).is_some() {
                    return Err(ErrorCode::Malformed);
                }
                ServerReply::Done
            }
            ServerOp::ServerStatus => {
                let b = Fields::new(body()?, &[1, 2, 3, 4, 5, 6, 7, 8]).map_err(bad)?;
                let joined = b.req(1).and_then(boolean).map_err(bad)?;
                let keylog = b.opt(8).map(keylog_from).transpose().map_err(bad)?;
                if keylog.is_some() != joined {
                    return Err(ErrorCode::Malformed);
                }
                let server = if joined {
                    Some((
                        text(b.req(2).map_err(bad)?, MAX_SERVER_URL)?,
                        b.req(3).and_then(fixed::<16>).map_err(bad)?,
                        text(b.req(4).map_err(bad)?, FINGERPRINT_LEN)?,
                        b.req(5).and_then(boolean).map_err(bad)?,
                    ))
                } else {
                    None
                };
                ServerReply::Status {
                    server,
                    lockers: b
                        .req(6)
                        .and_then(|l| array_max(l, MAX_LIST))
                        .map_err(bad)?
                        .iter()
                        .map(status_from)
                        .collect::<Result<_, _>>()
                        .map_err(bad)?,
                    last_sync_ms: b.opt(7).map(uint).transpose().map_err(bad)?,
                    keylog,
                }
            }
            ServerOp::ServerIdentity => {
                let b = Fields::new(body()?, &[1, 2, 3, 4, 5]).map_err(bad)?;
                ServerReply::Identity {
                    member_keys: b
                        .req(1)
                        .and_then(|x| bytes_max(x, MAX_MEMBER_KEYS))
                        .map_err(bad)?
                        .to_vec(),
                    fingerprint: text(b.req(2).map_err(bad)?, FINGERPRINT_LEN)?,
                    device: b.req(3).and_then(fixed::<16>).map_err(bad)?,
                    control_code: text(b.req(4).map_err(bad)?, 64)?,
                    name: name_from(b.opt(5)).map_err(bad)?,
                }
            }
            ServerOp::ServerJoin => {
                let b = Fields::new(body()?, &[1, 2, 3, 4]).map_err(bad)?;
                ServerReply::Joined {
                    server_id: b.req(1).and_then(fixed::<16>).map_err(bad)?,
                    fingerprint: text(b.req(2).map_err(bad)?, FINGERPRINT_LEN)?,
                    verified: b.req(3).and_then(boolean).map_err(bad)?,
                    account: b.req(4).and_then(boolean).map_err(bad)?,
                }
            }
            ServerOp::ServerConfirm => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                ServerReply::Confirmed {
                    account: b.req(1).and_then(boolean).map_err(bad)?,
                }
            }
            ServerOp::ServerSync => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                let mut out = Vec::new();
                for it in b.req(1).and_then(|x| array_max(x, MAX_LIST)).map_err(bad)? {
                    let i = Fields::new(it, &[1, 2, 3, 4, 5]).map_err(bad)?;
                    out.push(SyncReport {
                        locker: i.req(1).and_then(fixed::<16>).map_err(bad)?,
                        received: i.req(2).and_then(uint).map_err(bad)?,
                        sent: i.req(3).and_then(uint).map_err(bad)?,
                        refused: i.req(4).and_then(uint).map_err(bad)?,
                        access: i.req(5).and_then(boolean).map_err(bad)?,
                    });
                }
                ServerReply::Synced(out)
            }
            ServerOp::SharedLockerCreate => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                ServerReply::LockerCreated(b.req(1).and_then(fixed::<16>).map_err(bad)?)
            }
            ServerOp::DeviceRevoke => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                ServerReply::DeviceRevoked {
                    lockers: b.req(1).and_then(uint).map_err(bad)?,
                }
            }
            ServerOp::RoleGrant => {
                let b = Fields::new(body()?, &[1, 2, 3]).map_err(bad)?;
                ServerReply::Granted {
                    fingerprint: text(b.req(1).map_err(bad)?, FINGERPRINT_LEN)?,
                    devices: b.req(2).and_then(uint).map_err(bad)?,
                    name: name_from(b.opt(3)).map_err(bad)?,
                }
            }
            ServerOp::MemberSearch => {
                let b = Fields::new(body()?, &[1, 2]).map_err(bad)?;
                ServerReply::Found {
                    members: b
                        .req(1)
                        .and_then(|x| array_max(x, MAX_FOUND))
                        .map_err(bad)?
                        .iter()
                        .map(found_from)
                        .collect::<Result<_, _>>()
                        .map_err(bad)?,
                    more: b.req(2).and_then(boolean).map_err(bad)?,
                }
            }
            ServerOp::QuorumPrepare | ServerOp::QuorumCollect => {
                ServerReply::Request(quorum_from(body()?).map_err(bad)?)
            }
            ServerOp::QuorumList => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                ServerReply::Requests(
                    b.req(1)
                        .and_then(|x| array_max(x, MAX_REQUESTS))
                        .map_err(bad)?
                        .iter()
                        .map(quorum_from)
                        .collect::<Result<_, _>>()
                        .map_err(bad)?,
                )
            }
            ServerOp::QuorumInspect => {
                let b = Fields::new(body()?, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]).map_err(bad)?;
                ServerReply::Inspected {
                    locker: b.req(1).and_then(fixed::<16>).map_err(bad)?,
                    name: b
                        .opt(2)
                        .map(|n| text_max(n, MAX_LOCKER_NAME).map(|s| Zeroizing::new(s.to_owned())))
                        .transpose()
                        .map_err(bad)?,
                    action: b.req(3).and_then(action_from).map_err(bad)?,
                    target: b.opt(4).map(fixed::<16>).transpose().map_err(bad)?,
                    target_fingerprint: b.opt(5).map(|f| text(f, FINGERPRINT_LEN)).transpose()?,
                    detail: b.opt(6).map(uint).transpose().map_err(bad)?,
                    issuer: b.req(7).and_then(fixed::<16>).map_err(bad)?,
                    issuer_fingerprint: b.opt(8).map(|f| text(f, FINGERPRINT_LEN)).transpose()?,
                    can_sign: b.req(9).and_then(boolean).map_err(bad)?,
                    target_name: name_from(b.opt(10)).map_err(bad)?,
                    issuer_name: name_from(b.opt(11)).map_err(bad)?,
                }
            }
            ServerOp::QuorumApprove => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                ServerReply::Approved(text(b.req(1).map_err(bad)?, MAX_TEXT)?)
            }
            ServerOp::QuarantineList => {
                let b = Fields::new(body()?, &[1, 2]).map_err(bad)?;
                ServerReply::Quarantine {
                    ops: b
                        .req(1)
                        .and_then(|x| array_max(x, MAX_LIST))
                        .map_err(bad)?
                        .iter()
                        .map(quarantined_from)
                        .collect::<Result<_, _>>()
                        .map_err(bad)?,
                    can_decide: b.req(2).and_then(boolean).map_err(bad)?,
                }
            }
            ServerOp::LockerMembers => {
                let b = Fields::new(body()?, &[1, 2, 3, 4, 5]).map_err(bad)?;
                ServerReply::Members {
                    members: b
                        .req(1)
                        .and_then(|x| array_max(x, MAX_LIST))
                        .map_err(bad)?
                        .iter()
                        .map(member_from)
                        .collect::<Result<_, _>>()
                        .map_err(bad)?,
                    me: b.req(2).and_then(fixed::<16>).map_err(bad)?,
                    grantable: b.req(3).and_then(roles_from).map_err(bad)?,
                    grant_refusal: refusal_from(b.opt(4)).map_err(bad)?,
                    quorum: b.opt(5).map(uint).transpose().map_err(bad)?,
                }
            }
        };
        Ok((id, Ok(reply)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn round(r: &ServerRequest) -> ServerRequest {
        let f = r.encode(7).unwrap();
        assert!(is_server_request(&f));
        let (id, back) = ServerRequest::decode(&f).unwrap();
        assert_eq!(id, 7);
        back
    }

    #[test]
    fn requests_round_trip() {
        let all = [
            ServerRequest::ServerStatus,
            ServerRequest::ServerIdentity,
            ServerRequest::ServerJoin {
                url: "hirzla://h:7443".into(),
                roots: b"pem".to_vec(),
                fingerprint: Some("ABCDEFGHIJKLMNOPQRST".into()),
            },
            ServerRequest::ServerConfirm {
                fingerprint: "ABCDEFGHIJKLMNOPQRS2".into(),
            },
            ServerRequest::ServerSync,
            ServerRequest::SharedLockerCreate {
                name: Zeroizing::new("Équipe".into()),
            },
            ServerRequest::RoleGrant {
                locker: [1; 16],
                member: [2; 16],
                role: Role::Editor,
                fingerprint: None,
            },
            ServerRequest::RoleRevoke {
                locker: [1; 16],
                member: [2; 16],
            },
            ServerRequest::LockerMembers { locker: [3; 16] },
            ServerRequest::DeviceRevoke { device: [4; 16] },
            ServerRequest::ServerJoinLink {
                link: "hirzla-invitation:AAAA".into(),
            },
            ServerRequest::QuorumPrepare {
                locker: [1; 16],
                action: QuorumAction::OwnerRemoval,
                target: Some([2; 16]),
                detail: None,
            },
            ServerRequest::QuorumInspect {
                offer: "hirzla-demande:x".into(),
            },
            ServerRequest::QuorumApprove {
                offer: "hirzla-demande:x".into(),
            },
            ServerRequest::QuorumCollect {
                token: "hirzla-accord:x".into(),
            },
            ServerRequest::QuorumApply { request: [5; 16] },
            ServerRequest::QuorumList { locker: None },
            ServerRequest::QuorumList {
                locker: Some([1; 16]),
            },
            ServerRequest::QuorumCancel { request: [5; 16] },
            ServerRequest::QuarantineList { locker: [1; 16] },
            ServerRequest::QuarantineDecide {
                locker: [1; 16],
                ops: vec![[1; 48], [2; 48]],
                accept: true,
            },
            ServerRequest::ProfileSet {
                name: "Marie Durand".into(),
            },
            ServerRequest::ProfileSet {
                name: String::new(),
            },
            ServerRequest::MemberSearch { text: "dur".into() },
            ServerRequest::MemberVerify {
                member: [2; 16],
                fingerprint: "ABCDEFGHIJKLMNOPQRST".into(),
            },
        ];
        for r in &all {
            assert_eq!(&round(r), r);
        }
    }

    #[test]
    fn wrong_version_unknown_op_and_bad_args_are_refused() {
        let enc = |v: u64, op: u64, args: Option<Value>| {
            let mut e = vec![
                (1, Value::Uint(v)),
                (2, Value::Uint(3)),
                (3, Value::Uint(op)),
            ];
            if let Some(a) = args {
                e.push((4, a));
            }
            cbor::encode(&Value::map(e)).unwrap()
        };
        assert_eq!(
            ServerRequest::decode(&enc(1, 40, None)).unwrap_err(),
            (3, ServerCode::General(ErrorCode::UnsupportedVersion))
        );
        // 49 is `DeviceRevoke` (ADR 0059): without its arguments, malformed.
        assert_eq!(
            ServerRequest::decode(&enc(4, 49, None)).unwrap_err(),
            (3, ServerCode::General(ErrorCode::Malformed))
        );
        // Arguments on an operation without any.
        assert_eq!(
            ServerRequest::decode(&enc(4, 44, Some(Value::map(vec![])))).unwrap_err(),
            (3, ServerCode::General(ErrorCode::Malformed))
        );
        // Unknown role, bad fingerprint, empty name.
        let grant = Value::map(vec![
            (1, Value::bytes(&[1; 16])),
            (2, Value::bytes(&[2; 16])),
            (3, Value::Uint(9)),
        ]);
        assert_eq!(
            ServerRequest::decode(&enc(4, 46, Some(grant)))
                .unwrap_err()
                .1,
            ServerCode::General(ErrorCode::InvalidInput)
        );
        let confirm = Value::map(vec![(1, Value::text("ABC1"))]);
        assert_eq!(
            ServerRequest::decode(&enc(4, 43, Some(confirm)))
                .unwrap_err()
                .1,
            ServerCode::General(ErrorCode::InvalidInput)
        );
        let create = Value::map(vec![(1, Value::text(""))]);
        assert_eq!(
            ServerRequest::decode(&enc(4, 45, Some(create)))
                .unwrap_err()
                .1,
            ServerCode::General(ErrorCode::InvalidInput)
        );
        assert_eq!(
            ServerRequest::decode(&enc(4, 99, None)).unwrap_err(),
            (3, ServerCode::General(ErrorCode::UnknownOperation))
        );
        // A device revocation names exactly one device of 16 bytes (ADR 0059).
        for bad in [
            None,
            Some(Value::map(vec![(1, Value::bytes(&[1; 15]))])),
            Some(Value::map(vec![
                (1, Value::bytes(&[1; 16])),
                (2, Value::bytes(&[1; 16])),
            ])),
        ] {
            assert_eq!(
                ServerRequest::decode(&enc(4, 49, bad)).unwrap_err().1,
                ServerCode::General(ErrorCode::Malformed)
            );
        }
        // A link together with the separate fields; an empty or duplicated decision list; an
        // unknown action.
        let both = Value::map(vec![
            (1, Value::text("hirzla://h")),
            (4, Value::text("hirzla-invitation:x")),
        ]);
        assert_eq!(
            ServerRequest::decode(&enc(4, 42, Some(both)))
                .unwrap_err()
                .1,
            ServerCode::General(ErrorCode::Malformed)
        );
        for ops in [vec![], vec![Value::bytes(&[1; 48]), Value::bytes(&[1; 48])]] {
            let decide = Value::map(vec![
                (1, Value::bytes(&[1; 16])),
                (2, Value::Array(ops)),
                (3, Value::Bool(false)),
            ]);
            assert_eq!(
                ServerRequest::decode(&enc(4, 98, Some(decide)))
                    .unwrap_err()
                    .1,
                ServerCode::General(ErrorCode::InvalidInput)
            );
        }
        let prepare = Value::map(vec![(1, Value::bytes(&[1; 16])), (2, Value::Uint(4))]);
        assert_eq!(
            ServerRequest::decode(&enc(4, 90, Some(prepare)))
                .unwrap_err()
                .1,
            ServerCode::General(ErrorCode::InvalidInput)
        );
        // Display names (ADR 0069): an invalid name, a search text too short, a fingerprint
        // that is not one; 123 to 129 are reserved, not known.
        for name in ["Marie ", "Marie\u{202E}", "a\u{200B}b"] {
            let set = Value::map(vec![(1, Value::text(name))]);
            assert_eq!(
                ServerRequest::decode(&enc(4, 120, Some(set)))
                    .unwrap_err()
                    .1,
                ServerCode::General(ErrorCode::InvalidInput)
            );
        }
        let long = Value::map(vec![(1, Value::text(&"a".repeat(MAX_DISPLAY_NAME + 1)))]);
        assert_eq!(
            ServerRequest::decode(&enc(4, 120, Some(long)))
                .unwrap_err()
                .1,
            ServerCode::General(ErrorCode::Malformed)
        );
        let short = Value::map(vec![(1, Value::text("a"))]);
        assert_eq!(
            ServerRequest::decode(&enc(4, 121, Some(short)))
                .unwrap_err()
                .1,
            ServerCode::General(ErrorCode::InvalidInput)
        );
        let verify = Value::map(vec![(1, Value::bytes(&[1; 16])), (2, Value::text("ABC"))]);
        assert_eq!(
            ServerRequest::decode(&enc(4, 122, Some(verify)))
                .unwrap_err()
                .1,
            ServerCode::General(ErrorCode::InvalidInput)
        );
        assert_eq!(
            ServerRequest::decode(&enc(4, 123, None)).unwrap_err(),
            (3, ServerCode::General(ErrorCode::UnknownOperation))
        );
        assert!(is_server_request(&enc(4, 129, None)));
        // Not a server request.
        assert!(!is_server_request(&enc(1, 5, None)));
        assert!(is_server_request(&enc(4, 95, None)));
    }

    #[test]
    fn fingerprints_are_normalised() {
        assert_eq!(
            normalise_fingerprint("abcd-efgh ijkl-mnop qrst").as_deref(),
            Some("ABCDEFGHIJKLMNOPQRST")
        );
        assert!(normalise_fingerprint("ABCDEFGHIJKLMNOPQRS1").is_none());
        assert!(normalise_fingerprint("ABCDEFGHIJKLMNOPQRS").is_none());
    }

    #[test]
    fn replies_round_trip() {
        let replies = [
            (ServerOp::RoleRevoke, ServerReply::Done),
            (
                ServerOp::DeviceRevoke,
                ServerReply::DeviceRevoked { lockers: 2 },
            ),
            (
                ServerOp::ServerStatus,
                ServerReply::Status {
                    server: None,
                    lockers: Vec::new(),
                    last_sync_ms: None,
                    keylog: None,
                },
            ),
            (
                ServerOp::ServerStatus,
                ServerReply::Status {
                    last_sync_ms: Some(1_763_200_000_000),
                    keylog: Some(KeyLogStatus {
                        suspect: Some(SuspectReason::SizeDecrease),
                        entries: 12,
                        alerts: vec![
                            KeyLogAlert {
                                kind: AlertKind::UnknownOwnDevice,
                                index: Some(7),
                                device: Some([9; 16]),
                                locker: None,
                            },
                            KeyLogAlert {
                                kind: AlertKind::ForeignMemberKey,
                                index: Some(2),
                                device: None,
                                locker: None,
                            },
                            KeyLogAlert {
                                kind: AlertKind::WithheldRemoval,
                                index: Some(4),
                                device: None,
                                locker: Some([1; 16]),
                            },
                            KeyLogAlert {
                                kind: AlertKind::WithheldInscription,
                                index: None,
                                device: Some([9; 16]),
                                locker: None,
                            },
                            KeyLogAlert {
                                kind: AlertKind::UninscribedRemoval,
                                index: None,
                                device: None,
                                locker: Some([1; 16]),
                            },
                        ],
                    }),
                    server: Some(("hirzla://h".into(), [4; 16], "A".repeat(20), false)),
                    lockers: vec![LockerStatus {
                        id: [1; 16],
                        name: Some(Zeroizing::new("n".into())),
                        role: Some(Role::Reader),
                        cursor: 3,
                        unsent: 1,
                        pending: 0,
                        quarantined: 0,
                        access: true,
                        frozen: true,
                    }],
                },
            ),
            (
                ServerOp::ServerSync,
                ServerReply::Synced(vec![SyncReport {
                    locker: [1; 16],
                    received: 2,
                    sent: 1,
                    refused: 0,
                    access: false,
                }]),
            ),
            (
                ServerOp::LockerMembers,
                ServerReply::Members {
                    me: [5; 16],
                    members: vec![MemberInfo {
                        member: [5; 16],
                        role: Role::Owner,
                        devices: 1,
                        fingerprint: "B".repeat(20),
                        proven: true,
                        change_to: vec![Role::Manager, Role::Editor],
                        change_refusal: None,
                        remove_refusal: Some(Refusal::LastOwner),
                        name: Some("Marie Durand".into()),
                        verified: true,
                    }],
                    grantable: Vec::new(),
                    grant_refusal: Some(Refusal::AccessLost),
                    quorum: Some(2),
                },
            ),
            (
                ServerOp::QuorumPrepare,
                ServerReply::Request(QuorumState {
                    request: [1; 16],
                    locker: [2; 16],
                    action: QuorumAction::OwnerRoleChange,
                    target: Some([3; 16]),
                    detail: Some(2),
                    counted: vec![[4; 16], [5; 16]],
                    required: 3,
                    offer: "hirzla-demande:AAAA".into(),
                    created_ms: 12,
                }),
            ),
            (ServerOp::QuorumList, ServerReply::Requests(Vec::new())),
            (
                ServerOp::QuorumInspect,
                ServerReply::Inspected {
                    locker: [2; 16],
                    name: Some(Zeroizing::new("Équipe".into())),
                    action: QuorumAction::Policy,
                    target: None,
                    target_fingerprint: None,
                    detail: Some(3),
                    issuer: [4; 16],
                    issuer_fingerprint: Some("C".repeat(20)),
                    can_sign: true,
                    target_name: None,
                    issuer_name: Some("Zoé".into()),
                },
            ),
            (
                ServerOp::ServerIdentity,
                ServerReply::Identity {
                    member_keys: vec![1, 2, 3],
                    fingerprint: "D".repeat(20),
                    device: [6; 16],
                    control_code: "AB-CD".into(),
                    name: Some("Marie Durand".into()),
                },
            ),
            (
                ServerOp::RoleGrant,
                ServerReply::Granted {
                    fingerprint: "D".repeat(20),
                    devices: 2,
                    name: None,
                },
            ),
            (
                ServerOp::MemberSearch,
                ServerReply::Found {
                    members: vec![FoundInfo {
                        member: [7; 16],
                        name: "Paul Renaud".into(),
                        fingerprint: "E".repeat(20),
                        verified: false,
                    }],
                    more: true,
                },
            ),
            (ServerOp::ProfileSet, ServerReply::Done),
            (ServerOp::MemberVerify, ServerReply::Done),
            (
                ServerOp::QuorumApprove,
                ServerReply::Approved("hirzla-accord:AAAA".into()),
            ),
            (ServerOp::QuorumApply, ServerReply::Done),
            (ServerOp::QuarantineDecide, ServerReply::Done),
            (
                ServerOp::QuarantineList,
                ServerReply::Quarantine {
                    ops: vec![QuarantinedOp {
                        op_id: [7; 48],
                        member: [1; 16],
                        device: [2; 16],
                        cause: 1,
                        class: 1,
                        wall_ms: Some(5),
                        title: Some(Zeroizing::new("Routeur".into())),
                        secret: Some([3; 16]),
                        received_ms: 10,
                        due_ms: 20,
                    }],
                    can_decide: false,
                },
            ),
        ];
        for (op, r) in replies {
            let f = ServerReply::encode(9, &Ok(r.clone())).unwrap();
            assert_eq!(ServerReply::decode(op, &f).unwrap(), (9, Ok(r)));
        }
        // A joined status without its log, a suspect log without its reason, a device alert
        // without its device: refused.
        let status = |keylog: Option<Value>| {
            let mut b = vec![
                (1, Value::Bool(true)),
                (2, Value::text("hirzla://h:7443")),
                (3, Value::bytes(&[1; 16])),
                (4, Value::text(&"A".repeat(20))),
                (5, Value::Bool(true)),
                (6, Value::Array(Vec::new())),
            ];
            if let Some(k) = keylog {
                b.push((8, k));
            }
            cbor::encode(&Value::map(vec![
                (1, Value::Uint(SERVER_VERSION)),
                (2, Value::Uint(1)),
                (3, Value::Uint(0)),
                (4, Value::map(b)),
            ]))
            .unwrap()
        };
        assert!(ServerReply::decode(ServerOp::ServerStatus, &status(None)).is_err());
        let suspect_without_reason = Value::map(vec![
            (1, Value::Bool(true)),
            (2, Value::Uint(3)),
            (4, Value::Array(Vec::new())),
        ]);
        assert!(ServerReply::decode(
            ServerOp::ServerStatus,
            &status(Some(suspect_without_reason))
        )
        .is_err());
        let device_alert_without_device = Value::map(vec![
            (1, Value::Bool(false)),
            (2, Value::Uint(3)),
            (
                4,
                Value::Array(vec![Value::map(vec![
                    (1, Value::Uint(2)),
                    (2, Value::Uint(1)),
                ])]),
            ),
        ]);
        assert!(ServerReply::decode(
            ServerOp::ServerStatus,
            &status(Some(device_alert_without_device))
        )
        .is_err());
        let healthy = Value::map(vec![
            (1, Value::Bool(false)),
            (2, Value::Uint(3)),
            (4, Value::Array(Vec::new())),
        ]);
        assert!(ServerReply::decode(ServerOp::ServerStatus, &status(Some(healthy))).is_ok());
        for code in [
            ServerCode::ApprovalInvalid,
            ServerCode::QuorumNotMet(1, 3),
            ServerCode::LockerFrozen,
            ServerCode::InvitationInvalid,
            ServerCode::AlreadyRevoked,
        ] {
            let f = ServerReply::encode(2, &Err(code)).unwrap();
            assert_eq!(
                ServerReply::decode(ServerOp::QuorumApply, &f).unwrap(),
                (2, Err(code))
            );
        }
        let f = ServerReply::encode(2, &Err(ServerCode::ServerRefused(4))).unwrap();
        assert_eq!(
            ServerReply::decode(ServerOp::ServerSync, &f).unwrap(),
            (2, Err(ServerCode::ServerRefused(4)))
        );
    }

    #[test]
    fn debug_never_shows_locker_names() {
        let locker = LockerStatus {
            id: [1; 16],
            name: Some(Zeroizing::new("secret-casier".to_owned())),
            role: None,
            cursor: 0,
            unsent: 0,
            pending: 0,
            quarantined: 0,
            access: true,
            frozen: false,
        };
        let d = format!("{locker:?}");
        assert!(!d.contains("secret"), "{d}");
    }
}
