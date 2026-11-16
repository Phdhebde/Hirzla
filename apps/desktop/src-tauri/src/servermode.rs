//! Commands of the server mode (local API version 4, `docs/api-locale.md` § 15, ADR 0041):
//! joining a `hirzlad`, confirming its fingerprint, synchronising, shared lockers, members and
//! roles, and the state of the key transparency log.
//!
//! The core does every network exchange and holds every key. The web view receives what it
//! shows: addresses, fingerprints, identifiers, roles, counts, and what the current member may
//! do (computed by the core). The site CA file is chosen with the system's picker and read by
//! this process: the web view only learns its name.

use std::io::Read;
use std::path::Path;

use hirzla_core::server_mode::proto::{
    normalise_fingerprint, AlertKind, KeyLogStatus, LockerStatus, MemberInfo, QuarantinedOp,
    QuorumAction, QuorumState, Refusal, Role, ServerReply, ServerRequest, SuspectReason,
    SyncReport, MAX_LOCKER_NAME, MAX_ROOTS, MAX_TEXT,
};
use hirzla_vault::model::{Id16, MemberKeys, OpId, MAX_SERVER_URL};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::commands::{guard, hex, id16, on_main_thread, AppState, State};
use crate::error::DesktopError;

// -----------------------------------------------------------------------------------------
// Types exchanged with the web view
// -----------------------------------------------------------------------------------------

/// A role, by a stable name (`sync-protocol.md` § 7.1).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoleName {
    /// `Owner`.
    Owner,
    /// `Manager`.
    Manager,
    /// `Editor`.
    Editor,
    /// `Reader`.
    Reader,
    /// `BlindUser`.
    BlindUser,
    /// `Auditor`.
    Auditor,
}

impl From<Role> for RoleName {
    fn from(r: Role) -> Self {
        match r {
            Role::Owner => RoleName::Owner,
            Role::Manager => RoleName::Manager,
            Role::Editor => RoleName::Editor,
            Role::Reader => RoleName::Reader,
            Role::BlindUser => RoleName::BlindUser,
            Role::Auditor => RoleName::Auditor,
        }
    }
}

impl From<RoleName> for Role {
    fn from(r: RoleName) -> Self {
        match r {
            RoleName::Owner => Role::Owner,
            RoleName::Manager => Role::Manager,
            RoleName::Editor => Role::Editor,
            RoleName::Reader => Role::Reader,
            RoleName::BlindUser => Role::BlindUser,
            RoleName::Auditor => Role::Auditor,
        }
    }
}

fn refusal_name(r: Refusal) -> &'static str {
    match r {
        Refusal::RoleTooLow => "role",
        Refusal::QuorumRequired => "quorum",
        Refusal::LastOwner => "last_owner",
        Refusal::AccessLost => "access_lost",
    }
}

/// One shared locker in the state of the server mode.
#[derive(Clone, Serialize)]
pub struct SharedLockerDto {
    id: String,
    /// Absent until the locker's metadata is readable.
    name: Option<Zeroizing<String>>,
    role: Option<RoleName>,
    unsent: u64,
    pending: u64,
    quarantined: u64,
    /// `false` once the server refused the locker (member removed).
    access: bool,
    /// Writes frozen: a removal announced by the key log was not received (ADR 0045).
    frozen: bool,
}

impl From<LockerStatus> for SharedLockerDto {
    fn from(l: LockerStatus) -> Self {
        SharedLockerDto {
            id: hex(&l.id),
            name: l.name,
            role: l.role.map(Into::into),
            unsent: l.unsent,
            pending: l.pending,
            quarantined: l.quarantined,
            access: l.access,
            frozen: l.frozen,
        }
    }
}

/// An alert about the member's own keys, or a dated one (ADR 0045).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AlertDto {
    /// `foreign_member_key`, `unknown_device`, `unknown_revocation`, `withheld_removal`,
    /// `uninscribed_removal`, `withheld_inscription`, `withheld_operation` or
    /// `unknown_profile` (ADR 0069).
    kind: &'static str,
    /// Rank of the entry in the log, when there is one.
    index: Option<u64>,
    device: Option<String>,
    locker: Option<String>,
}

/// The local key transparency log (ADR 0040, ADR 0041).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct KeyLogDto {
    suspect: bool,
    /// Why, when suspect: `root`, `shorter`, `rule`, `peer`, `proof`.
    reason: Option<&'static str>,
    entries: u64,
    alerts: Vec<AlertDto>,
}

impl From<KeyLogStatus> for KeyLogDto {
    fn from(k: KeyLogStatus) -> Self {
        KeyLogDto {
            suspect: k.suspect.is_some(),
            reason: k.suspect.map(|r| match r {
                SuspectReason::RootMismatch => "root",
                SuspectReason::SizeDecrease => "shorter",
                SuspectReason::RuleViolation => "rule",
                SuspectReason::PeerHead | SuspectReason::Unserved => "peer",
                SuspectReason::ProofEntry => "proof",
            }),
            entries: k.entries,
            alerts: k
                .alerts
                .iter()
                .map(|a| AlertDto {
                    kind: match a.kind {
                        AlertKind::ForeignMemberKey => "foreign_member_key",
                        AlertKind::UnknownOwnDevice => "unknown_device",
                        AlertKind::UnknownOwnRevocation => "unknown_revocation",
                        AlertKind::WithheldRemoval => "withheld_removal",
                        AlertKind::UninscribedRemoval => "uninscribed_removal",
                        AlertKind::WithheldInscription => "withheld_inscription",
                        AlertKind::WithheldOperation => "withheld_operation",
                        AlertKind::UnknownOwnProfile => "unknown_profile",
                    },
                    index: a.index,
                    device: a.device.as_ref().map(|d| hex(d)),
                    locker: a.locker.as_ref().map(|l| hex(l)),
                })
                .collect(),
        }
    }
}

/// The state of the server mode.
#[derive(Clone, Serialize)]
pub struct ServerStatusDto {
    joined: bool,
    url: Option<String>,
    server_id: Option<String>,
    /// The server fingerprint, 20 characters.
    fingerprint: Option<String>,
    verified: bool,
    /// End of the last successful synchronisation since the vault was opened.
    last_sync_ms: Option<u64>,
    keylog: Option<KeyLogDto>,
    lockers: Vec<SharedLockerDto>,
}

impl std::fmt::Debug for ServerStatusDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Locker names stay out of debug output.
        write!(
            f,
            "ServerStatusDto(joined: {}, {} lockers)",
            self.joined,
            self.lockers.len()
        )
    }
}

/// Public identity of this device, to give to the server administrator.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IdentityDto {
    member: String,
    /// Fingerprint of the member key.
    fingerprint: String,
    device: String,
    control_code: String,
}

/// Outcome of joining.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JoinedDto {
    fingerprint: String,
    verified: bool,
    /// Whether the server recognised the account.
    account: bool,
}

/// What one synchronisation did for one locker.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SyncDto {
    locker: String,
    received: u64,
    sent: u64,
    refused: u64,
    access: bool,
}

impl From<SyncReport> for SyncDto {
    fn from(r: SyncReport) -> Self {
        SyncDto {
            locker: hex(&r.locker),
            received: r.received,
            sent: r.sent,
            refused: r.refused,
            access: r.access,
        }
    }
}

/// One member of a shared locker, with what the current member may do to it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MemberDto {
    member: String,
    /// Whether it is the current member.
    me: bool,
    role: RoleName,
    devices: u64,
    fingerprint: String,
    proven: bool,
    change_to: Vec<RoleName>,
    change_refusal: Option<&'static str>,
    remove_refusal: Option<&'static str>,
}

/// Members of a shared locker.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MembersDto {
    me: String,
    members: Vec<MemberDto>,
    grantable: Vec<RoleName>,
    grant_refusal: Option<&'static str>,
    /// Quorum of owners in force (ADR 0044).
    quorum: Option<u64>,
}

fn members_dto(
    me: Id16,
    members: Vec<MemberInfo>,
    grantable: &[Role],
    grant_refusal: Option<Refusal>,
    quorum: Option<u64>,
) -> MembersDto {
    MembersDto {
        me: hex(&me),
        members: members
            .into_iter()
            .map(|m| MemberDto {
                member: hex(&m.member),
                me: m.member == me,
                role: m.role.into(),
                devices: m.devices,
                fingerprint: m.fingerprint,
                proven: m.proven,
                change_to: m.change_to.into_iter().map(Into::into).collect(),
                change_refusal: m.change_refusal.map(refusal_name),
                remove_refusal: m.remove_refusal.map(refusal_name),
            })
            .collect(),
        grantable: grantable.iter().map(|r| (*r).into()).collect(),
        grant_refusal: grant_refusal.map(refusal_name),
        quorum,
    }
}

/// An action that takes approvals, by a stable name (ADR 0044).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuorumActionName {
    /// Removal of an `Owner`.
    OwnerRemoval,
    /// Role change of an `Owner`.
    OwnerRoleChange,
    /// Quorum change.
    Policy,
}

impl From<QuorumAction> for QuorumActionName {
    fn from(a: QuorumAction) -> Self {
        match a {
            QuorumAction::OwnerRemoval => QuorumActionName::OwnerRemoval,
            QuorumAction::OwnerRoleChange => QuorumActionName::OwnerRoleChange,
            QuorumAction::Policy => QuorumActionName::Policy,
        }
    }
}

/// A pending approval request kept by the core.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct QuorumStateDto {
    request: String,
    locker: String,
    action: QuorumActionName,
    target: Option<String>,
    /// New role, for a role change.
    role: Option<RoleName>,
    /// New quorum, for a policy.
    quorum: Option<u64>,
    counted: Vec<String>,
    required: u64,
    /// The `hirzla-demande:` text to hand to the other owners.
    offer: String,
    created_ms: u64,
}

fn detail_names(action: QuorumAction, detail: Option<u64>) -> (Option<RoleName>, Option<u64>) {
    match action {
        QuorumAction::OwnerRoleChange => (detail.and_then(Role::from_code).map(Into::into), None),
        QuorumAction::Policy => (None, detail),
        QuorumAction::OwnerRemoval => (None, None),
    }
}

impl From<QuorumState> for QuorumStateDto {
    fn from(q: QuorumState) -> Self {
        let (role, quorum) = detail_names(q.action, q.detail);
        QuorumStateDto {
            request: hex(&q.request),
            locker: hex(&q.locker),
            action: q.action.into(),
            target: q.target.as_ref().map(|t| hex(t)),
            role,
            quorum,
            counted: q.counted.iter().map(|m| hex(m)).collect(),
            required: q.required,
            offer: q.offer,
            created_ms: q.created_ms,
        }
    }
}

/// What an approver would sign (`QuorumInspect`).
#[derive(Clone, Serialize)]
pub struct InspectedDto {
    locker: String,
    name: Option<Zeroizing<String>>,
    action: QuorumActionName,
    target: Option<String>,
    target_fingerprint: Option<String>,
    role: Option<RoleName>,
    quorum: Option<u64>,
    issuer: String,
    issuer_fingerprint: Option<String>,
    can_sign: bool,
}

impl std::fmt::Debug for InspectedDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InspectedDto(can_sign: {})", self.can_sign)
    }
}

/// A quarantined operation (ADR 0045). Never a secret value.
#[derive(Clone, Serialize)]
pub struct QuarantinedDto {
    op_id: String,
    member: String,
    device: String,
    /// `removal` (concurrent with a removal) or `fork`.
    cause: &'static str,
    /// `data` or `control`.
    class: &'static str,
    wall_ms: Option<u64>,
    title: Option<Zeroizing<String>>,
    secret: Option<String>,
    received_ms: u64,
    due_ms: u64,
}

impl From<QuarantinedOp> for QuarantinedDto {
    fn from(o: QuarantinedOp) -> Self {
        QuarantinedDto {
            op_id: hex(&o.op_id),
            member: hex(&o.member),
            device: hex(&o.device),
            cause: if o.cause == 2 { "fork" } else { "removal" },
            class: if o.class == 2 { "control" } else { "data" },
            wall_ms: o.wall_ms,
            title: o.title,
            secret: o.secret.as_ref().map(|s| hex(s)),
            received_ms: o.received_ms,
            due_ms: o.due_ms,
        }
    }
}

/// The quarantine of a locker.
#[derive(Clone, Serialize)]
pub struct QuarantineDto {
    ops: Vec<QuarantinedDto>,
    can_decide: bool,
}

impl std::fmt::Debug for QuarantineDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Titles stay out of debug output.
        write!(f, "QuarantineDto({} ops)", self.ops.len())
    }
}

/// The site CA chosen with the file picker, waiting for [`server_join`].
pub struct PendingCa {
    pem: Vec<u8>,
}

// -----------------------------------------------------------------------------------------
// Checks before the core
// -----------------------------------------------------------------------------------------

fn fingerprint_arg(typed: &str) -> Result<String, DesktopError> {
    normalise_fingerprint(typed).ok_or(DesktopError::Invalid(
        "Empreinte non valide : 20 caractères, lettres A à Z et chiffres 2 à 7 (les espaces et \
         les tirets sont ignorés).",
    ))
}

fn optional_fingerprint(typed: Option<&str>) -> Result<Option<String>, DesktopError> {
    typed
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(fingerprint_arg)
        .transpose()
}

fn url_arg(typed: &str) -> Result<String, DesktopError> {
    let url = typed.trim();
    if url.is_empty() || url.len() > MAX_SERVER_URL {
        return Err(DesktopError::Invalid(
            "Adresse du serveur non valide : hirzla://hôte, ou hirzla://hôte:port.",
        ));
    }
    // A bare host gets the scheme; the core checks the rest (`parse_address`).
    Ok(if url.contains("://") {
        url.to_owned()
    } else {
        format!("hirzla://{url}")
    })
}

fn member_arg(typed: &str) -> Result<Id16, DesktopError> {
    let cleaned: String = typed
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    id16(&cleaned).map_err(|_| {
        DesktopError::Invalid("Identifiant du membre non valide : 32 chiffres hexadécimaux.")
    })
}

fn device_arg(typed: &str) -> Result<Id16, DesktopError> {
    id16(typed).map_err(|_| DesktopError::Invalid("Identifiant d'appareil non valide."))
}

fn locker_arg(typed: &str) -> Result<Id16, DesktopError> {
    id16(typed).map_err(|_| DesktopError::Invalid("Identifiant de casier non valide."))
}

/// A pasted text object (`sync-protocol.md` § 11.10): its kind is checked by its prefix, the
/// core checks the rest.
fn text_arg(typed: &str, prefix: &str) -> Result<String, DesktopError> {
    let t: String = typed.chars().filter(|c| !c.is_whitespace()).collect();
    if t.len() > MAX_TEXT || !t.starts_with(prefix) {
        return Err(DesktopError::Invalid(match prefix {
            "hirzla-invitation:" => {
                "Collez le lien d'invitation complet : il commence par « hirzla-invitation: »."
            }
            "hirzla-demande:" => {
                "Collez la demande complète : elle commence par « hirzla-demande: »."
            }
            _ => "Collez l'accord complet : il commence par « hirzla-accord: ».",
        }));
    }
    Ok(t)
}

fn hex_id<const N: usize>(typed: &str) -> Result<[u8; N], DesktopError> {
    let bad = DesktopError::Invalid("Identifiant non valide.");
    if typed.len() != 2 * N || !typed.is_ascii() {
        return Err(bad);
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&typed[2 * i..2 * i + 2], 16).map_err(|_| bad.clone())?;
    }
    Ok(out)
}

fn locker_name_arg(typed: &str) -> Result<Zeroizing<String>, DesktopError> {
    let name = typed.trim();
    if name.is_empty() || name.len() > MAX_LOCKER_NAME {
        return Err(DesktopError::Invalid(
            "Le nom du casier doit compter de 1 à 256 octets.",
        ));
    }
    Ok(Zeroizing::new(name.to_owned()))
}

/// Reads a site CA file: at most [`MAX_ROOTS`] bytes, with at least one PEM certificate.
fn read_ca(path: &Path) -> Result<Vec<u8>, DesktopError> {
    let unreadable = DesktopError::Invalid("Le certificat de l'autorité n'a pas pu être lu.");
    let f = std::fs::File::open(path).map_err(|_| unreadable.clone())?;
    let mut pem = Vec::new();
    f.take(MAX_ROOTS as u64 + 1)
        .read_to_end(&mut pem)
        .map_err(|_| unreadable)?;
    let marker = b"-----BEGIN CERTIFICATE-----";
    if pem.len() > MAX_ROOTS || !pem.windows(marker.len()).any(|w| w == marker) {
        return Err(DesktopError::Invalid(
            "Ce fichier n'est pas un certificat d'autorité au format PEM (64 Kio au plus).",
        ));
    }
    Ok(pem)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

// -----------------------------------------------------------------------------------------
// Logic of the commands, testable without a web view
// -----------------------------------------------------------------------------------------

impl AppState {
    fn call_server(&self, request: &ServerRequest) -> Result<ServerReply, DesktopError> {
        self.with_link(|l| l.call_server(request))
    }

    /// State of the server mode.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn server_status(&self) -> Result<ServerStatusDto, DesktopError> {
        let ServerReply::Status {
            server,
            lockers,
            last_sync_ms,
            keylog,
        } = self.call_server(&ServerRequest::ServerStatus)?
        else {
            return Err(DesktopError::Protocol);
        };
        let (url, server_id, fingerprint, verified) = match server {
            Some((url, id, fp, verified)) => (Some(url), Some(hex(&id)), Some(fp), verified),
            None => (None, None, None, false),
        };
        Ok(ServerStatusDto {
            joined: url.is_some(),
            url,
            server_id,
            fingerprint,
            verified,
            last_sync_ms,
            keylog: keylog.map(Into::into),
            lockers: lockers.into_iter().map(Into::into).collect(),
        })
    }

    fn identity_reply(&self) -> Result<(Vec<u8>, IdentityDto), DesktopError> {
        let ServerReply::Identity {
            member_keys,
            fingerprint,
            device,
            control_code,
            ..
        } = self.call_server(&ServerRequest::ServerIdentity)?
        else {
            return Err(DesktopError::Protocol);
        };
        let member = hirzla_vault::cbor::decode(&member_keys)
            .ok()
            .and_then(|v| MemberKeys::from_value(&v).ok())
            .map(|k| k.member)
            .ok_or(DesktopError::Protocol)?;
        let dto = IdentityDto {
            member: hex(&member),
            fingerprint,
            device: hex(&device),
            control_code,
        };
        Ok((member_keys, dto))
    }

    /// Public identity of this device.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn server_identity(&self) -> Result<IdentityDto, DesktopError> {
        self.identity_reply().map(|(_, dto)| dto)
    }

    /// Writes the public member key at `path`, for the server administrator.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn export_identity(&self, path: &Path) -> Result<String, DesktopError> {
        let (member_keys, _) = self.identity_reply()?;
        std::fs::write(path, member_keys)
            .map_err(|_| DesktopError::Invalid("Le fichier n'a pas pu être écrit."))?;
        Ok(file_name(path))
    }

    /// Keeps the site CA read from `path` for [`AppState::join_server`]; returns its name.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn set_server_ca(&self, path: &Path) -> Result<String, DesktopError> {
        let pem = read_ca(path)?;
        let name = file_name(path);
        *guard(&self.pending_ca) = Some(PendingCa { pem });
        Ok(name)
    }

    /// Joins the server at `url` with the CA chosen before, comparing `fingerprint` (from
    /// the invitation) when given.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn join_server(
        &self,
        url: &str,
        fingerprint: Option<&str>,
    ) -> Result<JoinedDto, DesktopError> {
        let url = url_arg(url)?;
        let fingerprint = optional_fingerprint(fingerprint)?;
        let roots = guard(&self.pending_ca)
            .as_ref()
            .map(|c| c.pem.clone())
            .ok_or(DesktopError::Invalid(
                "Choisissez d'abord le certificat de l'autorité du site.",
            ))?;
        let ServerReply::Joined {
            fingerprint,
            verified,
            account,
            ..
        } = self.call_server(&ServerRequest::ServerJoin {
            url,
            roots,
            fingerprint,
        })?
        else {
            return Err(DesktopError::Protocol);
        };
        *guard(&self.pending_ca) = None;
        Ok(JoinedDto {
            fingerprint,
            verified,
            account,
        })
    }

    /// Confirms the server fingerprint compared out of band; returns whether the server
    /// recognised the account.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn confirm_server(&self, fingerprint: &str) -> Result<bool, DesktopError> {
        let fingerprint = fingerprint_arg(fingerprint)?;
        match self.call_server(&ServerRequest::ServerConfirm { fingerprint })? {
            ServerReply::Confirmed { account } => Ok(account),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Synchronises every shared locker.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn sync_server(&self) -> Result<Vec<SyncDto>, DesktopError> {
        match self.call_server(&ServerRequest::ServerSync)? {
            ServerReply::Synced(r) => Ok(r.into_iter().map(Into::into).collect()),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Creates a shared locker; returns its identifier.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn create_shared_locker(&self, name: &str) -> Result<String, DesktopError> {
        let name = locker_name_arg(name)?;
        match self.call_server(&ServerRequest::SharedLockerCreate { name })? {
            ServerReply::LockerCreated(id) => Ok(hex(&id)),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Members of a shared locker.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn locker_members(&self, locker: &str) -> Result<MembersDto, DesktopError> {
        let locker = locker_arg(locker)?;
        match self.call_server(&ServerRequest::LockerMembers { locker })? {
            ServerReply::Members {
                me,
                members,
                grantable,
                grant_refusal,
                quorum,
            } => Ok(members_dto(me, members, &grantable, grant_refusal, quorum)),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Grants a role (new member or role change); returns the member's fingerprint.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn grant_role(
        &self,
        locker: &str,
        member: &str,
        role: RoleName,
        fingerprint: Option<&str>,
    ) -> Result<String, DesktopError> {
        let request = ServerRequest::RoleGrant {
            locker: locker_arg(locker)?,
            member: member_arg(member)?,
            role: role.into(),
            fingerprint: optional_fingerprint(fingerprint)?,
        };
        match self.call_server(&request)? {
            ServerReply::Granted { fingerprint, .. } => Ok(fingerprint),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Removes a member from a shared locker.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn revoke_role(&self, locker: &str, member: &str) -> Result<(), DesktopError> {
        let request = ServerRequest::RoleRevoke {
            locker: locker_arg(locker)?,
            member: member_arg(member)?,
        };
        self.call_server(&request).map(drop)
    }

    /// Revokes another device of the member, from the alert « appareil inconnu inscrit à
    /// votre nom » (ADR 0059). Returns the number of lockers where the revocation was
    /// published.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn revoke_device(&self, device: &str) -> Result<u64, DesktopError> {
        let device = device_arg(device)?;
        match self.call_server(&ServerRequest::DeviceRevoke { device })? {
            ServerReply::DeviceRevoked { lockers } => Ok(lockers),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Joins with an invitation link (ADR 0046).
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn join_server_link(&self, link: &str) -> Result<JoinedDto, DesktopError> {
        let link = text_arg(link, "hirzla-invitation:")?;
        let ServerReply::Joined {
            fingerprint,
            verified,
            account,
            ..
        } = self.call_server(&ServerRequest::ServerJoinLink { link })?
        else {
            return Err(DesktopError::Protocol);
        };
        Ok(JoinedDto {
            fingerprint,
            verified,
            account,
        })
    }

    /// Prepares an approval request (ADR 0044).
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn quorum_prepare(
        &self,
        locker: &str,
        action: QuorumActionName,
        target: Option<&str>,
        role: Option<RoleName>,
        quorum: Option<u64>,
    ) -> Result<QuorumStateDto, DesktopError> {
        let locker = locker_arg(locker)?;
        let target = target.map(member_arg).transpose()?;
        let (action, detail) = match action {
            QuorumActionName::OwnerRemoval => (QuorumAction::OwnerRemoval, None),
            QuorumActionName::OwnerRoleChange => (
                QuorumAction::OwnerRoleChange,
                role.map(|r| Role::from(r).code()),
            ),
            QuorumActionName::Policy => (QuorumAction::Policy, quorum),
        };
        match self.call_server(&ServerRequest::QuorumPrepare {
            locker,
            action,
            target,
            detail,
        })? {
            ServerReply::Request(q) => Ok(q.into()),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// What a request would do, without signing it.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn quorum_inspect(&self, offer: &str) -> Result<InspectedDto, DesktopError> {
        let offer = text_arg(offer, "hirzla-demande:")?;
        match self.call_server(&ServerRequest::QuorumInspect { offer })? {
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
                ..
            } => {
                let (role, quorum) = detail_names(action, detail);
                Ok(InspectedDto {
                    locker: hex(&locker),
                    name,
                    action: action.into(),
                    target: target.as_ref().map(|t| hex(t)),
                    target_fingerprint,
                    role,
                    quorum,
                    issuer: hex(&issuer),
                    issuer_fingerprint,
                    can_sign,
                })
            }
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Signs a request; returns the `hirzla-accord:` text.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn quorum_approve(&self, offer: &str) -> Result<String, DesktopError> {
        let offer = text_arg(offer, "hirzla-demande:")?;
        match self.call_server(&ServerRequest::QuorumApprove { offer })? {
            ServerReply::Approved(t) => Ok(t),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Adds an approval received to a pending request.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn quorum_collect(&self, token: &str) -> Result<QuorumStateDto, DesktopError> {
        let token = text_arg(token, "hirzla-accord:")?;
        match self.call_server(&ServerRequest::QuorumCollect { token })? {
            ServerReply::Request(q) => Ok(q.into()),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Pending requests, of one locker or all.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn quorum_list(&self, locker: Option<&str>) -> Result<Vec<QuorumStateDto>, DesktopError> {
        let locker = locker.map(locker_arg).transpose()?;
        match self.call_server(&ServerRequest::QuorumList { locker })? {
            ServerReply::Requests(r) => Ok(r.into_iter().map(Into::into).collect()),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Publishes a request whose quorum is met.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn quorum_apply(&self, request: &str) -> Result<(), DesktopError> {
        let request = hex_id::<16>(request)?;
        self.call_server(&ServerRequest::QuorumApply { request })
            .map(drop)
    }

    /// Abandons a request.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn quorum_cancel(&self, request: &str) -> Result<(), DesktopError> {
        let request = hex_id::<16>(request)?;
        self.call_server(&ServerRequest::QuorumCancel { request })
            .map(drop)
    }

    /// The quarantine of a locker.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn quarantine_list(&self, locker: &str) -> Result<QuarantineDto, DesktopError> {
        let locker = locker_arg(locker)?;
        match self.call_server(&ServerRequest::QuarantineList { locker })? {
            ServerReply::Quarantine { ops, can_decide } => Ok(QuarantineDto {
                ops: ops.into_iter().map(Into::into).collect(),
                can_decide,
            }),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Accepts or rejects quarantined operations.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn quarantine_decide(
        &self,
        locker: &str,
        ops: &[String],
        accept: bool,
    ) -> Result<(), DesktopError> {
        let locker = locker_arg(locker)?;
        let mut ops: Vec<OpId> = ops
            .iter()
            .map(|o| hex_id::<48>(o))
            .collect::<Result<_, _>>()?;
        ops.sort_unstable();
        ops.dedup();
        if ops.is_empty() {
            return Err(DesktopError::Invalid("Choisissez au moins une opération."));
        }
        self.call_server(&ServerRequest::QuarantineDecide {
            locker,
            ops,
            accept,
        })
        .map(drop)
    }
}

// -----------------------------------------------------------------------------------------
// Tauri commands
// -----------------------------------------------------------------------------------------

/// See [`AppState::server_status`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn server_status(state: State<'_>) -> Result<ServerStatusDto, DesktopError> {
    state.server_status()
}

/// See [`AppState::server_identity`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn server_identity(state: State<'_>) -> Result<IdentityDto, DesktopError> {
    state.server_identity()
}

/// Asks where to save the public member key with the system's picker, then writes it.
/// Returns the file name.
#[tauri::command(async, rename_all = "snake_case")]
pub fn export_server_identity(
    state: State<'_>,
    window: tauri::WebviewWindow,
) -> Result<String, DesktopError> {
    let IdentityDto { member, .. } = state.server_identity()?;
    let suggested = format!("hirzla-membre-{}.hirzla-membre", &member[..8]);
    let path = on_main_thread(&window, move |parent| {
        rfd::FileDialog::new()
            .set_title("Enregistrer votre clé publique de membre")
            .set_file_name(suggested)
            .set_parent(parent)
            .save_file()
    })?;
    state.export_identity(&path)
}

/// Asks for the site CA with the system's picker and keeps it for [`server_join`]; returns
/// its name.
#[tauri::command(async, rename_all = "snake_case")]
pub fn choose_server_ca(
    state: State<'_>,
    window: tauri::WebviewWindow,
) -> Result<String, DesktopError> {
    let path = on_main_thread(&window, |parent| {
        rfd::FileDialog::new()
            .set_title("Certificat de l'autorité du site (PEM)")
            .add_filter("Certificat PEM", &["pem", "crt", "cer"])
            .set_parent(parent)
            .pick_file()
    })?;
    state.set_server_ca(&path)
}

/// See [`AppState::join_server`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn server_join(
    state: State<'_>,
    url: String,
    fingerprint: Option<String>,
) -> Result<JoinedDto, DesktopError> {
    state.join_server(&url, fingerprint.as_deref())
}

/// See [`AppState::confirm_server`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn server_confirm(state: State<'_>, fingerprint: String) -> Result<bool, DesktopError> {
    state.confirm_server(&fingerprint)
}

/// See [`AppState::sync_server`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn server_sync(state: State<'_>) -> Result<Vec<SyncDto>, DesktopError> {
    state.sync_server()
}

/// See [`AppState::create_shared_locker`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn create_shared_locker(state: State<'_>, name: String) -> Result<String, DesktopError> {
    state.create_shared_locker(&name)
}

/// See [`AppState::locker_members`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn locker_members(state: State<'_>, locker: String) -> Result<MembersDto, DesktopError> {
    state.locker_members(&locker)
}

/// See [`AppState::grant_role`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn grant_role(
    state: State<'_>,
    locker: String,
    member: String,
    role: RoleName,
    fingerprint: Option<String>,
) -> Result<String, DesktopError> {
    state.grant_role(&locker, &member, role, fingerprint.as_deref())
}

/// See [`AppState::revoke_role`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn revoke_role(state: State<'_>, locker: String, member: String) -> Result<(), DesktopError> {
    state.revoke_role(&locker, &member)
}

/// See [`AppState::revoke_device`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn revoke_device(state: State<'_>, device: String) -> Result<u64, DesktopError> {
    state.revoke_device(&device)
}

/// See [`AppState::join_server_link`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn server_join_link(state: State<'_>, link: String) -> Result<JoinedDto, DesktopError> {
    state.join_server_link(&link)
}

/// See [`AppState::quorum_prepare`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn quorum_prepare(
    state: State<'_>,
    locker: String,
    action: QuorumActionName,
    target: Option<String>,
    role: Option<RoleName>,
    quorum: Option<u64>,
) -> Result<QuorumStateDto, DesktopError> {
    state.quorum_prepare(&locker, action, target.as_deref(), role, quorum)
}

/// See [`AppState::quorum_inspect`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn quorum_inspect(state: State<'_>, offer: String) -> Result<InspectedDto, DesktopError> {
    state.quorum_inspect(&offer)
}

/// See [`AppState::quorum_approve`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn quorum_approve(state: State<'_>, offer: String) -> Result<String, DesktopError> {
    state.quorum_approve(&offer)
}

/// See [`AppState::quorum_collect`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn quorum_collect(state: State<'_>, token: String) -> Result<QuorumStateDto, DesktopError> {
    state.quorum_collect(&token)
}

/// See [`AppState::quorum_list`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn quorum_list(
    state: State<'_>,
    locker: Option<String>,
) -> Result<Vec<QuorumStateDto>, DesktopError> {
    state.quorum_list(locker.as_deref())
}

/// See [`AppState::quorum_apply`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn quorum_apply(state: State<'_>, request: String) -> Result<(), DesktopError> {
    state.quorum_apply(&request)
}

/// See [`AppState::quorum_cancel`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn quorum_cancel(state: State<'_>, request: String) -> Result<(), DesktopError> {
    state.quorum_cancel(&request)
}

/// See [`AppState::quarantine_list`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn quarantine_list(state: State<'_>, locker: String) -> Result<QuarantineDto, DesktopError> {
    state.quarantine_list(&locker)
}

/// See [`AppState::quarantine_decide`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn quarantine_decide(
    state: State<'_>,
    locker: String,
    ops: Vec<String>,
    accept: bool,
) -> Result<(), DesktopError> {
    state.quarantine_decide(&locker, &ops, accept)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hirzla_core::server_mode::proto::KeyLogAlert;

    #[test]
    fn typed_values_are_checked_before_the_core() {
        assert_eq!(
            fingerprint_arg("abcde-fghij klmno pqr23").unwrap(),
            "ABCDEFGHIJKLMNOPQR23"
        );
        assert!(fingerprint_arg("ABCDEFGHIJKLMNOPQRS1").is_err());
        assert_eq!(optional_fingerprint(Some("  ")).unwrap(), None);
        assert_eq!(
            url_arg("coffre.exemple.fr").unwrap(),
            "hirzla://coffre.exemple.fr"
        );
        assert_eq!(url_arg(" hirzla://h:7443 ").unwrap(), "hirzla://h:7443");
        assert!(url_arg("").is_err());
        assert!(url_arg(&"a".repeat(MAX_SERVER_URL + 1)).is_err());
        assert_eq!(member_arg(&"0F".repeat(16)).unwrap(), [0x0f; 16]);
        assert_eq!(
            member_arg("0f0f0f0f-0f0f0f0f 0f0f0f0f-0f0f0f0f").unwrap(),
            [0x0f; 16]
        );
        assert!(member_arg("0f").is_err());
        assert!(locker_arg("zz").is_err());
        assert_eq!(device_arg(&"ab".repeat(16)).unwrap(), [0xab; 16]);
        assert!(device_arg("ab").is_err());
        assert!(locker_name_arg("  ").is_err());
        assert!(locker_name_arg(&"é".repeat(129)).is_err());
        assert_eq!(locker_name_arg(" Équipe ").unwrap().as_str(), "Équipe");
        assert!(serde_json::from_str::<RoleName>("\"admin\"").is_err());
        assert_eq!(
            serde_json::from_str::<RoleName>("\"blind_user\"").unwrap(),
            RoleName::BlindUser
        );
    }

    #[test]
    fn the_site_ca_must_be_a_small_pem_file() {
        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("ac.pem");
        std::fs::write(
            &ok,
            b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(read_ca(&ok).is_ok());
        let not_pem = dir.path().join("ac.der");
        std::fs::write(&not_pem, [0x30, 0x82, 0x01]).unwrap();
        assert!(read_ca(&not_pem).is_err());
        let big = dir.path().join("big.pem");
        let mut b = b"-----BEGIN CERTIFICATE-----\n".to_vec();
        b.resize(MAX_ROOTS + 1, b'A');
        std::fs::write(&big, b).unwrap();
        assert!(read_ca(&big).is_err());
        assert!(read_ca(&dir.path().join("absent.pem")).is_err());
    }

    #[test]
    fn members_and_key_log_are_given_by_stable_names() {
        let dto = members_dto(
            [1; 16],
            vec![MemberInfo {
                member: [1; 16],
                role: Role::Owner,
                devices: 2,
                fingerprint: "A".repeat(20),
                proven: true,
                change_to: vec![Role::Manager],
                change_refusal: None,
                remove_refusal: Some(Refusal::LastOwner),
                name: None,
                verified: true,
            }],
            &[Role::Editor, Role::Reader],
            None,
            Some(2),
        );
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["members"][0]["me"], true);
        assert_eq!(json["members"][0]["role"], "owner");
        assert_eq!(json["members"][0]["change_to"][0], "manager");
        assert_eq!(json["members"][0]["remove_refusal"], "last_owner");
        assert_eq!(json["grantable"][1], "reader");
        assert_eq!(json["quorum"], 2);
        let k: KeyLogDto = KeyLogStatus {
            suspect: Some(SuspectReason::SizeDecrease),
            entries: 4,
            alerts: vec![KeyLogAlert {
                kind: AlertKind::UnknownOwnDevice,
                index: Some(3),
                device: Some([0xab; 16]),
                locker: None,
            }],
        }
        .into();
        let json = serde_json::to_value(&k).unwrap();
        assert_eq!(json["suspect"], true);
        assert_eq!(json["reason"], "shorter");
        assert_eq!(json["alerts"][0]["kind"], "unknown_device");
        assert_eq!(json["alerts"][0]["device"], "ab".repeat(16));
    }

    #[test]
    fn governance_texts_and_identifiers_are_checked_before_the_core() {
        assert_eq!(
            text_arg(" hirzla-accord:ab\ncd ", "hirzla-accord:").unwrap(),
            "hirzla-accord:abcd"
        );
        assert!(text_arg("hirzla-demande:x", "hirzla-accord:").is_err());
        assert!(text_arg(&"a".repeat(MAX_TEXT + 1), "hirzla-accord:").is_err());
        assert_eq!(hex_id::<2>("0aFF").unwrap(), [0x0a, 0xff]);
        assert!(hex_id::<2>("0a").is_err());
        assert!(hex_id::<2>("zzzz").is_err());
        let q: QuorumStateDto = QuorumState {
            request: [1; 16],
            locker: [2; 16],
            action: QuorumAction::OwnerRoleChange,
            target: Some([3; 16]),
            detail: Some(Role::Editor.code()),
            counted: vec![[4; 16]],
            required: 2,
            offer: "hirzla-demande:x".into(),
            created_ms: 5,
        }
        .into();
        let json = serde_json::to_value(&q).unwrap();
        assert_eq!(json["action"], "owner_role_change");
        assert_eq!(json["role"], "editor");
        assert_eq!(json["quorum"], serde_json::Value::Null);
        let o: QuarantinedDto = QuarantinedOp {
            op_id: [9; 48],
            member: [1; 16],
            device: [2; 16],
            cause: 1,
            class: 1,
            wall_ms: None,
            title: Some(Zeroizing::new("Routeur".into())),
            secret: None,
            received_ms: 1,
            due_ms: 2,
        }
        .into();
        let json = serde_json::to_value(&o).unwrap();
        assert_eq!(json["cause"], "removal");
        assert_eq!(json["op_id"], "09".repeat(48));
    }
}
