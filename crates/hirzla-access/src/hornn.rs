//! Session grants signed by the Hornn control plane (`docs/integration-hornn.md`).
//!
//! The agent gateway of Hornn is a machine member of the lockers it serves. Before its core
//! unseals anything for a session or a rotation, it requires a **session grant** signed by
//! Hornn with a hybrid key (ECDSA P-384 + ML-DSA-87, domain `hirzla/v1/hornn-session-grant`).
//! This module holds the format, the signature check, the time and recipient checks, the
//! single-use guard and the role rules of `BlindUser` use. It performs no I/O and holds no
//! secret: `hirzla-core` glues it to the replicas.
//!
//! | Item | Content |
//! | --- | --- |
//! | [`SessionGrant`] | The signed body, canonical CBOR |
//! | [`HornnTrust`] | Hornn's pinned identity and key; verifies a [`SignedGrant`] |
//! | [`ReplayGuard`] | Single use of each `grant_id`, fail closed |
//! | [`requester_may_trigger`], [`agent_role_allows`] | Role rules (`docs/roles.md`) |

use std::collections::BTreeMap;

use hirzla_crypto::sign::{Domain, HornnDomain, HornnSigningKey, Signature, VerifyingKey};
use hirzla_vault::cbor::{self, array_max, fixed, uint, uint_in, Fields, Value};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::Field;

use crate::Role;

/// Version of the grant format.
pub const GRANT_VERSION: u64 = 1;
/// Longest lifetime of a grant (`expires_ms - issued_ms`), in milliseconds.
pub const MAX_LIFETIME_MS: u64 = 60_000;
/// Clock skew tolerated between Hornn and the agent, in milliseconds.
pub const MAX_SKEW_MS: u64 = 5_000;
/// Largest encoded grant body, in bytes.
pub const MAX_BODY_LEN: usize = 1024;
/// Largest encoded signed grant, in bytes.
pub const MAX_SIGNED_LEN: usize = 8 * 1024;
/// Most grants remembered at once by a [`ReplayGuard`].
pub const MAX_REMEMBERED: usize = 4096;

/// What the grant allows the agent to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// 1: open a session for the requester; the agent unseals the fields named in the grant.
    Session,
    /// 2: rotate the password on the target at the end of a session.
    Rotation,
}

impl Purpose {
    /// Code on the wire.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Purpose::Session => 1,
            Purpose::Rotation => 2,
        }
    }

    /// Purpose of a wire code.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Purpose> {
        match code {
            1 => Some(Purpose::Session),
            2 => Some(Purpose::Rotation),
            _ => None,
        }
    }
}

/// Fields a session grant may name: the textual credentials of a password or SSH key secret.
pub const GRANT_FIELDS: [Field; 3] = [Field::Username, Field::Password, Field::SshPassphrase];

/// Why a grant is refused. Carries no detail of the grant: the core logs the variant only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum GrantRefusal {
    /// Not in the canonical form, or out of bounds.
    #[error("malformed grant")]
    Malformed,
    /// The hybrid signature does not verify (either half).
    #[error("invalid grant signature")]
    BadSignature,
    /// Issued by another Hornn instance than the pinned one.
    #[error("unexpected issuer")]
    WrongIssuer,
    /// Addressed to another agent (member or device).
    #[error("grant for another agent")]
    WrongAgent,
    /// Issued in the future beyond the tolerated skew.
    #[error("grant not yet valid")]
    NotYetValid,
    /// Expired.
    #[error("grant expired")]
    Expired,
    /// The lifetime exceeds [`MAX_LIFETIME_MS`], or ends before it starts.
    #[error("grant lifetime refused")]
    Lifetime,
    /// Issued before the core started: its single use cannot be proven.
    #[error("grant older than the core")]
    BeforeStart,
    /// Already used.
    #[error("grant already used")]
    Replayed,
    /// Too many live grants remembered: refused rather than forgotten.
    #[error("too many live grants")]
    GuardFull,
    /// The requester holds no role that allows a use of the secret.
    #[error("requester not allowed")]
    Requester,
    /// The agent's own role does not allow this purpose.
    #[error("agent role does not allow this")]
    AgentRole,
    /// The locker or the secret is unknown to the agent, or unusable.
    #[error("unknown locker or secret")]
    Unknown,
}

impl GrantRefusal {
    /// Reason code returned to the agent process (`docs/api-locale.md` § 14.3).
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            GrantRefusal::Malformed => 1,
            GrantRefusal::BadSignature => 2,
            GrantRefusal::WrongIssuer => 3,
            GrantRefusal::WrongAgent => 4,
            GrantRefusal::NotYetValid => 5,
            GrantRefusal::Expired => 6,
            GrantRefusal::Lifetime => 7,
            GrantRefusal::BeforeStart => 8,
            GrantRefusal::Replayed => 9,
            GrantRefusal::GuardFull => 10,
            GrantRefusal::Requester => 11,
            GrantRefusal::AgentRole => 12,
            GrantRefusal::Unknown => 13,
        }
    }

    /// Stable short name, for logs: lower-case letters and underscores.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            GrantRefusal::Malformed => "malformed",
            GrantRefusal::BadSignature => "bad_signature",
            GrantRefusal::WrongIssuer => "wrong_issuer",
            GrantRefusal::WrongAgent => "wrong_agent",
            GrantRefusal::NotYetValid => "not_yet_valid",
            GrantRefusal::Expired => "expired",
            GrantRefusal::Lifetime => "lifetime",
            GrantRefusal::BeforeStart => "before_start",
            GrantRefusal::Replayed => "replayed",
            GrantRefusal::GuardFull => "guard_full",
            GrantRefusal::Requester => "requester",
            GrantRefusal::AgentRole => "agent_role",
            GrantRefusal::Unknown => "unknown",
        }
    }
}

/// The body Hornn signs (`docs/integration-hornn.md` § 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionGrant {
    /// Random, 16 bytes, unique: the single-use token (`jti` of Hornn's current grants).
    pub grant_id: Id16,
    /// The Hornn instance (tenant) that issues the grant, pinned by the agent.
    pub issuer: Id16,
    /// The Hirzla member of the agent gateway.
    pub agent_member: Id16,
    /// The Hirzla device of the agent gateway.
    pub agent_device: Id16,
    /// Locker of the secret.
    pub locker: Id16,
    /// The secret.
    pub secret: Id16,
    /// The Hirzla member who asked for the session (usually a `BlindUser`).
    pub requester: Id16,
    /// What is allowed.
    pub purpose: Purpose,
    /// Issue time, milliseconds since the Unix epoch, Hornn's clock.
    pub issued_ms: u64,
    /// Expiry, milliseconds since the Unix epoch.
    pub expires_ms: u64,
    /// Fields to unseal for a session: sorted, without duplicate, among [`GRANT_FIELDS`].
    /// Empty for a rotation.
    pub fields: Vec<Field>,
}

impl SessionGrant {
    /// Canonical encoding: the bytes signed after `"hirzla/v1/hornn-session-grant" ‖ 0x00`.
    ///
    /// # Errors
    /// [`GrantRefusal::Malformed`] if the grant breaks a rule of the format.
    pub fn encode(&self) -> Result<Vec<u8>, GrantRefusal> {
        self.check_shape()?;
        let v = Value::map(vec![
            (1, Value::Uint(GRANT_VERSION)),
            (2, Value::bytes(&self.grant_id)),
            (3, Value::bytes(&self.issuer)),
            (4, Value::bytes(&self.agent_member)),
            (5, Value::bytes(&self.agent_device)),
            (6, Value::bytes(&self.locker)),
            (7, Value::bytes(&self.secret)),
            (8, Value::bytes(&self.requester)),
            (9, Value::Uint(self.purpose.code())),
            (10, Value::Uint(self.issued_ms)),
            (11, Value::Uint(self.expires_ms)),
            (
                12,
                Value::Array(self.fields.iter().map(|f| Value::Uint(*f as u64)).collect()),
            ),
        ]);
        Ok(cbor::encode(&v)
            .map_err(|_| GrantRefusal::Malformed)?
            .to_vec())
    }

    /// Strict decoding of a body: unknown key, wrong type, non-canonical encoding, unknown
    /// field or purpose, unsorted or duplicate fields are refused.
    ///
    /// # Errors
    /// [`GrantRefusal::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<SessionGrant, GrantRefusal> {
        let bad = |_| GrantRefusal::Malformed;
        if bytes.len() > MAX_BODY_LEN {
            return Err(GrantRefusal::Malformed);
        }
        let v = cbor::decode(bytes).map_err(bad)?;
        let f = Fields::new(&v, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]).map_err(bad)?;
        if f.req(1)
            .and_then(|v| uint_in(v, GRANT_VERSION..=GRANT_VERSION))
            .is_err()
        {
            return Err(GrantRefusal::Malformed);
        }
        let id = |k| f.req(k).and_then(fixed::<16>).map_err(bad);
        let purpose = Purpose::from_code(f.req(9).and_then(uint).map_err(bad)?)
            .ok_or(GrantRefusal::Malformed)?;
        let mut fields = Vec::new();
        for item in f
            .req(12)
            .and_then(|v| array_max(v, GRANT_FIELDS.len()))
            .map_err(bad)?
        {
            let code = uint(item).map_err(bad)?;
            let field = GRANT_FIELDS
                .into_iter()
                .find(|g| *g as u64 == code)
                .ok_or(GrantRefusal::Malformed)?;
            fields.push(field);
        }
        let g = SessionGrant {
            grant_id: id(2)?,
            issuer: id(3)?,
            agent_member: id(4)?,
            agent_device: id(5)?,
            locker: id(6)?,
            secret: id(7)?,
            requester: id(8)?,
            purpose,
            issued_ms: f.req(10).and_then(uint).map_err(bad)?,
            expires_ms: f.req(11).and_then(uint).map_err(bad)?,
            fields,
        };
        g.check_shape()?;
        Ok(g)
    }

    /// Rules of the format that do not depend on time or on the agent.
    fn check_shape(&self) -> Result<(), GrantRefusal> {
        let sorted = self
            .fields
            .windows(2)
            .all(|w| (w[0] as u64) < (w[1] as u64));
        let allowed = self.fields.iter().all(|f| GRANT_FIELDS.contains(f));
        let fields_ok = match self.purpose {
            Purpose::Session => !self.fields.is_empty(),
            Purpose::Rotation => self.fields.is_empty(),
        };
        if sorted && allowed && fields_ok {
            Ok(())
        } else {
            Err(GrantRefusal::Malformed)
        }
    }

    /// Signs the grant with Hornn's key: what the control plane does (reference for Hornn,
    /// and the tests). Returns the encoded [`SignedGrant`].
    ///
    /// # Errors
    /// [`GrantRefusal::Malformed`] if the grant breaks the format or signing fails.
    pub fn sign(&self, key: &HornnSigningKey) -> Result<Vec<u8>, GrantRefusal> {
        let body = self.encode()?;
        let sig = key
            .sign(HornnDomain::SessionGrant, &body)
            .map_err(|_| GrantRefusal::Malformed)?;
        SignedGrant { body, sig }.encode()
    }

    /// Time checks: lifetime at most [`MAX_LIFETIME_MS`], issued at most [`MAX_SKEW_MS`] in
    /// the future, not expired (with the same tolerance), and issued strictly more than
    /// [`MAX_SKEW_MS`] after `not_before_ms`, the start of the core. A core that stopped
    /// before `not_before_ms` only accepted grants issued at most [`MAX_SKEW_MS`] after its
    /// own clock: none of those passes here, so a grant consumed before a restart (which
    /// the [`ReplayGuard`] has forgotten) can never be used again. The price: for
    /// [`MAX_SKEW_MS`] after a start, every grant is refused.
    ///
    /// # Errors
    /// [`GrantRefusal::Lifetime`], [`GrantRefusal::NotYetValid`], [`GrantRefusal::Expired`]
    /// or [`GrantRefusal::BeforeStart`].
    pub fn check_time(&self, now_ms: u64, not_before_ms: u64) -> Result<(), GrantRefusal> {
        let life = self
            .expires_ms
            .checked_sub(self.issued_ms)
            .ok_or(GrantRefusal::Lifetime)?;
        if life == 0 || life > MAX_LIFETIME_MS {
            return Err(GrantRefusal::Lifetime);
        }
        if self.issued_ms > now_ms.saturating_add(MAX_SKEW_MS) {
            return Err(GrantRefusal::NotYetValid);
        }
        if now_ms >= self.expires_ms.saturating_add(MAX_SKEW_MS) {
            return Err(GrantRefusal::Expired);
        }
        if self.issued_ms <= not_before_ms.saturating_add(MAX_SKEW_MS) {
            return Err(GrantRefusal::BeforeStart);
        }
        Ok(())
    }

    /// The grant must name this agent, member and device.
    ///
    /// # Errors
    /// [`GrantRefusal::WrongAgent`].
    pub fn check_recipient(&self, member: &Id16, device: &Id16) -> Result<(), GrantRefusal> {
        if self.agent_member == *member && self.agent_device == *device {
            Ok(())
        } else {
            Err(GrantRefusal::WrongAgent)
        }
    }
}

/// A grant and Hornn's hybrid signature over its body: `{1: body, 2: sig}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedGrant {
    /// Encoded [`SessionGrant`], as signed.
    pub body: Vec<u8>,
    /// Hybrid signature.
    pub sig: Signature,
}

impl SignedGrant {
    /// Canonical encoding.
    ///
    /// # Errors
    /// [`GrantRefusal::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, GrantRefusal> {
        let v = Value::map(vec![
            (1, Value::bytes(&self.body)),
            (2, Value::bytes(self.sig.as_bytes())),
        ]);
        Ok(cbor::encode(&v)
            .map_err(|_| GrantRefusal::Malformed)?
            .to_vec())
    }

    /// Strict decoding. The body is not decoded here: it is only read once the signature
    /// verifies.
    ///
    /// # Errors
    /// [`GrantRefusal::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<SignedGrant, GrantRefusal> {
        let bad = |_| GrantRefusal::Malformed;
        if bytes.len() > MAX_SIGNED_LEN {
            return Err(GrantRefusal::Malformed);
        }
        let v = cbor::decode(bytes).map_err(bad)?;
        let f = Fields::new(&v, &[1, 2]).map_err(bad)?;
        let body = cbor::bytes_max(f.req(1).map_err(bad)?, MAX_BODY_LEN)
            .map_err(bad)?
            .to_vec();
        let sig = cbor::bytes_max(f.req(2).map_err(bad)?, MAX_SIGNED_LEN).map_err(bad)?;
        let sig = Signature::from_bytes(sig).map_err(|_| GrantRefusal::Malformed)?;
        Ok(SignedGrant { body, sig })
    }
}

/// Hornn's identity as the agent pins it at installation: the issuer identifier and the
/// hybrid verification key of the control plane.
#[derive(Debug, Clone)]
pub struct HornnTrust {
    issuer: Id16,
    key: VerifyingKey,
}

impl HornnTrust {
    /// Pins an issuer and its encoded hybrid key (`docs/format.md` § 3.1 layout).
    ///
    /// # Errors
    /// [`GrantRefusal::Malformed`] if the key does not parse.
    pub fn new(issuer: Id16, key: &[u8]) -> Result<HornnTrust, GrantRefusal> {
        let key = VerifyingKey::from_bytes(key).map_err(|_| GrantRefusal::Malformed)?;
        Ok(HornnTrust { issuer, key })
    }

    /// The pinned issuer.
    #[must_use]
    pub fn issuer(&self) -> Id16 {
        self.issuer
    }

    /// Verifies the hybrid signature (both halves), then decodes the body and checks the
    /// issuer. Time, recipient, single use and roles are checked by the caller.
    ///
    /// # Errors
    /// [`GrantRefusal::Malformed`], [`GrantRefusal::BadSignature`] or
    /// [`GrantRefusal::WrongIssuer`].
    pub fn verify(&self, signed: &[u8]) -> Result<SessionGrant, GrantRefusal> {
        let s = SignedGrant::decode(signed)?;
        self.key
            .verify(Domain::HornnSessionGrant, &s.body, &s.sig)
            .map_err(|_| GrantRefusal::BadSignature)?;
        let g = SessionGrant::decode(&s.body)?;
        if g.issuer != self.issuer {
            return Err(GrantRefusal::WrongIssuer);
        }
        Ok(g)
    }
}

/// Single use of grants: remembers each consumed `grant_id` until its expiry (plus the
/// skew). When full, refuses new grants rather than forgetting a live one.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    seen: BTreeMap<Id16, u64>,
}

impl ReplayGuard {
    /// An empty guard.
    #[must_use]
    pub fn new() -> ReplayGuard {
        ReplayGuard::default()
    }

    /// Consumes `grant`. Call it once every other check passed, right before unsealing, so
    /// that a refused grant does not burn its identifier.
    ///
    /// # Errors
    /// [`GrantRefusal::Replayed`] or [`GrantRefusal::GuardFull`].
    pub fn consume(&mut self, grant: &SessionGrant, now_ms: u64) -> Result<(), GrantRefusal> {
        self.seen.retain(|_, until| *until > now_ms);
        if self.seen.contains_key(&grant.grant_id) {
            return Err(GrantRefusal::Replayed);
        }
        if self.seen.len() >= MAX_REMEMBERED {
            return Err(GrantRefusal::GuardFull);
        }
        self.seen
            .insert(grant.grant_id, grant.expires_ms.saturating_add(MAX_SKEW_MS));
        Ok(())
    }

    /// Grants currently remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether no grant is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Whether a member holding `role` in the locker may ask Hornn for a use of its secrets.
/// `BlindUser` is the intended role (`docs/roles.md`); the reading roles may also, since they
/// could read the value anyway. `Auditor` and non-members may not.
#[must_use]
pub fn requester_may_trigger(role: Option<Role>) -> bool {
    matches!(
        role,
        Some(Role::BlindUser | Role::Reader | Role::Editor | Role::Manager | Role::Owner)
    )
}

/// Whether a machine member holding `role` may act for `purpose`. A machine member holds a
/// role limited to its lockers (ADR 0031): `Reader` (session) or `Editor` (session and
/// rotation). A machine that holds `Owner` or `Manager` is refused: it could share or manage
/// the locker, which no agent needs.
#[must_use]
pub fn agent_role_allows(role: Option<Role>, purpose: Purpose) -> bool {
    match purpose {
        Purpose::Session => matches!(role, Some(Role::Reader | Role::Editor)),
        Purpose::Rotation => matches!(role, Some(Role::Editor)),
    }
}

#[cfg(test)]
mod tests;
