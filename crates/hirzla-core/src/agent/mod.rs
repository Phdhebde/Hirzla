//! The machine member: the core of a Hornn agent gateway or rotation agent
//! (`docs/integration-hornn.md`, ADR 0031).
//!
//! A machine member is an ordinary member of the lockers it serves, with its own hybrid key
//! pairs. Its core holds a replica of each of these lockers and unseals a secret only for a
//! session grant signed by Hornn, addressed to it, fresh, never used, asked by a member whose
//! role allows the use. The member who asked (usually a `BlindUser`) never receives the
//! value: only the agent process connected to this core does, to open the session.
//!
//! - [`MachineMember`]: enrolment, replicas, sessions, rotation;
//! - [`rotation`]: the transport trait and the rotation target;
//! - [`proto`] and [`service`]: the agent operations of the local API (version 3, codes 20
//!   and up, `docs/api-locale.md` § 14).

pub mod proto;
pub mod rotation;
pub mod service;

use std::collections::BTreeMap;
use std::sync::Arc;

use hirzla_access::hornn::{
    agent_role_allows, requester_may_trigger, GrantRefusal, HornnTrust, Purpose, ReplayGuard,
    SessionGrant,
};
use hirzla_crypto::kem;
use hirzla_crypto::sign::{DeviceSigningKey, MemberSigningKey};
use hirzla_crypto::util::{random_array, sha384};
use hirzla_sync::replica::PendingReason;
use hirzla_sync::{AccessAuthorizer, LocalDevice, OpStatus, Replica, SyncError};
use hirzla_vault::cbor::{self, Value};
use hirzla_vault::model::{DeviceCert, Id16, MemberKeys, OpId};
use hirzla_vault::secret::{
    Field, FieldValue, SecretEdit, SecretState, SecretType, SetKind, SetValue,
};
use zeroize::Zeroizing;

use self::rotation::{RotationOutcome, RotationTransport, SshTarget, TransportError};

/// Most lockers a machine member serves.
pub const MAX_LOCKERS: usize = 256;
/// Length of a generated password, in characters.
pub const ROTATED_LENGTH: u32 = 32;

/// Errors of the machine member. None carries a secret or a detail of the grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AgentError {
    /// The grant is refused.
    #[error("grant refused: {0}")]
    Grant(GrantRefusal),
    /// The locker is not served by this agent.
    #[error("unknown locker")]
    UnknownLocker,
    /// The secret or a requested field is missing, or the secret is not usable for this.
    #[error("not found")]
    NotFound,
    /// The request is invalid.
    #[error("invalid input")]
    InvalidInput,
    /// The target refused the password change: nothing was published.
    #[error("transport refused")]
    Transport,
    /// The password was changed on the target but could not be published yet: it is kept
    /// in memory and published by [`MachineMember::publish_pending`].
    #[error("publication pending")]
    PublishPending,
    /// The sync layer failed (queue full, malformed operation, crypto).
    #[error("sync failure")]
    Sync,
    /// Internal failure (random generator, encoding).
    #[error("internal failure")]
    Internal,
}

impl From<GrantRefusal> for AgentError {
    fn from(r: GrantRefusal) -> Self {
        AgentError::Grant(r)
    }
}

impl From<SyncError> for AgentError {
    fn from(_: SyncError) -> Self {
        AgentError::Sync
    }
}

/// What the machine shows to be admitted in a locker: its public identity and its control
/// code (`sync-protocol.md` § 14). Public data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolment {
    /// Member identity (identifier and member key).
    pub member: MemberKeys,
    /// The certificate of its only device.
    pub cert: DeviceCert,
    /// 20 characters of `base32(SHA-384(CBOR({1: sig, 2: kem})))`, compared out of band.
    pub control_code: String,
}

impl Enrolment {
    /// Canonical encoding `{1: MemberKeys, 2: DeviceCert}`, handed to an owner who grants the
    /// machine its role.
    ///
    /// # Errors
    /// [`AgentError::Internal`].
    pub fn encode(&self) -> Result<Vec<u8>, AgentError> {
        let v = Value::map(vec![(1, self.member.to_value()), (2, self.cert.to_value())]);
        Ok(cbor::encode(&v).map_err(|_| AgentError::Internal)?.to_vec())
    }

    /// Strict decoding; checks that the certificate is signed by the member key and that the
    /// control code matches.
    ///
    /// # Errors
    /// [`AgentError::InvalidInput`].
    pub fn decode(bytes: &[u8]) -> Result<Enrolment, AgentError> {
        let bad = |_| AgentError::InvalidInput;
        let v = cbor::decode(bytes).map_err(bad)?;
        let f = cbor::Fields::new(&v, &[1, 2]).map_err(bad)?;
        let member = MemberKeys::from_value(f.req(1).map_err(bad)?).map_err(bad)?;
        let cert = DeviceCert::from_value(f.req(2).map_err(bad)?).map_err(bad)?;
        hirzla_sync::codec::verify_device_cert(&member, &cert)
            .map_err(|_| AgentError::InvalidInput)?;
        let control_code = control_code(&cert)?;
        Ok(Enrolment {
            member,
            cert,
            control_code,
        })
    }
}

fn internal<E>(_: E) -> AgentError {
    AgentError::Internal
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Control code of a device (`sync-protocol.md` § 14): the first 20 characters of the
/// RFC 4648 base32 of `SHA-384(CBOR({1: sig, 2: kem}))`. A display encoding, not a
/// cryptographic one: 100 bits of the hash.
///
/// # Errors
/// [`AgentError::Internal`].
pub fn control_code(cert: &DeviceCert) -> Result<String, AgentError> {
    let v = Value::map(vec![
        (1, Value::bytes(&cert.sig)),
        (2, Value::bytes(&cert.kem)),
    ]);
    let digest = sha384(&cbor::encode(&v).map_err(|_| AgentError::Internal)?);
    let mut out = String::with_capacity(20);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in digest {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 && out.len() < 20 {
            bits -= 5;
            out.push(char::from(BASE32[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
        if out.len() == 20 {
            break;
        }
    }
    Ok(out)
}

/// Generates the machine's identity: a member key, a device with its own signing and
/// establishment pairs, the certificate of the device. The member key is **dropped** after
/// certifying the device (ADR 0031): a machine never enrols a second device, and its removal
/// is a `Revoke` by an owner, which needs no member key.
///
/// # Errors
/// [`AgentError::Internal`].
pub fn enrol(issued_ms: u64) -> Result<(Arc<LocalDevice>, Enrolment), AgentError> {
    let member_key = MemberSigningKey::generate().map_err(internal)?;
    let member = MemberKeys {
        member: random_array().map_err(internal)?,
        sig: member_key.verifying_key().as_bytes().to_vec(),
    };
    let sign = DeviceSigningKey::generate().map_err(internal)?;
    let kem = kem::PrivateKey::generate().map_err(internal)?;
    let mut cert = DeviceCert {
        member: member.member,
        device: random_array().map_err(internal)?,
        sig: sign.verifying_key().as_bytes().to_vec(),
        kem: kem.public_key().as_bytes().to_vec(),
        issued_ms,
        issuer_sig: Vec::new(),
    };
    cert.issuer_sig = member_key
        .certify_device(&cert.body().map_err(internal)?)
        .map_err(internal)?
        .as_bytes()
        .to_vec();
    drop(member_key);
    let device = LocalDevice::new(member.clone(), cert.clone(), sign, kem).map_err(internal)?;
    let control_code = control_code(&cert)?;
    Ok((
        Arc::new(device),
        Enrolment {
            member,
            cert,
            control_code,
        },
    ))
}

/// Credentials unsealed for one session. Neither `Debug` nor `Clone`; erased on drop.
pub struct SessionCredentials {
    /// The fields named by the grant, in the grant's order.
    pub fields: Vec<(Field, Zeroizing<String>)>,
    /// URLs of the secret (not secret), for the gateway to check its target against.
    pub urls: Vec<Zeroizing<String>>,
    /// SSH hosts of the secret (not secret).
    pub hosts: Vec<Zeroizing<String>>,
}

type R = Replica<AccessAuthorizer>;

fn system_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The core of a machine member.
pub struct MachineMember {
    device: Arc<LocalDevice>,
    replicas: BTreeMap<Id16, R>,
    trust: HornnTrust,
    guard: ReplayGuard,
    started_ms: u64,
    clock: fn() -> u64,
    /// New passwords set on their target but not published yet, by `(locker, secret)`.
    pending: BTreeMap<(Id16, Id16), Zeroizing<String>>,
}

impl MachineMember {
    /// A machine member with its device and Hornn's pinned identity. `started_ms` is the
    /// start of the core: grants issued before it are refused (their single use cannot be
    /// proven after a restart).
    #[must_use]
    pub fn new(device: Arc<LocalDevice>, trust: HornnTrust, started_ms: u64) -> MachineMember {
        MachineMember {
            device,
            replicas: BTreeMap::new(),
            trust,
            guard: ReplayGuard::new(),
            started_ms,
            clock: system_ms,
            pending: BTreeMap::new(),
        }
    }

    /// Replaces the wall clock (tests), here and in the replicas.
    pub fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
        for r in self.replicas.values_mut() {
            r.set_clock(clock);
        }
    }

    /// The device.
    #[must_use]
    pub fn device(&self) -> &LocalDevice {
        &self.device
    }

    /// Start time of the core, milliseconds.
    #[must_use]
    pub fn started_ms(&self) -> u64 {
        self.started_ms
    }

    /// Hornn's pinned issuer.
    #[must_use]
    pub fn issuer(&self) -> Id16 {
        self.trust.issuer()
    }

    /// Lockers served.
    #[must_use]
    pub fn lockers(&self) -> Vec<Id16> {
        self.replicas.keys().copied().collect()
    }

    /// The replica of a locker.
    #[must_use]
    pub fn replica(&self, locker: &Id16) -> Option<&R> {
        self.replicas.get(locker)
    }

    /// Starts serving a locker the machine was admitted to. Idempotent.
    ///
    /// # Errors
    /// [`AgentError::InvalidInput`] beyond [`MAX_LOCKERS`].
    pub fn join(&mut self, locker: Id16, genesis: Option<OpId>) -> Result<(), AgentError> {
        if self.replicas.contains_key(&locker) {
            return Ok(());
        }
        if self.replicas.len() >= MAX_LOCKERS {
            return Err(AgentError::InvalidInput);
        }
        let mut r = R::join(Arc::clone(&self.device), AccessAuthorizer, locker, genesis);
        r.set_clock(self.clock);
        self.replicas.insert(locker, r);
        Ok(())
    }

    /// Receives encoded operations of a locker (from the relay, through the agent process).
    /// Then publishes pending rotations if the locker allows it again.
    ///
    /// # Errors
    /// [`AgentError::UnknownLocker`] or [`AgentError::Sync`].
    pub fn ingest(
        &mut self,
        locker: &Id16,
        ops: Vec<Vec<u8>>,
    ) -> Result<hirzla_sync::replica::IngestReport, AgentError> {
        let r = self
            .replicas
            .get_mut(locker)
            .ok_or(AgentError::UnknownLocker)?;
        let report = r.ingest(ops)?;
        let _ = self.publish_pending();
        Ok(report)
    }

    /// Operations of a locker not yet sent to the relay.
    ///
    /// # Errors
    /// [`AgentError::UnknownLocker`].
    pub fn outbox(&self, locker: &Id16) -> Result<Vec<(OpId, Vec<u8>)>, AgentError> {
        Ok(self
            .replicas
            .get(locker)
            .ok_or(AgentError::UnknownLocker)?
            .unsent())
    }

    /// Marks operations as accepted by the relay.
    ///
    /// # Errors
    /// [`AgentError::UnknownLocker`].
    pub fn ack(&mut self, locker: &Id16, ops: &[OpId]) -> Result<(), AgentError> {
        self.replicas
            .get_mut(locker)
            .ok_or(AgentError::UnknownLocker)?
            .mark_sent(ops);
        Ok(())
    }

    /// Every check of a grant, in this order: signature (both halves) and issuer, purpose,
    /// recipient, time, locker served, roles of the agent and of the requester in the
    /// current authorisation state, secret active. Single use is consumed last, by the
    /// caller, right before unsealing.
    fn authorize(&self, signed: &[u8], purpose: Purpose) -> Result<SessionGrant, AgentError> {
        let g = self.trust.verify(signed)?;
        if g.purpose != purpose {
            return Err(AgentError::Grant(GrantRefusal::Malformed));
        }
        g.check_recipient(&self.device.member_id(), &self.device.device_id())?;
        g.check_time((self.clock)(), self.started_ms)?;
        let r = self
            .replicas
            .get(&g.locker)
            .ok_or(AgentError::Grant(GrantRefusal::Unknown))?;
        let state = r
            .authorization()
            .ok_or(AgentError::Grant(GrantRefusal::Unknown))?
            .access()
            .state();
        let me = self.device.member_id();
        // An operation this device cannot open waits for a key it lacks: most likely an
        // epoch created by the removal of this machine, whose sealed part it can never read,
        // so its replica would keep seeing itself as a member. Fail closed (ADR 0031).
        let missing_key = r
            .statuses()
            .values()
            .any(|s| *s == OpStatus::Pending(PendingReason::MissingKey));
        if missing_key
            || state.active_device(&me, &self.device.device_id()).is_none()
            || !agent_role_allows(state.role(&me), purpose)
        {
            return Err(AgentError::Grant(GrantRefusal::AgentRole));
        }
        if g.requester == me || !requester_may_trigger(state.role(&g.requester)) {
            return Err(AgentError::Grant(GrantRefusal::Requester));
        }
        match r.secret(&g.secret) {
            Some(v) if v.merged.state.0 == SecretState::Active => Ok(g),
            _ => Err(AgentError::Grant(GrantRefusal::Unknown)),
        }
    }

    /// Opens a session: checks the grant, consumes it, and unseals the fields it names.
    ///
    /// # Errors
    /// [`AgentError::Grant`] for any refused check, [`AgentError::NotFound`] if a field is
    /// missing or not textual (the grant is consumed then: it was valid).
    pub fn open_session(&mut self, signed: &[u8]) -> Result<SessionCredentials, AgentError> {
        let g = self.authorize(signed, Purpose::Session)?;
        self.guard.consume(&g, (self.clock)())?;
        let v = self
            .replicas
            .get(&g.locker)
            .and_then(|r| r.secret(&g.secret))
            .ok_or(AgentError::NotFound)?;
        let mut fields = Vec::with_capacity(g.fields.len());
        for f in &g.fields {
            match v.merged.fields.get(f).map(|e| &e.value) {
                Some(FieldValue::Text(t)) => fields.push((*f, Zeroizing::new(t.to_string()))),
                _ => return Err(AgentError::NotFound),
            }
        }
        let texts = |kind| -> Vec<Zeroizing<String>> {
            v.merged
                .sets
                .get(&kind)
                .map(|s| {
                    s.visible()
                        .filter_map(|x| match x {
                            SetValue::Text(t) => Some(Zeroizing::new(t.to_string())),
                            SetValue::Attachment(_) => None,
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        Ok(SessionCredentials {
            fields,
            urls: texts(SetKind::Urls),
            hosts: texts(SetKind::Hosts),
        })
    }

    /// Rotates a password: checks the grant (purpose rotation, agent `Editor`), reads the
    /// target from the secret, generates a new password, has `transport` change it on the
    /// target, then publishes it as an ordinary `SecretPut`.
    ///
    /// # Errors
    /// [`AgentError::Grant`]; [`AgentError::NotFound`] if the secret is not a password with a
    /// user name and exactly one `ssh://` URL; [`AgentError::Transport`] if the target refused
    /// (nothing published); [`AgentError::PublishPending`] if the change succeeded but the
    /// publication must wait.
    pub fn rotate(
        &mut self,
        signed: &[u8],
        transport: &mut dyn RotationTransport,
    ) -> Result<RotationOutcome, AgentError> {
        let g = self.authorize(signed, Purpose::Rotation)?;
        if self.pending.contains_key(&(g.locker, g.secret)) {
            // A previous change is not published yet: the vault does not hold the password
            // the target expects.
            return Err(AgentError::PublishPending);
        }
        let (target, username, current) = self.rotation_inputs(&g)?;
        let new = crate::generator::generate(ROTATED_LENGTH, crate::proto::classes::ALL)
            .map_err(|_| AgentError::Internal)?;
        self.guard.consume(&g, (self.clock)())?;
        let confirmed = match transport.change_password(&target, &username, &current, &new) {
            Ok(()) => true,
            Err(TransportError::Indeterminate) => false,
            Err(TransportError::Refused) => return Err(AgentError::Transport),
        };
        self.pending.insert((g.locker, g.secret), new);
        let op = self.publish_one(g.locker, g.secret)?;
        Ok(RotationOutcome { op, confirmed })
    }

    /// Target, user name and current password of a rotation, read from the secret; checks
    /// that the agent can publish before anything changes on the target.
    fn rotation_inputs(
        &self,
        g: &SessionGrant,
    ) -> Result<(SshTarget, Zeroizing<String>, Zeroizing<String>), AgentError> {
        let r = self.replicas.get(&g.locker).ok_or(AgentError::NotFound)?;
        let v = r.secret(&g.secret).ok_or(AgentError::NotFound)?;
        if v.merged.secret_type != SecretType::Password {
            return Err(AgentError::NotFound);
        }
        let text = |f| match v.merged.fields.get(&f).map(|e| &e.value) {
            Some(FieldValue::Text(t)) => Some(Zeroizing::new(t.to_string())),
            _ => None,
        };
        let username = text(Field::Username).ok_or(AgentError::NotFound)?;
        let current = text(Field::Password).ok_or(AgentError::NotFound)?;
        let mut targets = v
            .merged
            .sets
            .get(&SetKind::Urls)
            .into_iter()
            .flat_map(|s| s.visible())
            .filter_map(|x| match x {
                SetValue::Text(t) if t.starts_with("ssh://") => {
                    Some(SshTarget::parse(t, &username))
                }
                _ => None,
            });
        let target = match (targets.next(), targets.next()) {
            (Some(Some(t)), None) => t,
            _ => return Err(AgentError::NotFound),
        };
        if r.writes_frozen() || r.current_epoch().is_none() {
            return Err(AgentError::Sync);
        }
        Ok((target, username, current))
    }

    fn publish_one(&mut self, locker: Id16, secret: Id16) -> Result<OpId, AgentError> {
        let new = self
            .pending
            .get(&(locker, secret))
            .ok_or(AgentError::NotFound)?;
        let r = self.replicas.get_mut(&locker).ok_or(AgentError::NotFound)?;
        let edit = SecretEdit {
            set: vec![(Field::Password, FieldValue::text(new))],
            ..SecretEdit::default()
        };
        match r.put_secret(Some(secret), SecretType::Password, edit) {
            Ok((_, op)) => {
                self.pending.remove(&(locker, secret));
                Ok(op)
            }
            Err(_) => Err(AgentError::PublishPending),
        }
    }

    /// Publishes the rotations whose publication failed. Returns how many remain.
    pub fn publish_pending(&mut self) -> usize {
        let keys: Vec<(Id16, Id16)> = self.pending.keys().copied().collect();
        for (l, s) in keys {
            let _ = self.publish_one(l, s);
        }
        self.pending.len()
    }
}

#[cfg(test)]
mod tests;
