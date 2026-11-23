//! What a device checks in the key log, and when (`transparence.md` § 6).
//!
//! The monitor replicates every entry, recomputes the root itself, checks the rules of a valid
//! log, watches the entries of its own member, answers « may I envelope a locker key for this
//! device », compares heads received from peers, and lists announced removals not received.
//! Once it has proof of inconsistency it becomes **suspect** for good: key distribution stops.

use std::collections::BTreeSet;

use hirzla_crypto::sign::VerifyingKey;
use hirzla_vault::cbor::{fixed, uint, uint_in, CborError, Fields, Value};
use hirzla_vault::model::{DeviceCert, Id16, MemberKeys, OpId};

use super::directory::{Directory, RuleViolation};
use super::entry::{
    device_cert_object, member_keys_object, EntryKind, KeyLogEntry, KeyLogHead, KeyLogProof,
};
use super::merkle::{self, Sha384};
use crate::control::verify_device_cert;
use crate::{AccessError, KeyLogFailure};

/// Why the log is inconsistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkReason {
    /// The recomputed root differs from the signed one.
    RootMismatch,
    /// A signed head is smaller than one already verified.
    SizeDecrease,
    /// An entry under a signed head breaks a rule of § 5.2.
    RuleViolation {
        /// Rank of the entry.
        index: u64,
        /// Rule.
        rule: RuleViolation,
    },
    /// A head from a peer does not match the local entries.
    PeerHead,
    /// A peer head is larger than what the server serves.
    Unserved,
    /// An entry of an inclusion proof differs from the local entry at the same rank.
    ProofEntry,
}

/// Proof that the server misbehaves: two incompatible signed heads, or a signed head and the
/// entries that contradict it. Kept and exportable for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkEvidence {
    /// The last head the device verified, if any.
    pub local: Option<KeyLogHead>,
    /// The head that contradicts it.
    pub other: KeyLogHead,
    /// Why.
    pub reason: ForkReason,
}

/// An alert about the device's own member (`transparence.md` § 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alert {
    /// A key inscribed for the member is not the member's key.
    ForeignMemberKey {
        /// Rank of the entry.
        index: u64,
    },
    /// A device unknown to the member is inscribed in its name.
    UnknownOwnDevice {
        /// Device.
        device: Id16,
        /// Rank of the entry.
        index: u64,
    },
    /// A revocation unknown to the member is inscribed in its name.
    UnknownOwnRevocation {
        /// Device.
        device: Id16,
        /// Rank of the entry.
        index: u64,
    },
    /// A profile (display name) this device did not issue is inscribed in the member's name
    /// (ADR 0069).
    UnknownOwnProfile {
        /// Rank of the entry.
        index: u64,
    },
}

/// Result of comparing a peer's head with the local log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerHead {
    /// The peer's head is a prefix of the local log, or equal to it.
    Consistent,
    /// The peer has seen more: update the log, then compare again.
    Ahead,
}

impl RuleViolation {
    fn code(self) -> u64 {
        match self {
            RuleViolation::Malformed => 1,
            RuleViolation::SecondMemberKey => 2,
            RuleViolation::UnknownMember => 3,
            RuleViolation::DeviceHistory => 4,
            RuleViolation::DuplicateRemoval => 5,
            RuleViolation::DuplicateProfile => 7,
        }
    }

    fn from_code(c: u64) -> Result<Self, CborError> {
        Ok(match c {
            1 => RuleViolation::Malformed,
            2 => RuleViolation::SecondMemberKey,
            3 => RuleViolation::UnknownMember,
            4 => RuleViolation::DeviceHistory,
            5 => RuleViolation::DuplicateRemoval,
            7 => RuleViolation::DuplicateProfile,
            _ => return Err(CborError::Malformed),
        })
    }
}

impl ForkEvidence {
    /// Canonical value, kept by the device (`format.md` § 15.2, ADR 0040):
    /// `{1: local (KeyLogHead)?, 2: other (KeyLogHead), 3: reason, 4: index?, 5: rule?}`,
    /// `reason` 1 root, 2 size decrease, 3 rule (with 4 and 5), 4 peer head, 5 unserved,
    /// 6 proof entry; `rule` 1 to 5 for R1 to R5, 7 for R7.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut e = Vec::new();
        if let Some(l) = &self.local {
            e.push((1, l.to_value()));
        }
        e.push((2, self.other.to_value()));
        let reason = match self.reason {
            ForkReason::RootMismatch => 1,
            ForkReason::SizeDecrease => 2,
            ForkReason::RuleViolation { .. } => 3,
            ForkReason::PeerHead => 4,
            ForkReason::Unserved => 5,
            ForkReason::ProofEntry => 6,
        };
        e.push((3, Value::Uint(reason)));
        if let ForkReason::RuleViolation { index, rule } = self.reason {
            e.push((4, Value::Uint(index)));
            e.push((5, Value::Uint(rule.code())));
        }
        Value::map(e)
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`] on any unknown key, wrong type or inconsistency.
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5])?;
        let reason = uint_in(f.req(3)?, 1..=6)?;
        let rule = (f.opt(4), f.opt(5));
        let reason = match (reason, rule) {
            (3, (Some(i), Some(r))) => ForkReason::RuleViolation {
                index: uint(i)?,
                rule: RuleViolation::from_code(uint(r)?)?,
            },
            (_, (Some(_), _) | (_, Some(_))) | (3, _) => return Err(CborError::Malformed),
            (1, _) => ForkReason::RootMismatch,
            (2, _) => ForkReason::SizeDecrease,
            (4, _) => ForkReason::PeerHead,
            (5, _) => ForkReason::Unserved,
            _ => ForkReason::ProofEntry,
        };
        Ok(ForkEvidence {
            local: f.opt(1).map(KeyLogHead::from_value).transpose()?,
            other: KeyLogHead::from_value(f.req(2)?)?,
            reason,
        })
    }
}

impl Alert {
    /// Canonical value, kept by the device (`format.md` § 15.2, ADR 0040):
    /// `{1: kind, 2: index, 3: device?}`, `kind` 1 foreign member key, 2 unknown own device,
    /// 3 unknown own revocation, 4 unknown own profile (ADR 0069).
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Alert::ForeignMemberKey { index } => {
                Value::map(vec![(1, Value::Uint(1)), (2, Value::Uint(*index))])
            }
            Alert::UnknownOwnDevice { device, index } => Value::map(vec![
                (1, Value::Uint(2)),
                (2, Value::Uint(*index)),
                (3, Value::bytes(device)),
            ]),
            Alert::UnknownOwnRevocation { device, index } => Value::map(vec![
                (1, Value::Uint(3)),
                (2, Value::Uint(*index)),
                (3, Value::bytes(device)),
            ]),
            Alert::UnknownOwnProfile { index } => {
                Value::map(vec![(1, Value::Uint(4)), (2, Value::Uint(*index))])
            }
        }
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`] on any unknown key, wrong type or inconsistency.
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3])?;
        let index = uint(f.req(2)?)?;
        let device = f.opt(3).map(fixed::<16>).transpose()?;
        Ok(match (uint_in(f.req(1)?, 1..=4)?, device) {
            (1, None) => Alert::ForeignMemberKey { index },
            (4, None) => Alert::UnknownOwnProfile { index },
            (2, Some(device)) => Alert::UnknownOwnDevice { device, index },
            (3, Some(device)) => Alert::UnknownOwnRevocation { device, index },
            _ => return Err(CborError::Malformed),
        })
    }
}

/// The key log as one device sees it.
#[derive(Debug, Clone)]
pub struct KeyLogMonitor {
    log_id: Id16,
    server_key: VerifyingKey,
    own: MemberKeys,
    own_object: [u8; 48],
    own_expected: BTreeSet<[u8; 48]>,
    entries: Vec<KeyLogEntry>,
    leaves: Vec<[u8; 48]>,
    directory: Directory,
    head: Option<KeyLogHead>,
    suspect: Option<ForkEvidence>,
}

impl KeyLogMonitor {
    /// A monitor with no entry yet, for the log `log_id` signed by the pinned `server_key`, on
    /// a device of the member `own`.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn new(
        log_id: Id16,
        server_key: VerifyingKey,
        own: MemberKeys,
    ) -> Result<Self, AccessError> {
        let own_object = member_keys_object(&own)?;
        Ok(KeyLogMonitor {
            log_id,
            server_key,
            own,
            own_object,
            own_expected: BTreeSet::new(),
            entries: Vec::new(),
            leaves: Vec::new(),
            directory: Directory::default(),
            head: None,
            suspect: None,
        })
    }

    /// Declares an object of the member that the device knows: a certificate of one of its
    /// devices (from the personal locker), a revocation or a profile it issued.
    pub fn expect_own(&mut self, object: [u8; 48]) {
        self.own_expected.insert(object);
    }

    /// Whether `cert` is a certificate of the member that the device knows (declared with
    /// [`KeyLogMonitor::expect_own_device`]).
    #[must_use]
    pub fn expects_own_device(&self, cert: &DeviceCert) -> bool {
        device_cert_object(cert).is_ok_and(|o| self.own_expected.contains(&o))
    }

    /// Declares one of the member's certificates.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn expect_own_device(&mut self, cert: &DeviceCert) -> Result<(), AccessError> {
        self.expect_own(device_cert_object(cert)?);
        Ok(())
    }

    /// Last verified head.
    #[must_use]
    pub fn head(&self) -> Option<&KeyLogHead> {
        self.head.as_ref()
    }

    /// Number of verified entries.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Verified entries.
    #[must_use]
    pub fn entries(&self) -> &[KeyLogEntry] {
        &self.entries
    }

    /// The directory of the verified entries.
    #[must_use]
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    /// Proof of inconsistency, if the log is suspect.
    #[must_use]
    pub fn suspect(&self) -> Option<&ForkEvidence> {
        self.suspect.as_ref()
    }

    /// Restores the proof of inconsistency kept by the device across a restart
    /// (`format.md` § 15.2): a suspect log never becomes sound again by itself
    /// (`transparence.md` § 6.7). The first proof kept wins.
    pub fn restore_suspect(&mut self, evidence: ForkEvidence) {
        if self.suspect.is_none() {
            self.suspect = Some(evidence);
        }
    }

    fn mark_suspect(&mut self, other: &KeyLogHead, reason: ForkReason) -> AccessError {
        if self.suspect.is_none() {
            self.suspect = Some(ForkEvidence {
                local: self.head.clone(),
                other: other.clone(),
                reason,
            });
        }
        AccessError::KeyLog(KeyLogFailure::Inconsistent)
    }

    fn not_suspect(&self) -> Result<(), AccessError> {
        if self.suspect.is_some() {
            Err(AccessError::KeyLog(KeyLogFailure::Suspect))
        } else {
            Ok(())
        }
    }

    /// Ingests a `KeyLogEntries` response (§ 6.1): `entries` from rank `start`, under `head`.
    /// Everything is checked before anything is kept. Returns the alerts about the device's
    /// own member.
    ///
    /// # Errors
    /// [`KeyLogFailure::BadHead`] or [`KeyLogFailure::BadResponse`] (transient, nothing kept);
    /// [`KeyLogFailure::Inconsistent`] (the log is now suspect); [`KeyLogFailure::Suspect`].
    pub fn ingest(
        &mut self,
        start: u64,
        entries: &[Vec<u8>],
        head: &KeyLogHead,
    ) -> Result<Vec<Alert>, AccessError> {
        self.not_suspect()?;
        head.verify(&self.server_key, &self.log_id)?;
        if let Some(prev) = &self.head {
            if head.size < prev.size {
                return Err(self.mark_suspect(head, ForkReason::SizeDecrease));
            }
        }
        if start != self.size() {
            return Err(AccessError::KeyLog(KeyLogFailure::BadResponse));
        }
        let total = self.size() + entries.len() as u64;
        if head.size != total {
            if head.size < self.size() {
                return Err(self.mark_suspect(head, ForkReason::SizeDecrease));
            }
            return Err(AccessError::KeyLog(KeyLogFailure::BadResponse));
        }
        let mut leaves = self.leaves.clone();
        leaves.extend(entries.iter().map(|e| merkle::leaf_hash::<Sha384>(e)));
        if merkle::root::<Sha384>(&leaves) != head.root {
            return Err(self.mark_suspect(head, ForkReason::RootMismatch));
        }
        // The new entries are now bound to a signed head: a malformed one is proof (R1).
        let mut directory = self.directory.clone();
        let mut decoded = Vec::with_capacity(entries.len());
        for (i, raw) in entries.iter().enumerate() {
            let index = self.size() + i as u64;
            let rule = match KeyLogEntry::decode(raw) {
                Ok(e) => directory.check(&e).map(|()| e),
                Err(_) => Err(RuleViolation::Malformed),
            };
            match rule {
                Ok(e) => {
                    directory.add(&e);
                    decoded.push(e);
                }
                Err(rule) => {
                    return Err(self.mark_suspect(head, ForkReason::RuleViolation { index, rule }))
                }
            }
        }
        let mut alerts = Vec::new();
        for (i, e) in decoded.iter().enumerate() {
            if e.member != self.own.member {
                continue;
            }
            let index = self.size() + i as u64;
            match (e.kind, e.device) {
                (EntryKind::MemberKey, _) if e.object != self.own_object => {
                    alerts.push(Alert::ForeignMemberKey { index });
                }
                (EntryKind::DeviceCert, Some(device)) if !self.own_expected.contains(&e.object) => {
                    alerts.push(Alert::UnknownOwnDevice { device, index });
                }
                (EntryKind::DeviceRevocation, Some(device))
                    if !self.own_expected.contains(&e.object) =>
                {
                    alerts.push(Alert::UnknownOwnRevocation { device, index });
                }
                (EntryKind::MemberProfile, _) if !self.own_expected.contains(&e.object) => {
                    alerts.push(Alert::UnknownOwnProfile { index });
                }
                _ => {}
            }
        }
        self.leaves = leaves;
        self.entries.extend(decoded);
        self.directory = directory;
        self.head = Some(head.clone());
        Ok(alerts)
    }

    /// May the device envelope a locker key for `cert`, a device of `keys` (§ 6.2)?
    ///
    /// The caller makes sure the log was updated less than an hour ago.
    ///
    /// # Errors
    /// [`KeyLogFailure::Suspect`], [`KeyLogFailure::NotInscribed`],
    /// [`KeyLogFailure::Substituted`], [`KeyLogFailure::Revoked`], or
    /// [`AccessError::InvalidSignature`] for a certificate not signed by the member key.
    pub fn check_recipient(&self, keys: &MemberKeys, cert: &DeviceCert) -> Result<(), AccessError> {
        self.not_suspect()?;
        let inscribed = self
            .directory
            .member_key(&keys.member)
            .ok_or(AccessError::KeyLog(KeyLogFailure::NotInscribed))?;
        if inscribed != member_keys_object(keys)? {
            return Err(AccessError::KeyLog(KeyLogFailure::Substituted));
        }
        let rec = self
            .directory
            .device(&cert.member, &cert.device)
            .ok_or(AccessError::KeyLog(KeyLogFailure::NotInscribed))?;
        if rec.cert != device_cert_object(cert)? {
            return Err(AccessError::KeyLog(KeyLogFailure::Substituted));
        }
        if rec.revocation.is_some() {
            return Err(AccessError::KeyLog(KeyLogFailure::Revoked));
        }
        verify_device_cert(cert, keys)
    }

    /// Compares a head received from a peer (§ 6.6). `fully_synced`: the device has just
    /// updated its log and the server answered `more = false`.
    ///
    /// # Errors
    /// [`KeyLogFailure::BadHead`] for a head the server did not sign;
    /// [`KeyLogFailure::Inconsistent`] when the heads prove a fork (the log becomes suspect).
    pub fn observe_peer_head(
        &mut self,
        head: &KeyLogHead,
        fully_synced: bool,
    ) -> Result<PeerHead, AccessError> {
        head.verify(&self.server_key, &self.log_id)?;
        let size = usize::try_from(head.size).unwrap_or(usize::MAX);
        if size <= self.leaves.len() {
            if merkle::root::<Sha384>(&self.leaves[..size]) == head.root {
                Ok(PeerHead::Consistent)
            } else {
                Err(self.mark_suspect(head, ForkReason::PeerHead))
            }
        } else if fully_synced {
            Err(self.mark_suspect(head, ForkReason::Unserved))
        } else {
            Ok(PeerHead::Ahead)
        }
    }

    /// Compares an inclusion proof received in an operation with the local log (§ 6.3, outside
    /// validity). The proof itself must already have been verified.
    ///
    /// # Errors
    /// As [`KeyLogMonitor::observe_peer_head`], and [`KeyLogFailure::Inconsistent`] when a
    /// proven entry differs from the local one.
    pub fn compare_proof(&mut self, proof: &KeyLogProof) -> Result<PeerHead, AccessError> {
        let verdict = self.observe_peer_head(&proof.head, false)?;
        for item in &proof.items {
            let local = usize::try_from(item.index)
                .ok()
                .and_then(|i| self.entries.get(i));
            if let Some(local) = local {
                if *local != item.entry {
                    return Err(self.mark_suspect(&proof.head, ForkReason::ProofEntry));
                }
            }
        }
        Ok(verdict)
    }

    /// Removals inscribed for `locker` whose `Revoke` the device has not received
    /// (§ 6.5). The caller applies the one-hour delay, then freezes its writes in the locker.
    #[must_use]
    pub fn missing_removals(
        &self,
        locker: &Id16,
        received: &dyn Fn(&OpId) -> bool,
    ) -> Vec<(OpId, Id16)> {
        self.directory
            .locker_removals(locker)
            .filter(|(op, _)| !received(op))
            .map(|(op, m)| (*op, *m))
            .collect()
    }

    /// Whether an object (certificate, revocation, `Revoke`) is inscribed.
    #[must_use]
    pub fn is_inscribed(&self, object: &[u8; 48]) -> bool {
        self.entries.iter().any(|e| e.object == *object)
    }

    /// Devices revoked in the log, with the hash of the revocation to fetch.
    pub fn revoked_devices(&self) -> impl Iterator<Item = (&(Id16, Id16), &[u8; 48])> {
        self.directory.revoked_devices()
    }
}
