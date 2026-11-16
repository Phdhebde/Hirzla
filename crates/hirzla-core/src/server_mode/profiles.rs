//! Display names of members (ADR 0069, `docs/api-locale.md` § 15.9, `transparence.md` § 6.8).
//!
//! - A name is what the holder of a member key calls itself: a `MemberProfile` signed by that
//!   key inside `hirzla-vault` and inscribed in the key log (entry of kind 6).
//! - A name is shown only once this device checked the whole chain itself: the profile is the
//!   current one of the member in the local key log, the member key is the inscribed one, the
//!   signature holds and the rank does not go back. Otherwise no name: never an unverified
//!   one.
//! - A name proves nothing about who holds the key. The fingerprint stays the proof: the
//!   core keeps, per member, the key whose fingerprint the user compared out of band.
//! - The server learns the names and the texts searched (`sync-protocol.md` § 12); it never
//!   learns which fingerprints were compared.

use std::collections::{BTreeMap, BTreeSet};

use hirzla_access::keylog::{member_keys_object, KeyLogMonitor};
use hirzla_access::profile::{
    valid_display_name, MemberProfile, MAX_DISPLAY_NAME, MAX_PROFILE_LEN,
};
use hirzla_crypto::util::sha384;
use hirzla_sync::net::client::Client;
use hirzla_sync::net::NetError;
use hirzla_vault::cbor::{array_max, fixed, text_max, uint_in, Fields, Value};
use hirzla_vault::model::{Id16, MemberKeys};
use hirzla_vault::{Vault, VaultError};

use super::proto::{FoundInfo, ServerCode, ServerReply, MAX_FOUND, MIN_SEARCH};
use super::{corrupt, fingerprint, general, internal, net, read_log, write_log, ServerMode};
use crate::proto::ErrorCode;

/// Most profile objects issued here and remembered (twice what the server inscribes for
/// one member, `transparence.md` § 5.2).
const MAX_ISSUED: usize = 512;
/// Most names kept.
const MAX_NAMES: usize = 65_536;
/// Most compared fingerprints kept.
const MAX_VERIFIED: usize = 65_536;
/// Most profiles fetched in one synchronisation.
const MAX_FETCH: usize = 256;
/// Most members remembered from the searches of this session.
const MAX_SEEN: usize = 4096;

/// The verified profile of a member, as last read from the key log.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct KnownName {
    /// Rank of the profile.
    seq: u64,
    /// Name; empty when the member withdrew it.
    name: String,
    /// SHA-384 of the encoded profile: the `object` of its key log entry.
    object: [u8; 48],
}

/// What the annex keeps about display names (`format.md` § 15.2, key 8).
#[derive(Default)]
pub(super) struct Profiles {
    /// Objects of the profiles this device issued: expected in the key log, across restarts.
    issued: Vec<[u8; 48]>,
    /// Verified profiles, by member.
    names: BTreeMap<Id16, KnownName>,
    /// Member keys (`SHA-384(CBOR(MemberKeys))`) whose fingerprint the user compared.
    verified: BTreeMap<Id16, [u8; 48]>,
}

impl Profiles {
    /// The objects of the profiles issued here.
    pub(super) fn issued(&self) -> &[[u8; 48]] {
        &self.issued
    }

    pub(super) fn to_value(&self) -> Value {
        Value::map(vec![
            (
                1,
                Value::Array(self.issued.iter().map(|o| Value::bytes(o)).collect()),
            ),
            (
                2,
                Value::Array(
                    self.names
                        .iter()
                        .map(|(m, k)| {
                            Value::map(vec![
                                (1, Value::bytes(m)),
                                (2, Value::Uint(k.seq)),
                                (3, Value::text(&k.name)),
                                (4, Value::bytes(&k.object)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                3,
                Value::Array(
                    self.verified
                        .iter()
                        .map(|(m, k)| Value::map(vec![(1, Value::bytes(m)), (2, Value::bytes(k))]))
                        .collect(),
                ),
            ),
        ])
    }

    pub(super) fn from_value(v: &Value) -> Result<Profiles, ServerCode> {
        let f = Fields::new(v, &[1, 2, 3]).map_err(corrupt)?;
        let issued: Vec<[u8; 48]> = array_max(f.req(1).map_err(corrupt)?, MAX_ISSUED)
            .map_err(corrupt)?
            .iter()
            .map(fixed::<48>)
            .collect::<Result<_, _>>()
            .map_err(corrupt)?;
        let mut names = BTreeMap::new();
        let mut last: Option<Id16> = None;
        for n in array_max(f.req(2).map_err(corrupt)?, MAX_NAMES).map_err(corrupt)? {
            let g = Fields::new(n, &[1, 2, 3, 4]).map_err(corrupt)?;
            let member = fixed::<16>(g.req(1).map_err(corrupt)?).map_err(corrupt)?;
            if last.is_some_and(|l| l >= member) {
                return Err(general(ErrorCode::Corrupt));
            }
            last = Some(member);
            let name = text_max(g.req(3).map_err(corrupt)?, MAX_DISPLAY_NAME).map_err(corrupt)?;
            if !valid_display_name(name) {
                return Err(general(ErrorCode::Corrupt));
            }
            names.insert(
                member,
                KnownName {
                    seq: uint_in(g.req(2).map_err(corrupt)?, 1..=u64::MAX).map_err(corrupt)?,
                    name: name.to_owned(),
                    object: fixed::<48>(g.req(4).map_err(corrupt)?).map_err(corrupt)?,
                },
            );
        }
        let mut verified = BTreeMap::new();
        let mut last: Option<Id16> = None;
        for n in array_max(f.req(3).map_err(corrupt)?, MAX_VERIFIED).map_err(corrupt)? {
            let g = Fields::new(n, &[1, 2]).map_err(corrupt)?;
            let member = fixed::<16>(g.req(1).map_err(corrupt)?).map_err(corrupt)?;
            if last.is_some_and(|l| l >= member) {
                return Err(general(ErrorCode::Corrupt));
            }
            last = Some(member);
            verified.insert(
                member,
                fixed::<48>(g.req(2).map_err(corrupt)?).map_err(corrupt)?,
            );
        }
        Ok(Profiles {
            issued,
            names,
            verified,
        })
    }
}

/// The checks of ADR 0069, point 2, on a profile received for the member of `keys`: it is
/// the current profile of the member in the local key log, `keys` is the inscribed member
/// key, the signature holds and the rank does not go back from the one kept. `None` on any
/// failure: no name.
fn check_profile(
    log: &KeyLogMonitor,
    kept: Option<&KnownName>,
    keys: &MemberKeys,
    bytes: &[u8],
) -> Option<KnownName> {
    let object = sha384(bytes);
    let dir = log.directory();
    if dir.profile(&keys.member) != Some(object) {
        return None;
    }
    if dir.member_key(&keys.member) != Some(member_keys_object(keys).ok()?) {
        return None;
    }
    let p = MemberProfile::decode(bytes).ok()?;
    p.verify(keys).ok()?;
    if kept.is_some_and(|k| k.object != object && p.seq <= k.seq) {
        return None;
    }
    Some(KnownName {
        seq: p.seq,
        name: p.name,
        object,
    })
}

/// Whether `name` holds `needle`, case ignored: the rule of `FindMembers`
/// (`sync-protocol.md` § 11.11).
fn holds(name: &str, needle: &str) -> bool {
    name.to_lowercase().contains(&needle.to_lowercase())
}

impl ServerMode {
    /// The verified display name of `member`: the one of its current profile in the local
    /// key log. `None` when it has none, withdrew it, or its current profile was not
    /// verified here yet.
    pub(super) fn display_name(&self, member: &Id16) -> Result<Option<String>, ServerCode> {
        let Some(j) = &self.joined else {
            return Ok(None);
        };
        let Some(k) = j.profiles.names.get(member) else {
            return Ok(None);
        };
        if k.name.is_empty() {
            return Ok(None);
        }
        let current = read_log(&j.keylog.monitor)?.directory().profile(member);
        Ok((current == Some(k.object)).then(|| k.name.clone()))
    }

    /// Whether the user compared the fingerprint of `keys` out of band. The member's own key
    /// needs no comparison. The flag falls if the key changes.
    pub(super) fn fingerprint_verified(&self, keys: &MemberKeys) -> bool {
        if keys.member == self.device.member_id() {
            return true;
        }
        let Some(j) = &self.joined else {
            return false;
        };
        match (
            j.profiles.verified.get(&keys.member),
            member_keys_object(keys),
        ) {
            (Some(kept), Ok(object)) => *kept == object,
            _ => false,
        }
    }

    /// Records that the fingerprint of `keys` was compared out of band.
    pub(super) fn note_verified(&mut self, keys: &MemberKeys) -> Result<(), ServerCode> {
        let me = self.device.member_id();
        let object = member_keys_object(keys).map_err(internal)?;
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        if keys.member == me {
            return Ok(());
        }
        if j.profiles.verified.len() >= MAX_VERIFIED
            && !j.profiles.verified.contains_key(&keys.member)
        {
            return Err(general(ErrorCode::InvalidInput));
        }
        j.profiles.verified.insert(keys.member, object);
        Ok(())
    }

    /// The members whose names this device keeps up to date: itself and the members holding
    /// a role in a locker held here, with the key each is known by.
    fn named_members(&self) -> Result<BTreeMap<Id16, MemberKeys>, ServerCode> {
        let j = self.joined()?;
        let mut out = BTreeMap::new();
        for s in j.lockers.values() {
            let Some(a) = s.replica.authorization() else {
                continue;
            };
            let state = a.access().state();
            for (id, _) in state.members_with_roles() {
                if let Some(e) = state.member(id) {
                    out.entry(*id).or_insert_with(|| e.keys.clone());
                }
            }
        }
        out.insert(self.device.member_id(), self.device.member_keys().clone());
        Ok(out)
    }

    /// The key a member is known by here: in a locker held here, or in a search of this
    /// session.
    fn known_keys(&self, member: &Id16) -> Result<Option<([u8; 48], String)>, ServerCode> {
        let j = self.joined()?;
        for s in j.lockers.values() {
            let Some(a) = s.replica.authorization() else {
                continue;
            };
            if let Some(e) = a.access().state().member(member) {
                return Ok(Some((
                    member_keys_object(&e.keys).map_err(internal)?,
                    fingerprint(&e.keys.sig),
                )));
            }
        }
        Ok(self.seen.get(member).cloned())
    }

    /// Brings the names up to date after the key log was (`ServerSync`, ADR 0069 point 5):
    /// fetches the current profile of each member of the lockers held here and of this
    /// member when it changed, and checks it. Best effort: a profile the server does not
    /// serve, or that fails a check, leaves the member without a name.
    pub(super) fn refresh_names(&mut self, client: &mut Client) -> Result<(), ServerCode> {
        let wanted = self.named_members()?;
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        j.profiles.names.retain(|m, _| wanted.contains_key(m));
        let mut fetched = 0usize;
        for (member, keys) in &wanted {
            let current = read_log(&j.keylog.monitor)?.directory().profile(member);
            let Some(object) = current else {
                j.profiles.names.remove(member);
                continue;
            };
            let kept = j.profiles.names.get(member);
            if kept.is_some_and(|k| k.object == object) {
                continue;
            }
            if fetched >= MAX_FETCH {
                break;
            }
            fetched += 1;
            let bytes = match client.keylog_object(&object, MAX_PROFILE_LEN) {
                Ok(b) => b,
                Err(NetError::Refused(_)) => continue,
                // The session is lost: the names wait for the next synchronisation.
                Err(_) => break,
            };
            let checked = check_profile(&*read_log(&j.keylog.monitor)?, kept, keys, &bytes);
            if let Some(k) = checked {
                j.profiles.names.insert(*member, k);
            }
        }
        Ok(())
    }

    /// `ProfileSet` (120): signs a new profile with the member key, inside the vault, and
    /// has it inscribed in the key log.
    ///
    /// # Errors
    /// [`ErrorCode::InvalidInput`] for an invalid name, [`ServerCode::Forbidden`] without the
    /// member key, [`ServerCode::KeyLogRejected`] when the current profile inscribed for the
    /// member cannot be read or verified, network errors.
    pub(super) fn profile_set(
        &mut self,
        vault: &Vault,
        name: &str,
    ) -> Result<ServerReply, ServerCode> {
        if !valid_display_name(name) {
            return Err(general(ErrorCode::InvalidInput));
        }
        self.joined()?;
        if !vault.holds_member_key() {
            return Err(ServerCode::Forbidden);
        }
        let mut client = self.session()?;
        self.update_keylog(vault, &mut client)?;
        let r = self.profile_set_in(vault, &mut client, name);
        let _ = client.bye();
        r.map(|()| ServerReply::Done)
    }

    fn profile_set_in(
        &mut self,
        vault: &Vault,
        client: &mut Client,
        name: &str,
    ) -> Result<(), ServerCode> {
        let me = self.device.member_id();
        let keys = self.device.member_keys().clone();
        // The rank follows the one of the profile inscribed, which another certification
        // device of the member may have issued.
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        let current = read_log(&j.keylog.monitor)?.directory().profile(&me);
        let kept = j.profiles.names.get(&me).cloned();
        let inscribed = match current {
            None => None,
            Some(object) => match &kept {
                Some(k) if k.object == object => Some(k.clone()),
                _ => {
                    let bytes =
                        client
                            .keylog_object(&object, MAX_PROFILE_LEN)
                            .map_err(|e| match e {
                                NetError::Refused(_) => ServerCode::KeyLogRejected,
                                other => net(other),
                            })?;
                    let k =
                        check_profile(&*read_log(&j.keylog.monitor)?, kept.as_ref(), &keys, &bytes)
                            .ok_or(ServerCode::KeyLogRejected)?;
                    j.profiles.names.insert(me, k.clone());
                    Some(k)
                }
            },
        };
        let unchanged = match &inscribed {
            Some(k) => k.name == name,
            None => name.is_empty(),
        };
        if unchanged {
            return self.save(vault);
        }
        let seq = inscribed
            .iter()
            .chain(kept.iter())
            .map(|k| k.seq)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(general(ErrorCode::InvalidInput))?;
        let issued_ms = self.now();
        let sig = vault
            .sign_member_profile(seq, name, issued_ms)
            .map_err(|e| match e {
                VaultError::Unsupported => ServerCode::Forbidden,
                other => internal(other),
            })?;
        let profile = MemberProfile {
            member: me,
            seq,
            name: name.to_owned(),
            issued_ms,
            sig,
        };
        profile.verify(&keys).map_err(internal)?;
        let bytes = profile.encode().map_err(internal)?;
        let object = sha384(&bytes);
        // Expected in the key log before it is sent, and across a restart: no alert 8 for a
        // profile issued here (`transparence.md` § 6.4).
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        if j.profiles.issued.len() >= MAX_ISSUED {
            j.profiles.issued.remove(0);
        }
        j.profiles.issued.push(object);
        write_log(&j.keylog.monitor)?.expect_own(object);
        self.save(vault)?;
        client.put_member_profile(&bytes).map_err(net)?;
        // The inscription (kind 6) is read while it is still expected.
        self.update_keylog(vault, client)?;
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        let now_current = read_log(&j.keylog.monitor)?.directory().profile(&me);
        if now_current == Some(object) {
            j.profiles.names.insert(
                me,
                KnownName {
                    seq,
                    name: name.to_owned(),
                    object,
                },
            );
        }
        self.save(vault)
    }

    /// `MemberSearch` (121): the members of the server whose current name holds `text`. Each
    /// answer of the server is checked against the local key log and dropped if it fails:
    /// the server can hide a member, not invent one nor lend it a name.
    ///
    /// # Errors
    /// [`ErrorCode::InvalidInput`] for a text too short or too long, network errors.
    pub(super) fn member_search(
        &mut self,
        vault: &Vault,
        text: &str,
    ) -> Result<ServerReply, ServerCode> {
        if text.len() < MIN_SEARCH || text.len() > MAX_DISPLAY_NAME {
            return Err(general(ErrorCode::InvalidInput));
        }
        let mut client = self.session()?;
        self.update_keylog(vault, &mut client)?;
        let found = client.find_members(text);
        let _ = client.bye();
        let found = found.map_err(net)?;
        let mut members = Vec::new();
        let mut seen = BTreeSet::new();
        for item in found.items.iter().take(MAX_FOUND) {
            let member = item.keys.member;
            let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
            let checked = check_profile(
                &*read_log(&j.keylog.monitor)?,
                j.profiles.names.get(&member),
                &item.keys,
                &item.profile,
            );
            let Some(k) = checked else { continue };
            if k.name.is_empty() || !holds(&k.name, text) || !seen.insert(member) {
                continue;
            }
            let object = member_keys_object(&item.keys).map_err(internal)?;
            let fp = fingerprint(&item.keys.sig);
            if j.profiles.names.len() < MAX_NAMES || j.profiles.names.contains_key(&member) {
                j.profiles.names.insert(member, k.clone());
            }
            if self.seen.len() >= MAX_SEEN {
                self.seen.clear();
            }
            self.seen.insert(member, (object, fp.clone()));
            members.push(FoundInfo {
                member,
                name: k.name,
                verified: self.fingerprint_verified(&item.keys),
                fingerprint: fp,
            });
        }
        self.save(vault)?;
        Ok(ServerReply::Found {
            members,
            more: found.more,
        })
    }

    /// `MemberVerify` (122): the user compared the fingerprint of `member` out of band, and
    /// typed or scanned it. No network.
    ///
    /// # Errors
    /// [`ErrorCode::NotFound`] for a member unknown here (neither in a locker held here nor
    /// in a search of this session), [`ServerCode::FingerprintMismatch`].
    pub(super) fn member_verify(
        &mut self,
        vault: &Vault,
        member: Id16,
        typed: &str,
    ) -> Result<ServerReply, ServerCode> {
        let (object, fp) = self
            .known_keys(&member)?
            .ok_or(general(ErrorCode::NotFound))?;
        if fp != typed {
            return Err(ServerCode::FingerprintMismatch);
        }
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        if member != self.device.member_id() {
            if j.profiles.verified.len() >= MAX_VERIFIED
                && !j.profiles.verified.contains_key(&member)
            {
                return Err(general(ErrorCode::InvalidInput));
            }
            j.profiles.verified.insert(member, object);
            self.save(vault)?;
        }
        Ok(ServerReply::Done)
    }
}
