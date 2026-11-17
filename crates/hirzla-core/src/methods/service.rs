//! What the core does with a hardware unlock method request (`docs/api-locale.md` § 21,
//! ADR 0075 § 5).
//!
//! Rules:
//! - the master password method is listed but never enrolled nor removed here;
//! - enrolling needs the open vault **and** the master password retyped, under the same brake
//!   as an unlock;
//! - a refused unlock by the hardware counts as a failed unlock; a cancelled gesture, an
//!   absent device or a deleted key do not (they prove nothing about the user);
//! - one gesture at a time: a second request that needs one gets `Busy`;
//! - the material released by the hardware is handed to the vault and dropped: it is never
//!   logged, never returned.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hirzla_keystore::unlock::{FactorError, FactorKind, Gesture, KeyRef, Material, UnlockFactor};
use hirzla_vault::model::hardware::{is_hardware_kind, HardwareKey};
use hirzla_vault::model::UNLOCK_PASSWORD;
use hirzla_vault::{unlock_methods, MethodInfo, Vault, VaultError};
use zeroize::Zeroizing;

use super::proto::{MethodCode, MethodEntry, MethodOp, MethodReply, MethodRequest};
use crate::events::Event;
use crate::proto::{ErrorCode, ErrorReply};
use crate::service::{vault_error, Core};

/// Most methods in a header (`docs/format.md` § 5.4).
const MAX_METHODS: usize = 8;

/// A refusal of a method request, with the wait of a `Throttled` refusal.
pub type MethodRefusal = (MethodCode, Option<u64>);

fn general(e: ErrorReply) -> MethodRefusal {
    (MethodCode::General(e.code), e.retry_after_s)
}

fn verr(e: VaultError) -> MethodRefusal {
    general(vault_error(e))
}

fn code(c: ErrorCode) -> MethodRefusal {
    (MethodCode::General(c), None)
}

fn method(c: MethodCode) -> MethodRefusal {
    (c, None)
}

/// The public reference the keystore works with, from the one of the header.
fn key_ref(key: &HardwareKey) -> KeyRef {
    match key {
        HardwareKey::WindowsHello { name, challenge } => KeyRef::WindowsHello {
            name: name.clone(),
            challenge: *challenge,
        },
        HardwareKey::SecureEnclave {
            wrapped_key,
            ephemeral_public,
        } => KeyRef::SecureEnclave {
            wrapped_key: wrapped_key.clone(),
            ephemeral_public: *ephemeral_public,
        },
        HardwareKey::Fido2 {
            credential_id,
            salt,
        } => KeyRef::Fido2 {
            credential_id: credential_id.clone(),
            salt: *salt,
        },
    }
}

/// The reference to keep in the header, from the one the keystore returned.
fn hardware_key(key: &KeyRef) -> HardwareKey {
    match key {
        KeyRef::WindowsHello { name, challenge } => HardwareKey::WindowsHello {
            name: name.clone(),
            challenge: *challenge,
        },
        KeyRef::SecureEnclave {
            wrapped_key,
            ephemeral_public,
        } => HardwareKey::SecureEnclave {
            wrapped_key: wrapped_key.clone(),
            ephemeral_public: *ephemeral_public,
        },
        KeyRef::Fido2 {
            credential_id,
            salt,
        } => HardwareKey::Fido2 {
            credential_id: credential_id.clone(),
            salt: *salt,
        },
    }
}

fn factor_error(e: FactorError) -> MethodCode {
    match e {
        FactorError::Unavailable => MethodCode::Unavailable,
        FactorError::Cancelled => MethodCode::Cancelled,
        FactorError::Invalidated => MethodCode::Invalidated,
        FactorError::Rejected => MethodCode::General(ErrorCode::UnlockFailed),
        FactorError::PinRequired => MethodCode::PinRequired,
        FactorError::PinBlocked => MethodCode::PinBlocked,
        FactorError::Failed => MethodCode::General(ErrorCode::Internal),
    }
}

fn kind_name(kind: u8) -> &'static str {
    FactorKind::from_number(kind).map_or("-", FactorKind::name)
}

/// Marks a gesture in progress; cleared when dropped, even if the gesture panics.
struct BusyGuard(Arc<AtomicBool>);

impl BusyGuard {
    fn take(flag: &Arc<AtomicBool>) -> Option<BusyGuard> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| BusyGuard(Arc::clone(flag)))
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

enum GestureKind {
    /// Enrolment of a new method.
    Enrol,
    /// Release of the material of the method at `rank`, whose key is `key`.
    Release { rank: usize, key: HardwareKey },
}

/// A gesture to run outside the core's lock, then to hand to
/// [`Core::methods_finish`].
pub struct PendingGesture {
    op: MethodOp,
    what: GestureKind,
    factor: Arc<dyn UnlockFactor>,
    vault_id: [u8; 16],
    pin: Option<Zeroizing<String>>,
    random: Zeroizing<[u8; 64]>,
    _busy: BusyGuard,
}

impl std::fmt::Debug for PendingGesture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PendingGesture({}, {})",
            self.op.name(),
            self.factor.kind().name()
        )
    }
}

/// What the hardware gave: for an enrolment, the new key with its material.
pub struct GestureOutcome(Result<(Option<KeyRef>, Material), FactorError>);

impl std::fmt::Debug for GestureOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Ok(_) => f.write_str("GestureOutcome(ok)"),
            Err(e) => write!(f, "GestureOutcome({e:?})"),
        }
    }
}

/// A prepared request: answered at once, or waiting for a gesture.
#[derive(Debug)]
pub enum Prepared {
    /// The answer.
    Done(Result<MethodReply, MethodRefusal>),
    /// A gesture to run without the core's lock.
    Gesture(PendingGesture),
}

/// Runs the user's gesture. Blocks until the user acts or the system gives up: call it
/// without holding the core's lock.
#[must_use]
pub fn run_gesture(pending: &PendingGesture) -> GestureOutcome {
    let gesture = Gesture {
        vault_id: pending.vault_id,
        pin: pending.pin.as_ref().map(|p| p.as_str()),
        random: &pending.random,
    };
    GestureOutcome(match &pending.what {
        GestureKind::Enrol => pending
            .factor
            .enrol(&gesture)
            .map(|(key, material)| (Some(key), material)),
        GestureKind::Release { key, .. } => pending
            .factor
            .release(&key_ref(key), &gesture)
            .map(|material| (None, material)),
    })
}

impl Core {
    /// Replaces the hardware factors of this core (tests, or a build that offers fewer).
    pub fn set_unlock_factors(&mut self, factors: Vec<Arc<dyn UnlockFactor>>) {
        self.factors = factors;
    }

    /// The factor of method kind `kind`, if this build has one.
    fn factor(&self, kind: u8) -> Option<Arc<dyn UnlockFactor>> {
        let kind = FactorKind::from_number(kind)?;
        self.factors.iter().find(|f| f.kind() == kind).cloned()
    }

    /// Answers one request, the gesture included, under `&mut self`. The daemon does not use
    /// it (it releases the lock during the gesture); tests and single-threaded callers do.
    ///
    /// # Errors
    /// The refusal, with the wait of a `Throttled` refusal.
    pub fn handle_methods(&mut self, request: MethodRequest) -> Result<MethodReply, MethodRefusal> {
        match self.methods_prepare(request) {
            Prepared::Done(r) => r,
            Prepared::Gesture(p) => {
                let outcome = run_gesture(&p);
                self.methods_finish(p, outcome)
            }
        }
    }

    /// Checks a request and answers it, or returns the gesture it needs. Logs the requests
    /// answered here.
    pub fn methods_prepare(&mut self, request: MethodRequest) -> Prepared {
        let op = request.op();
        let (kind, prepared) = match request {
            MethodRequest::UnlockMethods => ("-", Prepared::Done(self.list_methods())),
            MethodRequest::RemoveMethod { rank } => {
                let (kind, r) = self.remove_method(usize::from(rank));
                (kind, Prepared::Done(r))
            }
            MethodRequest::EnrollMethod {
                kind,
                password,
                pin,
            } => (
                kind_name(kind),
                self.prepare_enrol(kind, &password, pin)
                    .map_or_else(Prepared::Done, Prepared::Gesture),
            ),
            MethodRequest::UnlockWithMethod { rank, pin } => {
                let (kind, r) = self.prepare_unlock(usize::from(rank), pin);
                (kind, r.map_or_else(Prepared::Done, Prepared::Gesture))
            }
        };
        if let Prepared::Done(r) = &prepared {
            self.log_method(op, kind, r);
        }
        prepared
    }

    fn log_method(
        &self,
        op: MethodOp,
        kind: &'static str,
        result: &Result<MethodReply, MethodRefusal>,
    ) {
        self.log.record(Event::MethodRequest {
            op,
            kind,
            result: result.as_ref().err().map_or("ok", |(c, _)| c.name()),
        });
    }

    /// The methods of the header, read from the open vault or from the clear header.
    fn methods_info(&self) -> Result<Vec<MethodInfo>, MethodRefusal> {
        match self.vault.as_ref() {
            Some(v) => v.unlock_methods().map_err(verr),
            None if self.config.vault_path.exists() => {
                unlock_methods(&self.config.vault_path).map_err(verr)
            }
            None => Err(code(ErrorCode::NoVault)),
        }
    }

    fn list_methods(&self) -> Result<MethodReply, MethodRefusal> {
        let info = self.methods_info()?;
        let methods = info
            .iter()
            .map(|m| {
                let factor = m.hardware.as_ref().and_then(|_| self.factor(m.kind));
                MethodEntry {
                    rank: m.index,
                    kind: m.kind,
                    usable: m.kind == UNLOCK_PASSWORD
                        || factor.as_ref().is_some_and(|f| f.available()),
                    needs_pin: factor.as_ref().is_some_and(|f| f.needs_pin()),
                }
            })
            .collect();
        let enrollable = self
            .factors
            .iter()
            .filter(|f| f.available())
            .map(|f| f.kind().number())
            .collect();
        Ok(MethodReply::Methods {
            methods,
            enrollable,
        })
    }

    fn prepare_enrol(
        &mut self,
        kind: u8,
        password: &str,
        pin: Option<Zeroizing<String>>,
    ) -> Result<PendingGesture, Result<MethodReply, MethodRefusal>> {
        self.check_throttle().map_err(|e| Err(general(e)))?;
        let vault = self.vault().map_err(|e| Err(general(e)))?;
        match vault.verify_password(password) {
            Ok(()) => {}
            Err(VaultError::Unlock) => {
                self.record_failure();
                return Err(Err(code(ErrorCode::UnlockFailed)));
            }
            Err(e) => return Err(Err(verr(e))),
        }
        self.password_proven();
        let vault = self.vault().map_err(|e| Err(general(e)))?;
        let vault_id = vault.vault_id();
        let methods = vault.unlock_methods().map_err(|e| Err(verr(e)))?;
        // Windows Hello and Touch ID replace their method in place; FIDO2 adds one.
        let replaces = kind != FactorKind::Fido2.number() && methods.iter().any(|m| m.kind == kind);
        if !replaces && methods.len() >= MAX_METHODS {
            return Err(Err(code(ErrorCode::InvalidInput)));
        }
        let factor = self
            .factor(kind)
            .filter(|f| f.available())
            .ok_or(Err(method(MethodCode::Unavailable)))?;
        if factor.needs_pin() && pin.is_none() {
            return Err(Err(method(MethodCode::PinRequired)));
        }
        self.pending(
            MethodOp::EnrollMethod,
            GestureKind::Enrol,
            factor,
            vault_id,
            pin,
        )
    }

    fn prepare_unlock(
        &mut self,
        rank: usize,
        pin: Option<Zeroizing<String>>,
    ) -> (
        &'static str,
        Result<PendingGesture, Result<MethodReply, MethodRefusal>>,
    ) {
        if self.vault.is_some() {
            return ("-", Err(Err(code(ErrorCode::AlreadyUnlocked))));
        }
        let info = match self.methods_info() {
            Ok(i) => i,
            Err(e) => return ("-", Err(Err(e))),
        };
        let Some(m) = info.into_iter().nth(rank) else {
            return ("-", Err(Err(code(ErrorCode::NotFound))));
        };
        let kind = kind_name(m.kind);
        let r = (|| {
            if !is_hardware_kind(m.kind) {
                return Err(Err(code(ErrorCode::InvalidInput)));
            }
            self.check_throttle().map_err(|e| Err(general(e)))?;
            // A blob this build does not read, or a factor it lacks: not usable here.
            let key = m.hardware.ok_or(Err(method(MethodCode::Unavailable)))?;
            let factor = self
                .factor(m.kind)
                .filter(|f| f.available())
                .ok_or(Err(method(MethodCode::Unavailable)))?;
            if factor.needs_pin() && pin.is_none() {
                return Err(Err(method(MethodCode::PinRequired)));
            }
            let vault_id =
                hirzla_vault::vault_id_of(&self.config.vault_path).map_err(|e| Err(verr(e)))?;
            self.pending(
                MethodOp::UnlockWithMethod,
                GestureKind::Release { rank, key },
                factor,
                vault_id,
                pin,
            )
        })();
        (kind, r)
    }

    fn pending(
        &self,
        op: MethodOp,
        what: GestureKind,
        factor: Arc<dyn UnlockFactor>,
        vault_id: [u8; 16],
        pin: Option<Zeroizing<String>>,
    ) -> Result<PendingGesture, Result<MethodReply, MethodRefusal>> {
        let busy = BusyGuard::take(&self.gesture_busy).ok_or(Err(code(ErrorCode::Busy)))?;
        let random = Zeroizing::new(
            hirzla_crypto::util::random_array::<64>()
                .map_err(|_| Err(code(ErrorCode::Internal)))?,
        );
        Ok(PendingGesture {
            op,
            what,
            factor,
            vault_id,
            pin,
            random,
            _busy: busy,
        })
    }

    /// Applies the outcome of a gesture prepared by [`Core::methods_prepare`], and logs it.
    ///
    /// # Errors
    /// The refusal, with the wait of a `Throttled` refusal.
    pub fn methods_finish(
        &mut self,
        pending: PendingGesture,
        outcome: GestureOutcome,
    ) -> Result<MethodReply, MethodRefusal> {
        let op = pending.op;
        let kind = pending.factor.kind().name();
        let result = match pending.what {
            GestureKind::Enrol => self.finish_enrol(&pending, outcome),
            GestureKind::Release { rank, ref key } => {
                self.finish_unlock(rank, key, pending.vault_id, outcome)
            }
        };
        self.log_method(op, kind, &result);
        result
    }

    fn finish_enrol(
        &mut self,
        pending: &PendingGesture,
        outcome: GestureOutcome,
    ) -> Result<MethodReply, MethodRefusal> {
        let (key, material) = match outcome.0 {
            Ok((Some(key), material)) => (key, material),
            Ok((None, _)) => return Err(code(ErrorCode::Internal)),
            Err(e) => return Err(method(factor_error(e))),
        };
        // The vault may have been locked, or another one opened, during the gesture.
        let same = self
            .vault
            .as_ref()
            .is_some_and(|v| v.vault_id() == pending.vault_id);
        if !same {
            let _ = pending.factor.forget(&key);
            return Err(code(ErrorCode::Locked));
        }
        let vault = self.vault().map_err(general)?;
        match vault.add_hardware_method(&hardware_key(&key), material.as_bytes()) {
            Ok(rank) => Ok(MethodReply::Enrolled {
                rank: u8::try_from(rank).map_err(|_| code(ErrorCode::Internal))?,
            }),
            Err(e) => {
                let _ = pending.factor.forget(&key);
                Err(verr(e))
            }
        }
    }

    fn finish_unlock(
        &mut self,
        rank: usize,
        key: &HardwareKey,
        vault_id: [u8; 16],
        outcome: GestureOutcome,
    ) -> Result<MethodReply, MethodRefusal> {
        let material = match outcome.0 {
            Ok((_, material)) => material,
            Err(FactorError::Rejected) => {
                self.record_failure();
                return Err(code(ErrorCode::UnlockFailed));
            }
            Err(e) => return Err(method(factor_error(e))),
        };
        if self.vault.is_some() {
            return Err(code(ErrorCode::AlreadyUnlocked));
        }
        // Another vault file put in place during the gesture is refused by the header check
        // of `open_with_hardware` (the key must match); the identifier is checked first.
        match hirzla_vault::vault_id_of(&self.config.vault_path) {
            Ok(id) if id == vault_id => {}
            Ok(_) => return Err(method(MethodCode::Invalidated)),
            Err(e) => return Err(verr(e)),
        }
        match Vault::open_with_hardware(&self.config.vault_path, rank, key, material.as_bytes()) {
            Ok(v) => {
                self.opened(v);
                Ok(MethodReply::Done)
            }
            Err(VaultError::Unlock) => {
                self.record_failure();
                Err(code(ErrorCode::UnlockFailed))
            }
            Err(e) => Err(verr(e)),
        }
    }

    fn remove_method(&mut self, rank: usize) -> (&'static str, Result<MethodReply, MethodRefusal>) {
        let vault = match self.vault() {
            Ok(v) => v,
            Err(e) => return ("-", Err(general(e))),
        };
        let kind = vault
            .unlock_methods()
            .ok()
            .and_then(|m| m.get(rank).map(|m| kind_name(m.kind)))
            .unwrap_or("-");
        let removed = match vault.remove_hardware_method(rank) {
            Ok(k) => k,
            Err(e) => return (kind, Err(verr(e))),
        };
        // The key itself, when it lives in the system (Windows Hello): best effort.
        if let Some(key) = removed {
            let key = key_ref(&key);
            if let Some(f) = self.factor(key.kind().number()) {
                let _ = f.forget(&key);
            }
        }
        (kind, Ok(MethodReply::Done))
    }
}
