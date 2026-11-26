//! Hardware unlock methods (local API version 12, `docs/api-locale.md` § 21, ADR 0075):
//! Windows Hello, Touch ID and FIDO2 security keys, beside the master password that always
//! stays.
//!
//! The gesture is asked by the system, in a dialog of its own, on behalf of the core: the web
//! view never sees the hardware, a key name, a credential identifier nor the material.
//!
//! Windows Hello and Touch ID are classical only (ADR 0075 § 4): they may be added once the
//! user has turned them on in the settings, after the warning; the enrolment then carries the
//! acknowledgement the core requires.

use hirzla_core::methods::proto::{
    is_classical_kind, MethodEntry, MethodReply, MethodRequest, MAX_PIN,
};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::commands::{check_master, guard, AppState, State};
use crate::error::DesktopError;
use crate::prefs::Preferences;

/// The name of a method kind, for the interface.
fn kind_name(kind: u8) -> &'static str {
    match kind {
        1 => "password",
        2 => "tpm",
        3 => "touchid",
        4 => "fido2",
        5 => "hello",
        6 => "recovery",
        _ => "unknown",
    }
}

/// The kind of a method the interface asks to add.
fn kind_from_name(name: &str) -> Result<u8, DesktopError> {
    match name {
        "touchid" => Ok(3),
        "fido2" => Ok(4),
        "hello" => Ok(5),
        _ => Err(DesktopError::Invalid("Méthode de déverrouillage inconnue.")),
    }
}

fn check_pin(pin: Option<Zeroizing<String>>) -> Result<Option<Zeroizing<String>>, DesktopError> {
    match pin {
        Some(p) if p.is_empty() => Ok(None),
        Some(p) if p.len() > MAX_PIN => Err(DesktopError::Invalid(
            "Le code PIN d'une clé de sécurité compte au plus 63 octets.",
        )),
        other => Ok(other),
    }
}

/// One unlock method, as the interface shows it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MethodDto {
    /// Rank in the vault header.
    pub rank: u8,
    /// `password`, `hello`, `touchid`, `fido2`, `recovery`, `tpm` or `unknown`.
    pub kind: &'static str,
    /// Usable on this workstation now.
    pub usable: bool,
    /// A PIN must be typed in the application.
    pub needs_pin: bool,
}

impl From<MethodEntry> for MethodDto {
    fn from(m: MethodEntry) -> Self {
        MethodDto {
            rank: m.rank,
            kind: kind_name(m.kind),
            usable: m.usable,
            needs_pin: m.needs_pin,
        }
    }
}

/// The methods of the vault, and what this workstation can add.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MethodsDto {
    /// In rank order; the master password first.
    pub methods: Vec<MethodDto>,
    /// Kinds this workstation can add now.
    pub enrollable: Vec<&'static str>,
}

impl AppState {
    fn call_methods(&self, request: &MethodRequest) -> Result<MethodReply, DesktopError> {
        self.with_link(|l| l.call_methods(request))
    }

    /// The unlock methods of the vault (read from its clear header while it is locked).
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn unlock_methods(&self) -> Result<MethodsDto, DesktopError> {
        match self.call_methods(&MethodRequest::UnlockMethods)? {
            MethodReply::Methods {
                methods,
                enrollable,
                ..
            } => Ok(MethodsDto {
                methods: methods.into_iter().map(MethodDto::from).collect(),
                enrollable: enrollable.into_iter().map(kind_name).collect(),
            }),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Adds a hardware method; the master password is asked again. Returns its rank.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn enroll_method(
        &self,
        kind: &str,
        password: Zeroizing<String>,
        pin: Option<Zeroizing<String>>,
    ) -> Result<u8, DesktopError> {
        let kind = kind_from_name(kind)?;
        check_master(&password)?;
        let pin = check_pin(pin)?;
        let accept_classical_risk = is_classical_kind(kind) && self.classical_unlock_allowed();
        if is_classical_kind(kind) && !accept_classical_risk {
            return Err(DesktopError::Invalid(
                "Autorisez d'abord Windows Hello et Touch ID dans Réglages › Déverrouillage.",
            ));
        }
        match self.call_methods(&MethodRequest::EnrollMethod {
            kind,
            password,
            pin,
            accept_classical_risk,
        })? {
            MethodReply::Enrolled { rank } => Ok(rank),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Opens the vault with the hardware method at `rank`.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn unlock_with_method(
        &self,
        rank: u8,
        pin: Option<Zeroizing<String>>,
    ) -> Result<(), DesktopError> {
        let pin = check_pin(pin)?;
        self.call_methods(&MethodRequest::UnlockWithMethod { rank, pin })
            .map(drop)
    }

    /// Whether the user turned Windows Hello and Touch ID on, after the warning.
    #[must_use]
    pub fn classical_unlock_allowed(&self) -> bool {
        guard(&self.prefs).get().allow_classical_unlock
    }

    /// Turns Windows Hello and Touch ID on or off; kept in the local preferences.
    ///
    /// # Errors
    /// [`DesktopError::Invalid`] if the preferences cannot be written.
    pub fn set_classical_unlock_allowed(&self, allowed: bool) -> Result<bool, DesktopError> {
        let mut store = guard(&self.prefs);
        let prefs = Preferences {
            allow_classical_unlock: allowed,
            ..store.get()
        };
        store.set(prefs)?;
        Ok(allowed)
    }

    /// Removes the hardware method at `rank` (the last one only).
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn remove_method(&self, rank: u8) -> Result<(), DesktopError> {
        self.call_methods(&MethodRequest::RemoveMethod { rank })
            .map(drop)
    }
}

/// See [`AppState::unlock_methods`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn list_unlock_methods(state: State<'_>) -> Result<MethodsDto, DesktopError> {
    state.unlock_methods()
}

/// See [`AppState::enroll_method`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn enroll_unlock_method(
    state: State<'_>,
    kind: String,
    password: Zeroizing<String>,
    pin: Option<Zeroizing<String>>,
) -> Result<u8, DesktopError> {
    state.enroll_method(&kind, password, pin)
}

/// See [`AppState::classical_unlock_allowed`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn get_classical_unlock(state: State<'_>) -> bool {
    state.classical_unlock_allowed()
}

/// See [`AppState::set_classical_unlock_allowed`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn set_classical_unlock(state: State<'_>, allowed: bool) -> Result<bool, DesktopError> {
    state.set_classical_unlock_allowed(allowed)
}

/// See [`AppState::unlock_with_method`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn unlock_with_method(
    state: State<'_>,
    rank: u8,
    pin: Option<Zeroizing<String>>,
) -> Result<(), DesktopError> {
    state.unlock_with_method(rank, pin)
}

/// See [`AppState::remove_method`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn remove_unlock_method(state: State<'_>, rank: u8) -> Result<(), DesktopError> {
    state.remove_method(rank)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hirzla_core::methods::proto::MethodCode;
    use hirzla_core::proto::ErrorCode;

    #[test]
    fn kinds_and_pins_are_checked_before_the_core() {
        assert_eq!(kind_from_name("fido2").unwrap(), 4);
        assert_eq!(kind_from_name("hello").unwrap(), 5);
        assert_eq!(kind_from_name("touchid").unwrap(), 3);
        assert!(kind_from_name("password").is_err());
        assert!(kind_from_name("tpm").is_err());
        assert!(check_pin(Some(Zeroizing::new("9".repeat(64)))).is_err());
        assert_eq!(
            check_pin(Some(Zeroizing::new(String::new()))).unwrap(),
            None
        );
        assert!(check_pin(Some(Zeroizing::new("1234".into())))
            .unwrap()
            .is_some());
    }

    #[test]
    fn entries_are_named_for_the_interface() {
        let dto = MethodDto::from(MethodEntry {
            rank: 2,
            kind: 4,
            usable: false,
            needs_pin: true,
        });
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["kind"], "fido2");
        assert_eq!(json["rank"], 2);
        assert_eq!(json["needs_pin"], true);
        assert_eq!(kind_name(1), "password");
        assert_eq!(kind_name(6), "recovery");
        assert_eq!(kind_name(99), "unknown");
    }

    #[test]
    fn refusals_get_their_own_codes_and_messages() {
        for (code, name) in [
            (MethodCode::Unavailable, "method_unavailable"),
            (MethodCode::Cancelled, "method_cancelled"),
            (MethodCode::Invalidated, "method_invalidated"),
            (MethodCode::PinRequired, "pin_required"),
            (MethodCode::PinBlocked, "pin_blocked"),
            (
                MethodCode::ClassicalFactorNotAccepted,
                "classical_factor_not_accepted",
            ),
        ] {
            let e = DesktopError::from_method(code, None);
            assert_eq!(e.code(), name);
            assert!(!e.message().is_empty());
        }
        let e = DesktopError::from_method(MethodCode::General(ErrorCode::Throttled), Some(6));
        assert_eq!(e.retry_after_s(), Some(6));
        let e = DesktopError::from_method(MethodCode::General(ErrorCode::UnlockFailed), None);
        assert!(e.message().contains("matériel"));
    }
}
