//! TOTP codes (`docs/api-locale.md` § 22, local API version 13, ADR 0078).
//!
//! The core computes the code; this process passes it to the record, which shows it, or copies
//! it itself to the clipboard, cleared after the delay of the settings like a password. The
//! TOTP secret never reaches this process: the text the user pastes to set one (`otpauth://`
//! URI or base32 secret) goes to the core and is checked there.

use hirzla_core::proto::{ErrorCode, ErrorReply, MAX_ITEMS, MAX_TEXT};
use hirzla_core::totp::proto::{TotpCodeInfo, TotpReply, TotpRequest, MAX_TOTP_INPUT};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::commands::{hex, id16, AppState, SecretRef, State};
use crate::error::DesktopError;

const REFUSED: &str = "TOTP refusé : collez l'adresse otpauth://totp/… donnée par le site \
                       (souvent sous le QR code), ou sa clé secrète en base32 (au moins \
                       16 caractères). Ni HOTP, ni code Steam.";

/// A code, ready to show: never the TOTP secret.
#[derive(Clone, Serialize)]
pub struct TotpCodeDto {
    /// The code of the current period.
    code: Zeroizing<String>,
    /// Seconds before it changes.
    seconds_left: u32,
    /// Length of a period, in seconds.
    period: u16,
    /// Digits of a code.
    digits: u8,
    /// `SHA-1`, `SHA-256` or `SHA-512`.
    algorithm: &'static str,
    /// Issuer stored with the TOTP.
    issuer: Option<Zeroizing<String>>,
}

impl From<TotpCodeInfo> for TotpCodeDto {
    fn from(i: TotpCodeInfo) -> Self {
        TotpCodeDto {
            code: i.code,
            seconds_left: i.seconds_left,
            period: i.period,
            digits: i.digits,
            algorithm: match i.algorithm {
                2 => "SHA-256",
                3 => "SHA-512",
                _ => "SHA-1",
            },
            issuer: i.issuer,
        }
    }
}

/// A new secret of type TOTP.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewTotp {
    /// Locker; `None` for the personal one.
    locker: Option<String>,
    title: Zeroizing<String>,
    /// `otpauth://` URI or base32 secret.
    input: Zeroizing<String>,
    #[serde(default)]
    username: Option<Zeroizing<String>>,
    #[serde(default)]
    tags: Vec<Zeroizing<String>>,
}

impl std::fmt::Debug for NewTotp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewTotp")
    }
}

fn text(value: Zeroizing<String>) -> Result<Zeroizing<String>, DesktopError> {
    if value.trim().is_empty() || value.len() > MAX_TEXT {
        return Err(DesktopError::Invalid("Valeur vide ou trop longue."));
    }
    Ok(value)
}

fn input(value: Zeroizing<String>) -> Result<Zeroizing<String>, DesktopError> {
    if value.trim().is_empty() || value.len() > MAX_TOTP_INPUT {
        return Err(DesktopError::Invalid(REFUSED));
    }
    Ok(value)
}

/// A refusal of a TOTP request: the general codes only (§ 22.4).
#[must_use]
pub fn refusal(code: ErrorCode) -> DesktopError {
    if code == ErrorCode::InvalidInput {
        DesktopError::Invalid(REFUSED)
    } else {
        DesktopError::Refused(ErrorReply {
            code,
            retry_after_s: None,
            versions: Vec::new(),
        })
    }
}

impl AppState {
    fn totp(&self, request: &TotpRequest) -> Result<TotpReply, DesktopError> {
        self.with_link(|l| l.call_totp(request))
    }

    fn code_info(&self, target: &SecretRef, next: bool) -> Result<TotpCodeInfo, DesktopError> {
        match self.totp(&TotpRequest::Code {
            locker: id16(&target.locker)?,
            id: id16(&target.id)?,
            next,
        })? {
            TotpReply::Code(info) => Ok(*info),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// The current code of a secret, to show in its record.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn totp_code(&self, target: &SecretRef) -> Result<TotpCodeDto, DesktopError> {
        self.code_info(target, false).map(TotpCodeDto::from)
    }

    /// Copies the current code, or the next one, to the clipboard; returns the clearing delay.
    /// The code does not pass through the web view.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn totp_copy(&self, target: &SecretRef, next: bool) -> Result<u64, DesktopError> {
        let info = self.code_info(target, next)?;
        let code = if next {
            info.next.ok_or(DesktopError::Protocol)?
        } else {
            info.code
        };
        let delay = self.with_link(|l| l.status())?.clipboard_clear_s;
        self.clipboard.copy(code, delay)
    }

    /// Sets or replaces the TOTP of a password or of a TOTP secret.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn totp_set(
        &self,
        target: &SecretRef,
        text: Zeroizing<String>,
    ) -> Result<(), DesktopError> {
        self.totp(&TotpRequest::Set {
            locker: id16(&target.locker)?,
            id: id16(&target.id)?,
            input: input(text)?,
        })
        .map(drop)
    }

    /// Removes the TOTP of a secret.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn totp_clear(&self, target: &SecretRef) -> Result<(), DesktopError> {
        self.totp(&TotpRequest::Clear {
            locker: id16(&target.locker)?,
            id: id16(&target.id)?,
        })
        .map(drop)
    }

    /// Creates a secret of type TOTP.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn totp_create(&self, new: NewTotp) -> Result<SecretRef, DesktopError> {
        if new.tags.len() > MAX_ITEMS {
            return Err(DesktopError::Invalid("Trop d'étiquettes."));
        }
        let request = TotpRequest::Create {
            locker: new.locker.as_deref().map(id16).transpose()?,
            title: text(new.title)?,
            input: input(new.input)?,
            username: new.username.map(text).transpose()?,
            tags: new.tags.into_iter().map(text).collect::<Result<_, _>>()?,
        };
        match self.totp(&request)? {
            TotpReply::Created { locker, id } => Ok(SecretRef {
                locker: hex(&locker),
                id: hex(&id),
            }),
            _ => Err(DesktopError::Protocol),
        }
    }
}

/// See [`AppState::totp_code`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn totp_code(state: State<'_>, target: SecretRef) -> Result<TotpCodeDto, DesktopError> {
    state.totp_code(&target)
}

/// See [`AppState::totp_copy`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn totp_copy(state: State<'_>, target: SecretRef, next: bool) -> Result<u64, DesktopError> {
    state.totp_copy(&target, next)
}

/// See [`AppState::totp_set`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn totp_set(
    state: State<'_>,
    target: SecretRef,
    input: Zeroizing<String>,
) -> Result<(), DesktopError> {
    state.totp_set(&target, input)
}

/// See [`AppState::totp_clear`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn totp_clear(state: State<'_>, target: SecretRef) -> Result<(), DesktopError> {
    state.totp_clear(&target)
}

/// See [`AppState::totp_create`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn totp_create(state: State<'_>, totp: NewTotp) -> Result<SecretRef, DesktopError> {
    state.totp_create(totp)
}
