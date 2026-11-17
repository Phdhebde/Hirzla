//! What the core does with a TOTP request (`docs/api-locale.md` § 22, ADR 0078): it computes
//! the code of a stored TOTP secret with `hirzla_crypto::totp` and writes or removes a TOTP
//! configuration. The secret itself never leaves the core.

use std::time::{SystemTime, UNIX_EPOCH};

use hirzla_crypto::totp::{self as tc, TotpAlgorithm, TotpParams};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{
    Field, FieldValue, SecretBody, SecretEdit, SecretState, SecretType, SetKind, SetValue,
    TotpConfig,
};
use zeroize::Zeroizing;

use super::proto::{TotpCodeInfo, TotpReply, TotpRequest};
use crate::events::Event;
use crate::proto::ErrorCode;
use crate::service::{vault_error, Core};

/// Seconds since the Unix epoch on the system clock. The core has no other source of time:
/// it asks nothing of the network (rule 7 of `CLAUDE.md`).
fn system_time() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn params(c: &TotpConfig) -> Result<TotpParams, ErrorCode> {
    let algorithm = match c.algorithm {
        1 => TotpAlgorithm::Sha1,
        2 => TotpAlgorithm::Sha256,
        3 => TotpAlgorithm::Sha512,
        // The vault refuses any other value when it reads a secret.
        _ => return Err(ErrorCode::Corrupt),
    };
    Ok(TotpParams {
        algorithm,
        digits: c.digits,
        period: u32::from(c.period),
    })
}

/// The code (and, when asked, the next one) of a TOTP configuration at `now`.
pub(crate) fn code_info(c: &TotpConfig, now: u64, next: bool) -> Result<TotpCodeInfo, ErrorCode> {
    let p = params(c)?;
    let code = tc::totp(&c.secret, &p, now).map_err(|_| ErrorCode::Corrupt)?;
    let next = if next {
        Some(
            tc::totp_next(&c.secret, &p, now)
                .map_err(|_| ErrorCode::Internal)?
                .into_text(),
        )
    } else {
        None
    };
    Ok(TotpCodeInfo {
        code: code.into_text(),
        seconds_left: p.seconds_left(now),
        period: c.period,
        digits: c.digits,
        algorithm: c.algorithm,
        issuer: c.issuer.as_deref().map(|i| Zeroizing::new(i.to_owned())),
        next,
    })
}

/// The TOTP configuration of a secret body, if it holds one.
fn config_of(body: &SecretBody) -> Option<&TotpConfig> {
    match body.fields.get(&Field::Totp).map(|e| &e.value) {
        Some(FieldValue::Totp(c)) => Some(c),
        _ => None,
    }
}

/// The configuration of what a client sent, or `InvalidInput`.
fn parse(input: &str) -> Result<TotpConfig, ErrorCode> {
    hirzla_vault::totp::parse(input).ok_or(ErrorCode::InvalidInput)
}

impl Core {
    /// Answers one TOTP request and logs its outcome (operation and result only: never a code
    /// nor a TOTP text).
    ///
    /// # Errors
    /// The general code of the refusal.
    pub fn handle_totp(&mut self, request: TotpRequest) -> Result<TotpReply, ErrorCode> {
        let op = request.op();
        let result = self.dispatch_totp(request);
        self.log.record(Event::TotpRequest {
            op,
            result: result.as_ref().err().map_or("ok", |c| c.name()),
        });
        result
    }

    /// Replaces the clock of the TOTP codes, for tests that need a fixed time.
    pub fn set_totp_clock(&mut self, clock: fn() -> Option<u64>) {
        self.totp_clock = Some(clock);
    }

    fn totp_now(&self) -> Result<u64, ErrorCode> {
        // A clock before 1970 is a broken clock: no code rather than a wrong one.
        self.totp_clock.unwrap_or(system_time)().ok_or(ErrorCode::Internal)
    }

    /// A secret this device holds that is not purged, or `NotFound`.
    fn totp_secret(&mut self, locker: &Id16, id: &Id16) -> Result<SecretBody, ErrorCode> {
        self.secret_body(locker, id)
            .map_err(|e| e.code)?
            .filter(|b| b.state.0 != SecretState::Purged)
            .ok_or(ErrorCode::NotFound)
    }

    fn dispatch_totp(&mut self, request: TotpRequest) -> Result<TotpReply, ErrorCode> {
        match request {
            TotpRequest::Code { locker, id, next } => {
                // Showing a code is no activity: an open record that refreshes its code must
                // not keep the vault open (`docs/api-locale.md` § 22.3).
                let quiet = self.last_activity;
                let body = self.totp_secret(&locker, &id);
                self.last_activity = quiet;
                let body = body?;
                let config = config_of(&body).ok_or(ErrorCode::NotFound)?;
                let info = code_info(config, self.totp_now()?, next)?;
                Ok(TotpReply::Code(Box::new(info)))
            }
            TotpRequest::Set { locker, id, input } => {
                let config = parse(&input)?;
                drop(input);
                let body = self.totp_secret(&locker, &id)?;
                if !matches!(body.secret_type, SecretType::Password | SecretType::Totp) {
                    return Err(ErrorCode::InvalidInput);
                }
                self.edit_totp(
                    locker,
                    id,
                    body.secret_type,
                    SecretEdit {
                        set: vec![(Field::Totp, FieldValue::Totp(config))],
                        ..SecretEdit::default()
                    },
                )?;
                Ok(TotpReply::Done)
            }
            TotpRequest::Clear { locker, id } => {
                let body = self.totp_secret(&locker, &id)?;
                if config_of(&body).is_none() {
                    return Err(ErrorCode::NotFound);
                }
                self.edit_totp(
                    locker,
                    id,
                    body.secret_type,
                    SecretEdit {
                        clear: vec![Field::Totp],
                        ..SecretEdit::default()
                    },
                )?;
                Ok(TotpReply::Done)
            }
            TotpRequest::Create {
                locker,
                title,
                input,
                username,
                tags,
            } => {
                let config = parse(&input)?;
                drop(input);
                let locker = self.target_locker(locker)?;
                let mut set = vec![
                    (Field::Title, FieldValue::Text(title)),
                    (Field::Totp, FieldValue::Totp(config)),
                ];
                if let Some(u) = username {
                    set.push((Field::Username, FieldValue::Text(u)));
                }
                let edit = SecretEdit {
                    set,
                    add: tags
                        .into_iter()
                        .map(|t| (SetKind::Tags, SetValue::Text(t)))
                        .collect(),
                    ..SecretEdit::default()
                };
                let id = self.create_in(locker, SecretType::Totp, edit)?;
                Ok(TotpReply::Created { locker, id })
            }
        }
    }

    /// Writes an edit to a secret of the vault or of a shared locker.
    fn edit_totp(
        &mut self,
        locker: Id16,
        id: Id16,
        secret_type: SecretType,
        edit: SecretEdit,
    ) -> Result<(), ErrorCode> {
        if self.is_shared(&locker) {
            self.write_shared(&locker, Some(id), secret_type, edit)
                .map_err(|e| e.code)?;
        } else {
            self.vault()
                .map_err(|e| e.code)?
                .update_secret(locker, id, edit)
                .map_err(|e| vault_error(e).code)?;
        }
        Ok(())
    }
}
