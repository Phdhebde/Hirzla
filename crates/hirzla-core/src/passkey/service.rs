//! What the core does with a passkey request (`docs/api-locale.md` § 23, ADR 0079).
//!
//! Every operation first checks the relying party identifier against the origin
//! ([`rp_id_allowed`]). The private key is read from the vault, used and erased; only the
//! public key, the authenticator data, the `clientDataJSON` and the signature go out.

use std::time::{Duration, Instant};

use hirzla_crypto::webauthn::{
    self as wa, AttestedCredential, PasskeyAlgorithm, PasskeyPrivateKey, FLAG_BE, FLAG_BS, FLAG_UP,
    FLAG_UV,
};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, FieldValue, SecretBody, SecretEdit, SecretState, SecretType};
use zeroize::Zeroizing;

use super::proto::{
    Assertion, Candidate, CreateArgs, Created, PasskeyCode, PasskeyReply, PasskeyRequest,
    UserVerification, MAX_CANDIDATES,
};
use super::rp::{client_data_json, rp_id_allowed};
use crate::events::Event;
use crate::proto::ErrorCode;
use crate::service::{vault_error, Core};

/// How long after the vault was opened the core announces the user as verified (flag UV,
/// ADR 0079 § 2).
pub const VERIFICATION_WINDOW: Duration = Duration::from_secs(5 * 60);
/// Length of a new credential identifier.
const CREDENTIAL_ID_LEN: usize = 16;

fn general(c: ErrorCode) -> PasskeyCode {
    PasskeyCode::General(c)
}

fn text(body: &SecretBody, f: Field) -> Option<&Zeroizing<String>> {
    match body.fields.get(&f).map(|e| &e.value) {
        Some(FieldValue::Text(t)) => Some(t),
        _ => None,
    }
}

fn bytes(body: &SecretBody, f: Field) -> Option<&Zeroizing<Vec<u8>>> {
    match body.fields.get(&f).map(|e| &e.value) {
        Some(FieldValue::Bytes(b)) => Some(b),
        _ => None,
    }
}

/// Whether a secret body is an active passkey for `rp_id`.
fn is_passkey_for(body: &SecretBody, rp_id: &str) -> bool {
    body.secret_type == SecretType::Passkey
        && body.state.0 == SecretState::Active
        && text(body, Field::RpId).is_some_and(|r| r.as_str() == rp_id)
}

/// Whether a passkey may be offered without an `allowCredentials` list.
fn discoverable(body: &SecretBody) -> bool {
    !matches!(
        body.fields.get(&Field::Discoverable).map(|e| &e.value),
        Some(FieldValue::Bool(false))
    )
}

impl Core {
    /// Answers one passkey request and logs its outcome (operation and result only: never
    /// the site, the account, the challenge or a signature).
    ///
    /// # Errors
    /// The code of the refusal.
    pub fn handle_passkey(&mut self, request: PasskeyRequest) -> Result<PasskeyReply, PasskeyCode> {
        let op = request.op();
        let result = self.dispatch_passkey(request);
        self.log.record(Event::PasskeyRequest {
            op,
            result: result.as_ref().err().map_or("ok", |c| c.name()),
        });
        result
    }

    /// Whether the user was verified recently: the vault was opened less than
    /// [`VERIFICATION_WINDOW`] ago.
    fn recently_verified(&self) -> bool {
        self.verified_at
            .is_some_and(|t| Instant::now().saturating_duration_since(t) < VERIFICATION_WINDOW)
    }

    /// The flags of a ceremony; `VerificationRequired` if the site requires a verification
    /// that is not recent.
    fn flags(&self, uv: UserVerification) -> Result<u8, PasskeyCode> {
        let verified = self.recently_verified();
        if uv == UserVerification::Required && !verified {
            return Err(PasskeyCode::VerificationRequired);
        }
        let mut flags = FLAG_UP | FLAG_BE | FLAG_BS;
        if verified {
            flags |= FLAG_UV;
        }
        Ok(flags)
    }

    /// Every active passkey of the vault for `rp_id`, with its locker.
    fn passkeys_for(&mut self, rp_id: &str) -> Result<Vec<(Id16, SecretBody)>, PasskeyCode> {
        let vault = self.vault().map_err(|e| general(e.code))?;
        let mut out = Vec::new();
        for l in vault.lockers() {
            for e in vault.list(l.id).map_err(|e| general(vault_error(e).code))? {
                if e.secret_type != SecretType::Passkey || e.state != SecretState::Active {
                    continue;
                }
                let body = vault
                    .read_secret(l.id, e.secret_id)
                    .map_err(|e| general(vault_error(e).code))?;
                if is_passkey_for(&body, rp_id) {
                    out.push((l.id, body));
                }
            }
        }
        Ok(out)
    }

    fn dispatch_passkey(&mut self, request: PasskeyRequest) -> Result<PasskeyReply, PasskeyCode> {
        match request {
            PasskeyRequest::Create(args) => self.passkey_create(&args),
            PasskeyRequest::Candidates {
                origin,
                rp_id,
                allow,
            } => {
                if !rp_id_allowed(&origin, &rp_id) {
                    return Err(general(ErrorCode::InvalidInput));
                }
                let mut list = Vec::new();
                for (locker, body) in self.passkeys_for(&rp_id)? {
                    let Some(cred) = bytes(&body, Field::CredentialId) else {
                        continue;
                    };
                    let offered = if allow.is_empty() {
                        discoverable(&body)
                    } else {
                        allow.iter().any(|a| a.as_slice() == cred.as_slice())
                    };
                    if !offered {
                        continue;
                    }
                    list.push(Candidate {
                        locker,
                        id: body.secret_id,
                        credential_id: cred.to_vec(),
                        title: text(&body, Field::Title).cloned().unwrap_or_default(),
                        user_name: text(&body, Field::Username).cloned(),
                        display_name: text(&body, Field::DisplayName).cloned(),
                    });
                    if list.len() == MAX_CANDIDATES {
                        break;
                    }
                }
                Ok(PasskeyReply::Candidates(list))
            }
            PasskeyRequest::Assert {
                origin,
                rp_id,
                challenge,
                locker,
                id,
                uv,
            } => {
                if !rp_id_allowed(&origin, &rp_id) {
                    return Err(general(ErrorCode::InvalidInput));
                }
                // Any other secret, site or state: `NotFound`, without saying why.
                let not_found = || general(ErrorCode::NotFound);
                let body = self
                    .secret_body(&locker, &id)
                    .map_err(|e| general(e.code))?
                    .filter(|b| is_passkey_for(b, &rp_id))
                    .ok_or_else(not_found)?;
                let flags = self.flags(uv)?;
                let algorithm = match body.fields.get(&Field::Alg).map(|e| &e.value) {
                    Some(FieldValue::Alg(a)) => PasskeyAlgorithm::from_cose(*a),
                    _ => None,
                }
                .ok_or(PasskeyCode::AlgorithmUnsupported)?;
                let credential_id = bytes(&body, Field::CredentialId)
                    .ok_or_else(not_found)?
                    .to_vec();
                let key = PasskeyPrivateKey::from_bytes(
                    bytes(&body, Field::PasskeyPrivateKey)
                        .ok_or_else(not_found)?
                        .clone(),
                );
                let client_data_json = client_data_json(false, &challenge, &origin);
                let authenticator_data = wa::authenticator_data(&rp_id, flags, None)
                    .map_err(|_| general(ErrorCode::InvalidInput))?;
                let signature = wa::sign(
                    algorithm,
                    &key,
                    &authenticator_data,
                    &wa::sha256(&client_data_json),
                )
                .map_err(|_| general(ErrorCode::Corrupt))?;
                Ok(PasskeyReply::Assertion(Box::new(Assertion {
                    credential_id,
                    client_data_json,
                    authenticator_data,
                    signature,
                    user_handle: bytes(&body, Field::UserHandle).map(|h| h.to_vec()),
                })))
            }
        }
    }

    fn passkey_create(&mut self, a: &CreateArgs) -> Result<PasskeyReply, PasskeyCode> {
        if !rp_id_allowed(&a.origin, &a.rp_id) {
            return Err(general(ErrorCode::InvalidInput));
        }
        let algorithm = a
            .algorithms
            .iter()
            .find_map(|x| PasskeyAlgorithm::from_cose(*x))
            .ok_or(PasskeyCode::AlgorithmUnsupported)?;
        if !a.exclude.is_empty() {
            let excluded = self.passkeys_for(&a.rp_id)?.iter().any(|(_, b)| {
                bytes(b, Field::CredentialId)
                    .is_some_and(|c| a.exclude.iter().any(|x| x.as_slice() == c.as_slice()))
            });
            if excluded {
                return Err(PasskeyCode::CredentialExcluded);
            }
        }
        let flags = self.flags(a.uv)?;
        let key = wa::generate(algorithm).map_err(|_| general(ErrorCode::Internal))?;
        let credential_id =
            wa::random_bytes(CREDENTIAL_ID_LEN).map_err(|_| general(ErrorCode::Internal))?;
        let title = a
            .rp_name
            .as_ref()
            .filter(|n| !n.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| Zeroizing::new(a.rp_id.clone()));
        let mut set = vec![
            (Field::Title, FieldValue::Text(title)),
            (Field::Username, FieldValue::Text(a.user_name.clone())),
            (Field::RpId, FieldValue::text(&a.rp_id)),
            (
                Field::CredentialId,
                FieldValue::Bytes(Zeroizing::new(credential_id.clone())),
            ),
            (
                Field::UserHandle,
                FieldValue::Bytes(Zeroizing::new(a.user_id.clone())),
            ),
            (
                Field::PasskeyPrivateKey,
                FieldValue::Bytes(Zeroizing::new(key.private_key.as_bytes().to_vec())),
            ),
            (Field::Alg, FieldValue::Alg(algorithm.cose())),
            (Field::Discoverable, FieldValue::Bool(true)),
        ];
        if let Some(d) = a.display_name.as_ref().filter(|d| !d.is_empty()) {
            set.push((Field::DisplayName, FieldValue::Text(d.clone())));
        }
        if a.user_name.is_empty() {
            set.retain(|(f, _)| *f != Field::Username);
        }
        // Always the personal locker (ADR 0079 § 4).
        let locker = self.target_locker(None).map_err(general)?;
        let id = self
            .create_in(
                locker,
                SecretType::Passkey,
                SecretEdit {
                    set,
                    ..SecretEdit::default()
                },
            )
            .map_err(general)?;
        let authenticator_data = wa::authenticator_data(
            &a.rp_id,
            flags,
            Some(&AttestedCredential {
                credential_id: &credential_id,
                public_cose: &key.public_cose,
            }),
        )
        .map_err(|_| general(ErrorCode::InvalidInput))?;
        let attestation_object = wa::attestation_object_none(&authenticator_data)
            .map_err(|_| general(ErrorCode::Internal))?;
        Ok(PasskeyReply::Created(Box::new(Created {
            locker,
            id,
            credential_id,
            client_data_json: client_data_json(true, &a.challenge, &a.origin),
            attestation_object,
            authenticator_data,
            public_key: key.public_spki,
            algorithm: algorithm.cose(),
        })))
    }
}
