//! Passkey operations of the local API (`docs/api-locale.md` § 23): version 14, operation
//! codes 180 to 182, error codes 185 to 187, range 180 to 189 reserved (ADR 0079). Same
//! frames, same CBOR profile and same strict decoding as the rest of the API
//! (`crate::proto`).
//!
//! No private key ever crosses the channel: a reply carries what the WebAuthn standard puts
//! in the response to the site (credential identifier, `clientDataJSON`, authenticator data,
//! attestation object or signature, user handle) and the public key.

use hirzla_vault::cbor::{self, array_max, bytes_max, fixed, text_max, uint, Fields, Value};
use hirzla_vault::model::Id16;
use zeroize::Zeroizing;

use crate::proto::{ErrorCode, MAX_ITEMS, MAX_ORIGIN};

/// Version of the protocol that carries the passkey operations.
pub const PASSKEY_VERSION: u64 = 14;
/// Operation and error codes reserved for passkeys.
pub const PASSKEY_OPS: std::ops::RangeInclusive<u64> = 180..=189;
/// Longest relying party identifier.
pub const MAX_RP_ID: usize = hirzla_crypto::webauthn::MAX_RP_ID;
/// Shortest and longest challenge (ADR 0079 § 2).
pub const CHALLENGE_LEN: std::ops::RangeInclusive<usize> = 16..=1024;
/// Longest user handle (`user.id`), as in the vault's field 42.
pub const MAX_USER_ID: usize = 64;
/// Longest credential identifier.
pub const MAX_CREDENTIAL_ID: usize = hirzla_crypto::webauthn::MAX_CREDENTIAL_ID;
/// Longest user name, display name or relying party name on the wire.
const MAX_SHORT: usize = 1024;
/// Most credentials in a `PasskeyCandidates` reply.
pub const MAX_CANDIDATES: usize = 256;
/// Most algorithms a site may list.
const MAX_ALGORITHMS: usize = 16;
/// Longest public key, attestation object or signature in a reply.
const MAX_BLOB: usize = 8 * 1024;
/// Longest `clientDataJSON` in a reply: a challenge of 1 024 bytes in base64url and an
/// origin of [`MAX_ORIGIN`] bytes fit.
const MAX_CLIENT_DATA: usize = 4 * 1024;

/// Passkey operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyOp {
    /// Create a credential for a site.
    PasskeyCreate = 180,
    /// The credentials a site may use.
    PasskeyCandidates = 181,
    /// Sign a challenge with a credential.
    PasskeyAssert = 182,
}

impl PasskeyOp {
    /// All operations.
    pub const ALL: [PasskeyOp; 3] = [
        PasskeyOp::PasskeyCreate,
        PasskeyOp::PasskeyCandidates,
        PasskeyOp::PasskeyAssert,
    ];

    /// The operation from its number.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<PasskeyOp> {
        PasskeyOp::ALL.into_iter().find(|o| *o as u64 == n)
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            PasskeyOp::PasskeyCreate => "passkey_create",
            PasskeyOp::PasskeyCandidates => "passkey_candidates",
            PasskeyOp::PasskeyAssert => "passkey_assert",
        }
    }
}

/// The site's wish about user verification (`userVerification`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserVerification {
    /// `discouraged`.
    Discouraged = 1,
    /// `preferred`.
    Preferred = 2,
    /// `required`.
    Required = 3,
}

impl UserVerification {
    fn from_u64(n: u64) -> Option<UserVerification> {
        match n {
            1 => Some(UserVerification::Discouraged),
            2 => Some(UserVerification::Preferred),
            3 => Some(UserVerification::Required),
            _ => None,
        }
    }
}

/// Error codes of this family (185 to 187). The general codes of § 7 keep their numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyCode {
    /// A general code of § 7.
    General(ErrorCode),
    /// 185: the site requires user verification and the vault was not opened recently.
    VerificationRequired,
    /// 186: the vault already holds one of the excluded credentials for this site.
    CredentialExcluded,
    /// 187: none of the algorithms the site accepts is −7 or −8.
    AlgorithmUnsupported,
}

impl From<ErrorCode> for PasskeyCode {
    fn from(c: ErrorCode) -> PasskeyCode {
        PasskeyCode::General(c)
    }
}

impl PasskeyCode {
    /// Status number on the wire.
    #[must_use]
    pub fn status(self) -> u64 {
        match self {
            PasskeyCode::General(c) => c as u64,
            PasskeyCode::VerificationRequired => 185,
            PasskeyCode::CredentialExcluded => 186,
            PasskeyCode::AlgorithmUnsupported => 187,
        }
    }

    /// The code of status `n`.
    #[must_use]
    pub fn from_status(n: u64) -> Option<PasskeyCode> {
        Some(match n {
            185 => PasskeyCode::VerificationRequired,
            186 => PasskeyCode::CredentialExcluded,
            187 => PasskeyCode::AlgorithmUnsupported,
            n => PasskeyCode::General(ErrorCode::from_u64(n)?),
        })
    }

    /// Stable short name, for logs and the native host.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            PasskeyCode::General(c) => c.name(),
            PasskeyCode::VerificationRequired => "verification_required",
            PasskeyCode::CredentialExcluded => "credential_excluded",
            PasskeyCode::AlgorithmUnsupported => "algorithm_unsupported",
        }
    }
}

/// What `PasskeyCreate` carries (`navigator.credentials.create`).
#[derive(Clone, PartialEq, Eq)]
pub struct CreateArgs {
    /// Origin of the page, canonical `https`.
    pub origin: String,
    /// Relying party identifier.
    pub rp_id: String,
    /// Challenge.
    pub challenge: Vec<u8>,
    /// `user.id`, the user handle.
    pub user_id: Vec<u8>,
    /// `user.name`.
    pub user_name: Zeroizing<String>,
    /// `user.displayName`.
    pub display_name: Option<Zeroizing<String>>,
    /// COSE algorithms the site accepts, in its order of preference.
    pub algorithms: Vec<i64>,
    /// Credentials the site already knows for this account (`excludeCredentials`).
    pub exclude: Vec<Vec<u8>>,
    /// User verification wished.
    pub uv: UserVerification,
    /// `rp.name`.
    pub rp_name: Option<Zeroizing<String>>,
}

/// A passkey request.
#[derive(Clone, PartialEq, Eq)]
pub enum PasskeyRequest {
    /// Create a credential.
    Create(Box<CreateArgs>),
    /// The credentials a site may use.
    Candidates {
        /// Origin of the page.
        origin: String,
        /// Relying party identifier.
        rp_id: String,
        /// Credentials the site allows (`allowCredentials`); empty: any discoverable one.
        allow: Vec<Vec<u8>>,
    },
    /// Sign a challenge.
    Assert {
        /// Origin of the page.
        origin: String,
        /// Relying party identifier.
        rp_id: String,
        /// Challenge.
        challenge: Vec<u8>,
        /// Locker of the credential.
        locker: Id16,
        /// Secret of the credential.
        id: Id16,
        /// User verification wished.
        uv: UserVerification,
    },
}

impl std::fmt::Debug for PasskeyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The operation only: neither the site nor the account.
        write!(f, "PasskeyRequest::{}", self.op().name())
    }
}

/// A new credential (`PasskeyCreate`).
#[derive(Clone, PartialEq, Eq)]
pub struct Created {
    /// Locker of the new secret.
    pub locker: Id16,
    /// The new secret.
    pub id: Id16,
    /// Credential identifier.
    pub credential_id: Vec<u8>,
    /// `clientDataJSON`.
    pub client_data_json: Vec<u8>,
    /// Attestation object, format `none`.
    pub attestation_object: Vec<u8>,
    /// Authenticator data.
    pub authenticator_data: Vec<u8>,
    /// Public key, DER SubjectPublicKeyInfo.
    pub public_key: Vec<u8>,
    /// COSE algorithm.
    pub algorithm: i64,
}

/// A credential a site may use (`PasskeyCandidates`).
#[derive(Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Locker.
    pub locker: Id16,
    /// Secret.
    pub id: Id16,
    /// Credential identifier.
    pub credential_id: Vec<u8>,
    /// Title of the secret.
    pub title: Zeroizing<String>,
    /// `user.name`.
    pub user_name: Option<Zeroizing<String>>,
    /// `user.displayName`.
    pub display_name: Option<Zeroizing<String>>,
}

/// A signed assertion (`PasskeyAssert`).
#[derive(Clone, PartialEq, Eq)]
pub struct Assertion {
    /// Credential identifier.
    pub credential_id: Vec<u8>,
    /// `clientDataJSON`.
    pub client_data_json: Vec<u8>,
    /// Authenticator data.
    pub authenticator_data: Vec<u8>,
    /// Signature.
    pub signature: Vec<u8>,
    /// User handle.
    pub user_handle: Option<Vec<u8>>,
}

/// A successful reply to a passkey request.
#[derive(Clone, PartialEq, Eq)]
pub enum PasskeyReply {
    /// A credential was created.
    Created(Box<Created>),
    /// The credentials a site may use.
    Candidates(Vec<Candidate>),
    /// A signed assertion.
    Assertion(Box<Assertion>),
}

impl std::fmt::Debug for PasskeyReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PasskeyReply::Created(_) => "PasskeyReply::Created",
            PasskeyReply::Candidates(_) => "PasskeyReply::Candidates",
            PasskeyReply::Assertion(_) => "PasskeyReply::Assertion",
        })
    }
}

/// Whether `frame` is a passkey request: its operation code (key 3) is in [`PASSKEY_OPS`].
#[must_use]
pub fn is_passkey_request(frame: &[u8]) -> bool {
    let Ok(v) = cbor::decode(frame) else {
        return false;
    };
    let Ok(f) = Fields::new(&v, &[1, 2, 3, 4]) else {
        return false;
    };
    f.req(3)
        .and_then(uint)
        .is_ok_and(|op| PASSKEY_OPS.contains(&op))
}

type R<T> = Result<T, cbor::CborError>;

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn signed(v: &Value) -> R<i64> {
    match v {
        Value::Uint(n) => i64::try_from(*n).map_err(|_| cbor::CborError::Malformed),
        Value::Nint(n) => i64::try_from(*n)
            .map(|n| -1 - n)
            .map_err(|_| cbor::CborError::Malformed),
        _ => Err(cbor::CborError::Malformed),
    }
}

fn byte_list(v: &Value, max: usize) -> R<Vec<Vec<u8>>> {
    array_max(v, MAX_ITEMS)?
        .iter()
        .map(|b| {
            let b = bytes_max(b, max)?;
            if b.is_empty() {
                return Err(cbor::CborError::Malformed);
            }
            Ok(b.to_vec())
        })
        .collect()
}

fn bytes_in(v: &Value, range: std::ops::RangeInclusive<usize>) -> R<Vec<u8>> {
    let b = bytes_max(v, *range.end())?;
    if b.len() < *range.start() {
        return Err(cbor::CborError::Malformed);
    }
    Ok(b.to_vec())
}

fn short(v: &Value) -> R<Zeroizing<String>> {
    text_max(v, MAX_SHORT).map(z)
}

fn uv_from(v: &Value) -> R<UserVerification> {
    UserVerification::from_u64(uint(v)?).ok_or(cbor::CborError::Malformed)
}

fn bytes_list_value(items: &[Vec<u8>]) -> Value {
    Value::Array(items.iter().map(|b| Value::bytes(b)).collect())
}

impl PasskeyRequest {
    /// Its operation.
    #[must_use]
    pub fn op(&self) -> PasskeyOp {
        match self {
            PasskeyRequest::Create(_) => PasskeyOp::PasskeyCreate,
            PasskeyRequest::Candidates { .. } => PasskeyOp::PasskeyCandidates,
            PasskeyRequest::Assert { .. } => PasskeyOp::PasskeyAssert,
        }
    }

    fn args(&self) -> Value {
        match self {
            PasskeyRequest::Create(a) => {
                let mut e = vec![
                    (1, Value::text(&a.origin)),
                    (2, Value::text(&a.rp_id)),
                    (3, Value::bytes(&a.challenge)),
                    (4, Value::bytes(&a.user_id)),
                    (5, Value::text(&a.user_name)),
                    (
                        7,
                        Value::Array(a.algorithms.iter().map(|x| Value::int(*x)).collect()),
                    ),
                    (9, Value::Uint(a.uv as u64)),
                ];
                if let Some(d) = &a.display_name {
                    e.push((6, Value::text(d)));
                }
                if !a.exclude.is_empty() {
                    e.push((8, bytes_list_value(&a.exclude)));
                }
                if let Some(n) = &a.rp_name {
                    e.push((10, Value::text(n)));
                }
                Value::map(e)
            }
            PasskeyRequest::Candidates {
                origin,
                rp_id,
                allow,
            } => {
                let mut e = vec![(1, Value::text(origin)), (2, Value::text(rp_id))];
                if !allow.is_empty() {
                    e.push((3, bytes_list_value(allow)));
                }
                Value::map(e)
            }
            PasskeyRequest::Assert {
                origin,
                rp_id,
                challenge,
                locker,
                id,
                uv,
            } => Value::map(vec![
                (1, Value::text(origin)),
                (2, Value::text(rp_id)),
                (3, Value::bytes(challenge)),
                (4, Value::bytes(locker)),
                (5, Value::bytes(id)),
                (6, Value::Uint(*uv as u64)),
            ]),
        }
    }

    /// Encodes the request with identifier `id` (client side, tests).
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(&self, id: u64) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        cbor::encode(&Value::map(vec![
            (1, Value::Uint(PASSKEY_VERSION)),
            (2, Value::Uint(id)),
            (3, Value::Uint(self.op() as u64)),
            (4, self.args()),
        ]))
        .map_err(|_| ErrorCode::Internal)
    }

    /// Strict decoding of a passkey request. Returns the identifier (0 if unreadable) with
    /// the code to answer on failure.
    ///
    /// # Errors
    /// `(id, code)`.
    pub fn decode(frame: &[u8]) -> Result<(u64, PasskeyRequest), (u64, ErrorCode)> {
        let malformed = ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(|_| (0, malformed))?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(|_| (0, malformed))?;
        let id = f.req(2).and_then(uint).map_err(|_| (0, malformed))?;
        let version = f.req(1).and_then(uint).map_err(|_| (id, malformed))?;
        if version != PASSKEY_VERSION {
            return Err((id, ErrorCode::UnsupportedVersion));
        }
        let op = f.req(3).and_then(uint).map_err(|_| (id, malformed))?;
        let op = PasskeyOp::from_u64(op).ok_or((id, ErrorCode::UnknownOperation))?;
        let args = f.opt(4).ok_or((id, malformed))?;
        Self::decode_args(op, args)
            .map(|r| (id, r))
            .map_err(|_| (id, malformed))
    }

    fn decode_args(op: PasskeyOp, args: &Value) -> R<PasskeyRequest> {
        let origin = |f: &Fields<'_>| {
            f.req(1)
                .and_then(|o| text_max(o, MAX_ORIGIN))
                .map(str::to_owned)
        };
        let rp_id = |f: &Fields<'_>| {
            f.req(2)
                .and_then(|r| text_max(r, MAX_RP_ID))
                .map(str::to_owned)
        };
        match op {
            PasskeyOp::PasskeyCreate => {
                let f = Fields::new(args, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
                let algorithms = array_max(f.req(7)?, MAX_ALGORITHMS)?
                    .iter()
                    .map(signed)
                    .collect::<R<Vec<i64>>>()?;
                if algorithms.is_empty() {
                    return Err(cbor::CborError::Malformed);
                }
                Ok(PasskeyRequest::Create(Box::new(CreateArgs {
                    origin: origin(&f)?,
                    rp_id: rp_id(&f)?,
                    challenge: bytes_in(f.req(3)?, CHALLENGE_LEN)?,
                    user_id: bytes_in(f.req(4)?, 1..=MAX_USER_ID)?,
                    user_name: short(f.req(5)?)?,
                    display_name: f.opt(6).map(short).transpose()?,
                    algorithms,
                    exclude: f
                        .opt(8)
                        .map(|e| byte_list(e, MAX_CREDENTIAL_ID))
                        .transpose()?
                        .unwrap_or_default(),
                    uv: uv_from(f.req(9)?)?,
                    rp_name: f.opt(10).map(short).transpose()?,
                })))
            }
            PasskeyOp::PasskeyCandidates => {
                let f = Fields::new(args, &[1, 2, 3])?;
                Ok(PasskeyRequest::Candidates {
                    origin: origin(&f)?,
                    rp_id: rp_id(&f)?,
                    allow: f
                        .opt(3)
                        .map(|a| byte_list(a, MAX_CREDENTIAL_ID))
                        .transpose()?
                        .unwrap_or_default(),
                })
            }
            PasskeyOp::PasskeyAssert => {
                let f = Fields::new(args, &[1, 2, 3, 4, 5, 6])?;
                Ok(PasskeyRequest::Assert {
                    origin: origin(&f)?,
                    rp_id: rp_id(&f)?,
                    challenge: bytes_in(f.req(3)?, CHALLENGE_LEN)?,
                    locker: fixed::<16>(f.req(4)?)?,
                    id: fixed::<16>(f.req(5)?)?,
                    uv: uv_from(f.req(6)?)?,
                })
            }
        }
    }
}

fn opt_text(e: &mut Vec<(u64, Value)>, key: u64, t: Option<&Zeroizing<String>>) {
    if let Some(t) = t {
        e.push((key, Value::text(t)));
    }
}

impl PasskeyReply {
    fn body(&self) -> Value {
        match self {
            PasskeyReply::Created(c) => Value::map(vec![
                (1, Value::bytes(&c.locker)),
                (2, Value::bytes(&c.id)),
                (3, Value::bytes(&c.credential_id)),
                (4, Value::bytes(&c.client_data_json)),
                (5, Value::bytes(&c.attestation_object)),
                (6, Value::bytes(&c.authenticator_data)),
                (7, Value::bytes(&c.public_key)),
                (8, Value::int(c.algorithm)),
            ]),
            PasskeyReply::Candidates(list) => Value::Array(
                list.iter()
                    .map(|c| {
                        let mut e = vec![
                            (1, Value::bytes(&c.locker)),
                            (2, Value::bytes(&c.id)),
                            (3, Value::bytes(&c.credential_id)),
                            (4, Value::text(&c.title)),
                        ];
                        opt_text(&mut e, 5, c.user_name.as_ref());
                        opt_text(&mut e, 6, c.display_name.as_ref());
                        Value::map(e)
                    })
                    .collect(),
            ),
            PasskeyReply::Assertion(a) => {
                let mut e = vec![
                    (1, Value::bytes(&a.credential_id)),
                    (2, Value::bytes(&a.client_data_json)),
                    (3, Value::bytes(&a.authenticator_data)),
                    (4, Value::bytes(&a.signature)),
                ];
                if let Some(h) = &a.user_handle {
                    e.push((5, Value::bytes(h)));
                }
                Value::map(e)
            }
        }
    }

    /// Encodes a reply (success or refusal) to request `id`.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(
        id: u64,
        result: &Result<PasskeyReply, PasskeyCode>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![(1, Value::Uint(PASSKEY_VERSION)), (2, Value::Uint(id))];
        match result {
            Ok(r) => {
                e.push((3, Value::Uint(0)));
                e.push((4, r.body()));
            }
            Err(c) => {
                e.push((3, Value::Uint(c.status())));
                if *c == PasskeyCode::General(ErrorCode::UnsupportedVersion) {
                    e.push((
                        4,
                        Value::map(vec![(2, Value::Array(vec![Value::Uint(PASSKEY_VERSION)]))]),
                    ));
                }
            }
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Decodes the reply to a passkey request of operation `op` (client side, tests).
    ///
    /// # Errors
    /// [`ErrorCode::Malformed`].
    pub fn decode(
        op: PasskeyOp,
        frame: &[u8],
    ) -> Result<(u64, Result<PasskeyReply, PasskeyCode>), ErrorCode> {
        let bad = |_| ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(bad)?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(bad)?;
        let version = f.req(1).and_then(uint).map_err(bad)?;
        let id = f.req(2).and_then(uint).map_err(bad)?;
        let status = f.req(3).and_then(uint).map_err(bad)?;
        if status != 0 {
            let code = PasskeyCode::from_status(status).ok_or(ErrorCode::Malformed)?;
            return Ok((id, Err(code)));
        }
        if version != PASSKEY_VERSION {
            return Err(ErrorCode::Malformed);
        }
        let body = f.opt(4).ok_or(ErrorCode::Malformed)?;
        let reply = Self::decode_body(op, body).map_err(bad)?;
        Ok((id, Ok(reply)))
    }

    fn decode_body(op: PasskeyOp, body: &Value) -> R<PasskeyReply> {
        let blob = |v: &Value, max| bytes_in(v, 1..=max);
        Ok(match op {
            PasskeyOp::PasskeyCreate => {
                let b = Fields::new(body, &[1, 2, 3, 4, 5, 6, 7, 8])?;
                PasskeyReply::Created(Box::new(Created {
                    locker: fixed::<16>(b.req(1)?)?,
                    id: fixed::<16>(b.req(2)?)?,
                    credential_id: blob(b.req(3)?, MAX_CREDENTIAL_ID)?,
                    client_data_json: blob(b.req(4)?, MAX_CLIENT_DATA)?,
                    attestation_object: blob(b.req(5)?, MAX_BLOB)?,
                    authenticator_data: blob(b.req(6)?, MAX_BLOB)?,
                    public_key: blob(b.req(7)?, MAX_BLOB)?,
                    algorithm: signed(b.req(8)?)?,
                }))
            }
            PasskeyOp::PasskeyCandidates => PasskeyReply::Candidates(
                array_max(body, MAX_CANDIDATES)?
                    .iter()
                    .map(|c| {
                        let c = Fields::new(c, &[1, 2, 3, 4, 5, 6])?;
                        Ok(Candidate {
                            locker: fixed::<16>(c.req(1)?)?,
                            id: fixed::<16>(c.req(2)?)?,
                            credential_id: blob(c.req(3)?, MAX_CREDENTIAL_ID)?,
                            title: short(c.req(4)?)?,
                            user_name: c.opt(5).map(short).transpose()?,
                            display_name: c.opt(6).map(short).transpose()?,
                        })
                    })
                    .collect::<R<Vec<_>>>()?,
            ),
            PasskeyOp::PasskeyAssert => {
                let b = Fields::new(body, &[1, 2, 3, 4, 5])?;
                PasskeyReply::Assertion(Box::new(Assertion {
                    credential_id: blob(b.req(1)?, MAX_CREDENTIAL_ID)?,
                    client_data_json: blob(b.req(2)?, MAX_CLIENT_DATA)?,
                    authenticator_data: blob(b.req(3)?, MAX_BLOB)?,
                    signature: blob(b.req(4)?, MAX_BLOB)?,
                    user_handle: b.opt(5).map(|h| bytes_in(h, 1..=MAX_USER_ID)).transpose()?,
                }))
            }
        })
    }
}
