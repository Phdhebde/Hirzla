//! The passkey messages of the extension (ADR 0079 § 5): `passkey_create`,
//! `passkey_candidates` and `passkey_assert`, turned into requests of the local API
//! version 14 and back.
//!
//! The JSON stays flat (ADR 0027): bytes are base64url without padding, lists are texts
//! separated by commas (`"algs": "-7,-8"`, `"allow": "AbC,dEf"`). The host checks the origin
//! and the form of every value; the core decides whether the site may use the relying party
//! identifier and holds every key.

use data_encoding::BASE64URL_NOPAD;
use hirzla_core::passkey::proto::{
    CreateArgs, PasskeyReply, PasskeyRequest, UserVerification, CHALLENGE_LEN, MAX_CREDENTIAL_ID,
    MAX_RP_ID, MAX_USER_ID,
};
use zeroize::Zeroizing;

use crate::host::{client_error, error_json, hex, id16, origin, text, CoreLink, HostError};
use crate::json::{encoded_len, Object, Writer};

/// Longest user name, display name or relying party name accepted from the extension.
const MAX_NAME: usize = 1024;
/// Most identifiers in `allow` or `exclude`, and most algorithms.
const MAX_LIST: usize = 64;

fn required<'a>(o: &'a Object, key: &str) -> Result<&'a Zeroizing<String>, HostError> {
    text(o, key)?.ok_or(HostError::BadRequest)
}

/// Bytes in base64url without padding, of `range` length once decoded.
fn b64(s: &str, range: std::ops::RangeInclusive<usize>) -> Result<Vec<u8>, HostError> {
    let b = BASE64URL_NOPAD
        .decode(s.as_bytes())
        .map_err(|_| HostError::InvalidInput)?;
    if range.contains(&b.len()) {
        Ok(b)
    } else {
        Err(HostError::InvalidInput)
    }
}

/// A list of credential identifiers, comma separated; absent or empty: none.
fn id_list(o: &Object, key: &str) -> Result<Vec<Vec<u8>>, HostError> {
    let Some(t) = text(o, key)? else {
        return Ok(Vec::new());
    };
    if t.is_empty() {
        return Ok(Vec::new());
    }
    let items: Vec<&str> = t.split(',').collect();
    if items.len() > MAX_LIST {
        return Err(HostError::InvalidInput);
    }
    items
        .into_iter()
        .map(|i| b64(i, 1..=MAX_CREDENTIAL_ID))
        .collect()
}

fn rp_id(o: &Object) -> Result<String, HostError> {
    let r = required(o, "rpId")?;
    if r.is_empty() || r.len() > MAX_RP_ID {
        return Err(HostError::InvalidInput);
    }
    Ok(r.as_str().to_owned())
}

fn uv(o: &Object) -> Result<UserVerification, HostError> {
    match text(o, "uv")?.map(|t| t.as_str()) {
        None | Some("preferred") => Ok(UserVerification::Preferred),
        Some("required") => Ok(UserVerification::Required),
        Some("discouraged") => Ok(UserVerification::Discouraged),
        Some(_) => Err(HostError::InvalidInput),
    }
}

fn name(o: &Object, key: &str) -> Result<Option<Zeroizing<String>>, HostError> {
    match text(o, key)? {
        None => Ok(None),
        Some(t) if t.is_empty() => Ok(None),
        Some(t) if t.len() > MAX_NAME || t.chars().any(char::is_control) => {
            Err(HostError::InvalidInput)
        }
        Some(t) => Ok(Some(t.clone())),
    }
}

fn algorithms(o: &Object) -> Result<Vec<i64>, HostError> {
    let t = required(o, "algs")?;
    let items: Vec<&str> = t.split(',').collect();
    if t.is_empty() || items.len() > MAX_LIST {
        return Err(HostError::InvalidInput);
    }
    items
        .into_iter()
        .map(|a| a.parse::<i64>().map_err(|_| HostError::InvalidInput))
        .collect()
}

/// Checks a passkey message of type `kind`.
///
/// # Errors
/// [`HostError`].
pub fn parse(kind: &str, o: &Object) -> Result<PasskeyRequest, HostError> {
    let keys: &[&str] = match kind {
        "passkey_candidates" => &["type", "origin", "rpId", "allow"],
        "passkey_assert" => &["type", "origin", "rpId", "challenge", "locker", "id", "uv"],
        "passkey_create" => &[
            "type",
            "origin",
            "rpId",
            "rpName",
            "challenge",
            "userId",
            "userName",
            "displayName",
            "algs",
            "exclude",
            "uv",
        ],
        _ => return Err(HostError::BadRequest),
    };
    if !o.only(keys) {
        return Err(HostError::BadRequest);
    }
    let origin = origin(o)?;
    let rp_id = rp_id(o)?;
    Ok(match kind {
        "passkey_candidates" => PasskeyRequest::Candidates {
            origin,
            rp_id,
            allow: id_list(o, "allow")?,
        },
        "passkey_assert" => PasskeyRequest::Assert {
            origin,
            rp_id,
            challenge: b64(required(o, "challenge")?, CHALLENGE_LEN)?,
            locker: id16(o, "locker")?,
            id: id16(o, "id")?,
            uv: uv(o)?,
        },
        _ => PasskeyRequest::Create(Box::new(CreateArgs {
            origin,
            rp_id,
            challenge: b64(required(o, "challenge")?, CHALLENGE_LEN)?,
            user_id: b64(required(o, "userId")?, 1..=MAX_USER_ID)?,
            user_name: name(o, "userName")?.unwrap_or_default(),
            display_name: name(o, "displayName")?,
            algorithms: algorithms(o)?,
            exclude: id_list(o, "exclude")?,
            uv: uv(o)?,
            rp_name: name(o, "rpName")?,
        })),
    })
}

fn b64_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Answers a checked passkey message.
pub fn respond(core: &mut impl CoreLink, request: &PasskeyRequest) -> Zeroizing<String> {
    let reply = match core.call_passkey(request) {
        Ok(Ok(r)) => r,
        Ok(Err(code)) => return error_json(code.name()),
        Err(e) => return client_error(&e),
    };
    let e = |b: &[u8]| BASE64URL_NOPAD.encode(b);
    match (request, reply) {
        (PasskeyRequest::Create(_), PasskeyReply::Created(c)) => {
            let mut w = Writer::with_capacity(
                256 + b64_len(
                    c.credential_id.len()
                        + c.client_data_json.len()
                        + c.attestation_object.len()
                        + c.authenticator_data.len()
                        + c.public_key.len(),
                ),
            );
            w.raw("{\"ok\":true,\"credential\":")
                .string(&e(&c.credential_id))
                .raw(",\"clientData\":")
                .string(&e(&c.client_data_json))
                .raw(",\"attestation\":")
                .string(&e(&c.attestation_object))
                .raw(",\"authData\":")
                .string(&e(&c.authenticator_data))
                .raw(",\"publicKey\":")
                .string(&e(&c.public_key))
                .raw(",\"alg\":")
                .raw(&c.algorithm.to_string())
                .raw("}");
            w.finish()
        }
        (PasskeyRequest::Candidates { .. }, PasskeyReply::Candidates(list)) => {
            let capacity = 64
                + list
                    .iter()
                    .map(|c| {
                        160 + b64_len(c.credential_id.len())
                            + encoded_len(c.title.len())
                            + c.user_name.as_ref().map_or(0, |u| encoded_len(u.len()))
                            + c.display_name.as_ref().map_or(0, |d| encoded_len(d.len()))
                    })
                    .sum::<usize>();
            let mut w = Writer::with_capacity(capacity);
            w.raw("{\"ok\":true,\"candidates\":[");
            for (i, c) in list.iter().enumerate() {
                if i > 0 {
                    w.raw(",");
                }
                w.raw("{\"locker\":")
                    .string(&hex(&c.locker))
                    .raw(",\"id\":")
                    .string(&hex(&c.id))
                    .raw(",\"credential\":")
                    .string(&e(&c.credential_id))
                    .raw(",\"title\":")
                    .string(&c.title);
                if let Some(u) = &c.user_name {
                    w.raw(",\"userName\":").string(u);
                }
                if let Some(d) = &c.display_name {
                    w.raw(",\"displayName\":").string(d);
                }
                w.raw("}");
            }
            w.raw("]}");
            w.finish()
        }
        (PasskeyRequest::Assert { .. }, PasskeyReply::Assertion(a)) => {
            let mut w = Writer::with_capacity(
                192 + b64_len(
                    a.credential_id.len()
                        + a.client_data_json.len()
                        + a.authenticator_data.len()
                        + a.signature.len()
                        + a.user_handle.as_ref().map_or(0, Vec::len),
                ),
            );
            w.raw("{\"ok\":true,\"credential\":")
                .string(&e(&a.credential_id))
                .raw(",\"clientData\":")
                .string(&e(&a.client_data_json))
                .raw(",\"authData\":")
                .string(&e(&a.authenticator_data))
                .raw(",\"signature\":")
                .string(&e(&a.signature));
            if let Some(h) = &a.user_handle {
                w.raw(",\"userHandle\":").string(&e(h));
            }
            w.raw("}");
            w.finish()
        }
        _ => error_json("core_error"),
    }
}
