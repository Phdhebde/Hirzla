//! FIDO2 over HID on Linux and macOS (ADR 0075 § 3), through `ctap-hid-fido2` (feature
//! `fido2-hid`, off by default). The PIN of the security key is typed in the client and passed
//! to the core like the master password; user verification is always required.
//!
//! The WebAuthn PRF transformation is applied here (`hirzla_crypto::util::webauthn_prf_salt`),
//! so that a key enrolled under Windows (`webauthn.dll`) gives the same output.
//!
//! Limits stated in ADR 0075 § 8: the library keeps the PIN and the `hmac-secret` output in
//! buffers it does not wipe; only one security key may be plugged in.

use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::{
    Extension as AssertionExtension, GetAssertionArgsBuilder,
};
use ctap_hid_fido2::fidokey::make_credential::make_credential_params::{
    Extension as CredentialExtension, MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::{get_fidokey_devices, FidoKeyHid, FidoKeyHidFactory, LibCfg};
use hirzla_crypto::util::webauthn_prf_salt;
use zeroize::{Zeroize, Zeroizing};

use super::{FactorError, FactorKind, Gesture, KeyRef, Material, UnlockFactor, FIDO2_RP_ID};

/// FIDO2 security key over HID.
pub struct HidFido2;

/// Maps a library error (text only) to what the user is told. CTAP status codes, from the
/// CTAP 2.1 specification: 0x31 PIN invalid, 0x32 PIN blocked, 0x34 PIN auth blocked,
/// 0x35 PIN not set, 0x36 PIN required, 0x2E no credentials, 0x27 operation denied,
/// 0x2F user action timeout.
fn library_error(e: &anyhow::Error) -> FactorError {
    let text = e.to_string();
    let has = |code: &str| text.contains(code);
    if has("0x31") || has("0x36") || has("0x35") {
        FactorError::PinRequired
    } else if has("0x32") || has("0x34") {
        FactorError::PinBlocked
    } else if has("0x2E") {
        FactorError::Invalidated
    } else if has("0x27") || has("0x2F") {
        FactorError::Cancelled
    } else {
        FactorError::Failed
    }
}

fn device() -> Result<FidoKeyHid, FactorError> {
    let mut cfg = LibCfg::init();
    // The core has no terminal: no "touch the sensor" line on its standard output.
    cfg.enable_keep_alive_msg = false;
    cfg.enable_log = false;
    FidoKeyHidFactory::create(&cfg).map_err(|_| FactorError::Unavailable)
}

/// One assertion with PRF input `salt`; returns the first output.
fn prf(
    dev: &FidoKeyHid,
    credential_id: &[u8],
    salt: &[u8; 32],
    pin: &str,
    challenge: &[u8; 32],
) -> Result<Material, FactorError> {
    let mut salt1 = webauthn_prf_salt(salt);
    let args = GetAssertionArgsBuilder::new(FIDO2_RP_ID, challenge)
        .pin(pin)
        .credential_id(credential_id)
        .extensions(&[AssertionExtension::HmacSecret(Some(salt1))])
        .build();
    salt1.zeroize();
    let mut assertions = dev
        .get_assertion_with_args(&args)
        .map_err(|e| library_error(&e))?;
    let mut out = None;
    for a in &mut assertions {
        for ext in &mut a.extensions {
            if let AssertionExtension::HmacSecret(Some(bytes)) = ext {
                if out.is_none() {
                    out = Some(Zeroizing::new(bytes.to_vec()));
                }
                bytes.zeroize();
            }
        }
    }
    // Without an output, the key does not support `hmac-secret`.
    out.map(Material::new).ok_or(FactorError::Unavailable)
}

impl UnlockFactor for HidFido2 {
    fn kind(&self) -> FactorKind {
        FactorKind::Fido2
    }

    fn available(&self) -> bool {
        !get_fidokey_devices().is_empty()
    }

    fn needs_pin(&self) -> bool {
        true
    }

    fn enrol(&self, gesture: &Gesture<'_>) -> Result<(KeyRef, Material), FactorError> {
        let pin = gesture.pin.ok_or(FactorError::PinRequired)?;
        let dev = device()?;
        let challenge = gesture.call_random();
        let args = MakeCredentialArgsBuilder::new(FIDO2_RP_ID, &challenge)
            .pin(pin)
            .extensions(&[CredentialExtension::HmacSecret(Some(true))])
            .build();
        let attestation = dev
            .make_credential_with_args(&args)
            .map_err(|e| library_error(&e))?;
        let credential_id = attestation.credential_descriptor.id.clone();
        if credential_id.is_empty() || credential_id.len() > 1023 {
            return Err(FactorError::Failed);
        }
        let salt = gesture.header_random();
        let material = prf(&dev, &credential_id, &salt, pin, &challenge)?;
        Ok((
            KeyRef::Fido2 {
                credential_id,
                salt,
            },
            material,
        ))
    }

    fn release(&self, key: &KeyRef, gesture: &Gesture<'_>) -> Result<Material, FactorError> {
        let KeyRef::Fido2 {
            credential_id,
            salt,
        } = key
        else {
            return Err(FactorError::Invalidated);
        };
        let pin = gesture.pin.ok_or(FactorError::PinRequired)?;
        let dev = device()?;
        prf(&dev, credential_id, salt, pin, &gesture.call_random())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctap_status_codes_map_to_what_the_user_is_told() {
        let e = |s: &str| library_error(&anyhow::anyhow!(s.to_owned()));
        assert_eq!(e("0x31 CTAP2_ERR_PIN_INVALID"), FactorError::PinRequired);
        assert_eq!(e("0x32 CTAP2_ERR_PIN_BLOCKED"), FactorError::PinBlocked);
        assert_eq!(e("0x2E CTAP2_ERR_NO_CREDENTIALS"), FactorError::Invalidated);
        assert_eq!(e("0x27 CTAP2_ERR_OPERATION_DENIED"), FactorError::Cancelled);
        assert_eq!(e("FIDO device not found."), FactorError::Failed);
    }
}
