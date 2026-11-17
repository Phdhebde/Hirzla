//! Encrypted export of a locker, `.hirzla-export` (`docs/format.md` § 16, ADR 0077).
//!
//! The file carries the current state of the active secrets of one locker, their attachments
//! and the locker's description, sealed under a key derived from an export password:
//!
//! ```text
//! S        = Argon2id(NFC(password), salt, m, t, p)
//! K_export = HKDF-SHA-512(S, salt = export_id, info = "hirzla/v1/locker-export-key")
//! ```
//!
//! Every part is a [`SealedBox`] of KEK `K_export`, after padding (§ 11). No identifier, key,
//! stamp or signature of the exporter's vault goes into the file: the importer rewrites
//! everything under its own keys ([`crate::Vault::import_locker`]).
//!
//! This module is pure: bytes in, bytes out. Reading and writing files is the core's job.

use hirzla_crypto::kdf::{self, KdfLabel};
use hirzla_crypto::password::{self, PasswordParams, SALT_LEN};
use hirzla_crypto::sym::{SymmetricKey, SEALED_BOX_OVERHEAD};
use hirzla_crypto::util::random_array;
use zeroize::Zeroizing;

use crate::cbor::{
    self, array_max, boolean, bytes_max, check_sorted, fixed, text_max, uint, uint_in, Fields,
    Value,
};
use crate::error::{ExportRefusal, VaultError};
use crate::model::{Dot, Id16, Stamp};
use crate::pad;
use crate::secret::{
    self, apply_edit, chunk_count, AttachmentRef, CustomField, Field, FieldValue, SecretEdit,
    SecretLink, SecretType, SetKind, SetValue, CHUNK_LEN, MAX_ATTACHMENT, MAX_CUSTOM,
};
use crate::vault::{nfc, seal_padded, unseal_padded};

/// Magic text of an export file.
pub const MAGIC: &str = "hirzla-export";
/// Version of the export format written and read by this build.
pub const VERSION: u64 = 1;
/// Largest export file, in bytes (256 MiB).
pub const MAX_FILE: usize = 256 * 1024 * 1024;
/// Largest encoded manifest, before padding (64 MiB).
pub const MAX_MANIFEST: usize = 64 * 1024 * 1024;
/// Most secrets in one export.
pub const MAX_SECRETS: usize = 100_000;
/// Most attachments in one export.
pub const MAX_ATTACHMENTS: usize = 4096;
/// Most attachment chunks in one export.
pub const MAX_CHUNKS: usize = 65_536;
/// Most folder names in the folder path of a secret.
pub const MAX_FOLDER_DEPTH: usize = 16;
/// Longest folder name, in bytes.
pub const MAX_FOLDER_NAME: usize = 256;
/// Fewest characters of an export password chosen by the user (after NFC).
pub const MIN_PASSWORD_CHARS: usize = 16;
/// Fewest distinct characters of an export password chosen by the user.
pub const MIN_PASSWORD_DISTINCT: usize = 8;
/// Argon2 version 1.3, as written in the `kdf` map.
const ARGON2_VERSION: u64 = 19;
/// Longest attachment name and media type (§ 8.4).
const MAX_ATTACHMENT_NAME: usize = 512;
const MAX_MEDIA_TYPE: usize = 128;
/// Most attachments of one secret (§ 8.2).
const MAX_SECRET_ATTACHMENTS: usize = 64;
/// Longest locker name, description and icon (§ 7.4).
const MAX_LOCKER_NAME: usize = 256;
const MAX_DESCRIPTION: usize = 4096;
const MAX_ICON: usize = 64;
/// Longest custom field label and value (§ 8.3).
const MAX_CUSTOM_LABEL: usize = 256;
const MAX_CUSTOM_VALUE: usize = 65_536;

/// Cost of the Argon2id derivation written into a new export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportCost {
    /// Memory, KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

impl ExportCost {
    /// The cost written by the core: 256 MiB, 3 passes, 4 lanes. Fixed, not calibrated: the
    /// importer's device pays it (ADR 0077).
    pub const DEFAULT: ExportCost = ExportCost {
        m_kib: 262_144,
        t: 3,
        p: 4,
    };
}

/// Description of the exported locker (`docs/format.md` § 7.4).
#[derive(Clone, PartialEq, Eq)]
pub struct ExportLocker {
    /// Name, 1 to 256 bytes.
    pub name: Zeroizing<String>,
    /// Description.
    pub description: Option<Zeroizing<String>>,
    /// Colour index.
    pub color: Option<u64>,
    /// Icon.
    pub icon: Option<String>,
}

/// One attachment, in clear once the file is opened.
#[derive(Clone, PartialEq, Eq)]
pub struct ExportAttachment {
    /// File name.
    pub name: String,
    /// Media type.
    pub media_type: String,
    /// Content, erased on drop.
    pub data: Zeroizing<Vec<u8>>,
}

/// One secret: its current state, without stamps nor identifiers.
#[derive(Clone, PartialEq, Eq)]
pub struct ExportSecret {
    /// Type.
    pub secret_type: SecretType,
    /// Fields of `fields` (§ 8.2, § 8.3), links excluded; sorted by field, one per field.
    pub fields: Vec<(Field, FieldValue)>,
    /// Links (§ 8.5): field and rank of the target in [`ExportContent::secrets`].
    pub links: Vec<(Field, u32)>,
    /// Text sets: tags, URLs, hosts.
    pub sets: Vec<(SetKind, Vec<Zeroizing<String>>)>,
    /// Custom fields, in order.
    pub custom: Vec<CustomField>,
    /// Ranks of its attachments in [`ExportContent::attachments`].
    pub attachments: Vec<u32>,
    /// Folder path, from the root (ADR 0076); empty if none.
    pub folder: Vec<Zeroizing<String>>,
}

impl core::fmt::Debug for ExportSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Type and counts only: titles and values are confidential.
        f.debug_struct("ExportSecret")
            .field("type", &self.secret_type)
            .field("fields", &self.fields.len())
            .field("links", &self.links.len())
            .field("custom", &self.custom.len())
            .field("attachments", &self.attachments.len())
            .finish_non_exhaustive()
    }
}

/// What an export file carries, in clear.
#[derive(Clone, PartialEq, Eq)]
pub struct ExportContent {
    /// Indicative wall clock of the export, milliseconds.
    pub created_ms: u64,
    /// The locker.
    pub locker: ExportLocker,
    /// The secrets.
    pub secrets: Vec<ExportSecret>,
    /// The attachments.
    pub attachments: Vec<ExportAttachment>,
}

impl core::fmt::Debug for ExportContent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Counts only: names, titles and values are confidential.
        f.debug_struct("ExportContent")
            .field("secrets", &self.secrets.len())
            .field("attachments", &self.attachments.len())
            .finish_non_exhaustive()
    }
}

fn refuse(r: ExportRefusal) -> VaultError {
    VaultError::Export(r)
}

fn malformed<E>(_: E) -> VaultError {
    refuse(ExportRefusal::Malformed)
}

/// Checks an export password chosen by the user: at least [`MIN_PASSWORD_CHARS`] characters
/// after NFC normalisation, [`MIN_PASSWORD_DISTINCT`] of them distinct. A floor, not a
/// strength measure: the core proposes a generated passphrase instead.
///
/// # Errors
/// [`ExportRefusal::WeakPassword`].
pub fn check_password(password: &str) -> Result<(), VaultError> {
    let weak = refuse(ExportRefusal::WeakPassword);
    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(
        match icu_normalizer::ComposingNormalizerBorrowed::new_nfc().normalize(password) {
            std::borrow::Cow::Borrowed(same) => same.chars().collect(),
            // The normaliser allocated a copy of the password: wipe it once read.
            std::borrow::Cow::Owned(mut copy) => {
                let c = copy.chars().collect();
                zeroize::Zeroize::zeroize(&mut copy);
                c
            }
        },
    );
    if chars.len() < MIN_PASSWORD_CHARS {
        return Err(weak);
    }
    chars.sort_unstable();
    chars.dedup();
    if chars.len() < MIN_PASSWORD_DISTINCT {
        return Err(weak);
    }
    Ok(())
}

// -----------------------------------------------------------------------------------------
// Keys and associated data
// -----------------------------------------------------------------------------------------

fn export_key(
    password: &str,
    params: &PasswordParams,
    export_id: &Id16,
) -> Result<SymmetricKey, VaultError> {
    let pwd = nfc(password)?;
    let s = password::derive_key(&pwd, params)?;
    Ok(kdf::derive_key(&s, export_id, KdfLabel::LockerExport)?)
}

fn aad_manifest(export_id: &Id16, chunks: u64) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    Ok(cbor::encode(&Value::map(vec![
        (1, Value::text("hirzla/v1/locker-export")),
        (2, Value::bytes(export_id)),
        (3, Value::Uint(VERSION)),
        (4, Value::Uint(chunks)),
    ]))?)
}

fn aad_chunk(
    export_id: &Id16,
    attachment: u64,
    rank: u64,
    chunks: u64,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    Ok(cbor::encode(&Value::map(vec![
        (1, Value::text("hirzla/v1/locker-export-chunk")),
        (2, Value::bytes(export_id)),
        (3, Value::Uint(attachment)),
        (4, Value::Uint(rank)),
        (5, Value::Uint(chunks)),
    ]))?)
}

/// Largest sealed chunk: a full chunk padded to 1 MiB, plus the box.
fn max_chunk_box() -> usize {
    pad::padded_len(usize::try_from(CHUNK_LEN).unwrap_or(usize::MAX)) + SEALED_BOX_OVERHEAD
}

/// Largest sealed manifest.
fn max_manifest_box() -> usize {
    pad::padded_len(MAX_MANIFEST) + SEALED_BOX_OVERHEAD
}

// -----------------------------------------------------------------------------------------
// Manifest encoding
// -----------------------------------------------------------------------------------------

fn texts_value(items: &[Zeroizing<String>]) -> Value {
    Value::Array(items.iter().map(|t| Value::text(t)).collect())
}

fn ranks_value(items: &[u32]) -> Value {
    Value::Array(items.iter().map(|n| Value::Uint(u64::from(*n))).collect())
}

fn secret_value(s: &ExportSecret) -> Result<Value, VaultError> {
    let mut e = vec![
        (1, Value::Uint(s.secret_type as u64)),
        (
            2,
            Value::Map(
                s.fields
                    .iter()
                    .map(|(f, v)| (Value::Uint(*f as u64), secret::field_value_to_value(v)))
                    .collect(),
            ),
        ),
    ];
    if !s.links.is_empty() {
        e.push((
            3,
            Value::Map(
                s.links
                    .iter()
                    .map(|(f, r)| (Value::Uint(*f as u64), Value::Uint(u64::from(*r))))
                    .collect(),
            ),
        ));
    }
    if !s.sets.is_empty() {
        let mut sets = Vec::with_capacity(s.sets.len());
        for (k, items) in &s.sets {
            let values = cbor::sorted(items.iter().map(|t| Value::text(t)).collect())?;
            sets.push((Value::Uint(*k as u64), Value::Array(values)));
        }
        e.push((4, Value::Map(sets)));
    }
    if !s.custom.is_empty() {
        e.push((
            5,
            Value::Array(
                s.custom
                    .iter()
                    .map(|c| {
                        Value::map(vec![
                            (1, Value::text(&c.label)),
                            (2, Value::text(&c.value)),
                            (3, Value::Bool(c.sensitive)),
                        ])
                    })
                    .collect(),
            ),
        ));
    }
    if !s.attachments.is_empty() {
        let mut ranks = s.attachments.clone();
        ranks.sort_unstable();
        ranks.dedup();
        e.push((6, ranks_value(&ranks)));
    }
    if !s.folder.is_empty() {
        e.push((7, texts_value(&s.folder)));
    }
    Ok(Value::map(e))
}

fn manifest_value(c: &ExportContent) -> Result<Value, VaultError> {
    let mut locker = vec![(1, Value::text(&c.locker.name))];
    if let Some(d) = &c.locker.description {
        locker.push((2, Value::text(d)));
    }
    if let Some(n) = c.locker.color {
        locker.push((3, Value::Uint(n)));
    }
    if let Some(i) = &c.locker.icon {
        locker.push((4, Value::text(i)));
    }
    let secrets = c
        .secrets
        .iter()
        .map(secret_value)
        .collect::<Result<Vec<_>, _>>()?;
    let attachments = c
        .attachments
        .iter()
        .map(|a| {
            let size = u64::try_from(a.data.len()).map_err(|_| VaultError::InvalidInput)?;
            Ok(Value::map(vec![
                (1, Value::text(&a.name)),
                (2, Value::text(&a.media_type)),
                (3, Value::Uint(size)),
                (4, Value::Uint(chunk_count(size))),
            ]))
        })
        .collect::<Result<Vec<_>, VaultError>>()?;
    Ok(Value::map(vec![
        (1, Value::Uint(c.created_ms)),
        (2, Value::map(locker)),
        (3, Value::Array(secrets)),
        (4, Value::Array(attachments)),
    ]))
}

/// An attachment as the manifest describes it, before its chunks are opened.
struct AttachmentEntry {
    name: String,
    media_type: String,
    size: u64,
    chunks: u64,
}

fn text_list(
    v: &Value,
    max_items: usize,
    max_len: usize,
) -> Result<Vec<Zeroizing<String>>, VaultError> {
    let items = array_max(v, max_items).map_err(malformed)?;
    items
        .iter()
        .map(|t| {
            let s = text_max(t, max_len).map_err(malformed)?;
            Ok(Zeroizing::new(s.to_owned()))
        })
        .collect()
}

fn decode_secret(
    v: &Value,
    rank: usize,
    secrets: usize,
    attachments: usize,
) -> Result<ExportSecret, VaultError> {
    let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7]).map_err(malformed)?;
    let n = uint(f.req(1).map_err(malformed)?).map_err(malformed)?;
    let secret_type = SecretType::ALL
        .into_iter()
        .find(|t| *t as u64 == n)
        .ok_or_else(|| refuse(ExportRefusal::Malformed))?;

    let Value::Map(fm) = f.req(2).map_err(malformed)? else {
        return Err(refuse(ExportRefusal::Malformed));
    };
    let mut fields = Vec::with_capacity(fm.len());
    for (k, val) in fm {
        let field = Field::from_u64(uint(k).map_err(malformed)?)
            .ok_or_else(|| refuse(ExportRefusal::Malformed))?;
        if secret::is_link_field(secret_type, field) {
            return Err(refuse(ExportRefusal::Malformed));
        }
        let value = secret::field_value_from_value(secret_type, field, val).map_err(malformed)?;
        fields.push((field, value));
    }

    let mut links = Vec::new();
    if let Some(lv) = f.opt(3) {
        let Value::Map(lm) = lv else {
            return Err(refuse(ExportRefusal::Malformed));
        };
        if lm.is_empty() {
            return Err(refuse(ExportRefusal::Malformed));
        }
        for (k, val) in lm {
            let field = Field::from_u64(uint(k).map_err(malformed)?)
                .ok_or_else(|| refuse(ExportRefusal::Malformed))?;
            if !secret::is_link_field(secret_type, field) {
                return Err(refuse(ExportRefusal::Malformed));
            }
            let target = uint(val).map_err(malformed)?;
            // A link names another secret of the file (§ 8.5: never itself).
            let target = usize::try_from(target).map_err(malformed)?;
            if target >= secrets || target == rank {
                return Err(refuse(ExportRefusal::Malformed));
            }
            links.push((field, u32::try_from(target).map_err(malformed)?));
        }
    }

    let mut sets = Vec::new();
    if let Some(sv) = f.opt(4) {
        let Value::Map(sm) = sv else {
            return Err(refuse(ExportRefusal::Malformed));
        };
        if sm.is_empty() {
            return Err(refuse(ExportRefusal::Malformed));
        }
        for (k, val) in sm {
            let kind = SetKind::from_u64(uint(k).map_err(malformed)?)
                .ok_or_else(|| refuse(ExportRefusal::Malformed))?;
            let (len, max) = secret::text_set_bounds(secret_type, kind)
                .ok_or_else(|| refuse(ExportRefusal::Malformed))?;
            let items = array_max(val, max).map_err(malformed)?;
            if items.is_empty() {
                return Err(refuse(ExportRefusal::Malformed));
            }
            check_sorted(items).map_err(malformed)?;
            sets.push((kind, text_list(val, max, len)?));
        }
    }

    let mut custom = Vec::new();
    if let Some(cv) = f.opt(5) {
        let items = array_max(cv, MAX_CUSTOM).map_err(malformed)?;
        if items.is_empty() {
            return Err(refuse(ExportRefusal::Malformed));
        }
        for item in items {
            let c = Fields::new(item, &[1, 2, 3]).map_err(malformed)?;
            custom.push(CustomField {
                label: text_max(c.req(1).map_err(malformed)?, MAX_CUSTOM_LABEL)
                    .map_err(malformed)?
                    .to_owned(),
                value: Zeroizing::new(
                    text_max(c.req(2).map_err(malformed)?, MAX_CUSTOM_VALUE)
                        .map_err(malformed)?
                        .to_owned(),
                ),
                sensitive: boolean(c.req(3).map_err(malformed)?).map_err(malformed)?,
            });
        }
    }

    let mut ranks = Vec::new();
    if let Some(av) = f.opt(6) {
        let items = array_max(av, MAX_SECRET_ATTACHMENTS).map_err(malformed)?;
        if items.is_empty() {
            return Err(refuse(ExportRefusal::Malformed));
        }
        check_sorted(items).map_err(malformed)?;
        for item in items {
            let r = uint(item).map_err(malformed)?;
            let r = usize::try_from(r).map_err(malformed)?;
            if r >= attachments {
                return Err(refuse(ExportRefusal::Malformed));
            }
            ranks.push(u32::try_from(r).map_err(malformed)?);
        }
    }

    let mut folder = Vec::new();
    if let Some(fv) = f.opt(7) {
        folder = text_list(fv, MAX_FOLDER_DEPTH, MAX_FOLDER_NAME)?;
        if folder.is_empty() || folder.iter().any(|n| n.is_empty()) {
            return Err(refuse(ExportRefusal::Malformed));
        }
    }

    Ok(ExportSecret {
        secret_type,
        fields,
        links,
        sets,
        custom,
        attachments: ranks,
        folder,
    })
}

/// The decoded manifest, attachments not yet opened.
struct Manifest {
    created_ms: u64,
    locker: ExportLocker,
    secrets: Vec<ExportSecret>,
    attachments: Vec<AttachmentEntry>,
}

fn decode_manifest(bytes: &[u8]) -> Result<Manifest, VaultError> {
    let v = cbor::decode(bytes).map_err(malformed)?;
    let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(malformed)?;
    let created_ms = uint(f.req(1).map_err(malformed)?).map_err(malformed)?;

    let l = Fields::new(f.req(2).map_err(malformed)?, &[1, 2, 3, 4]).map_err(malformed)?;
    let name = text_max(l.req(1).map_err(malformed)?, MAX_LOCKER_NAME).map_err(malformed)?;
    if name.is_empty() {
        return Err(refuse(ExportRefusal::Malformed));
    }
    let locker = ExportLocker {
        name: Zeroizing::new(name.to_owned()),
        description: l
            .opt(2)
            .map(|d| text_max(d, MAX_DESCRIPTION).map(|s| Zeroizing::new(s.to_owned())))
            .transpose()
            .map_err(malformed)?,
        color: l.opt(3).map(uint).transpose().map_err(malformed)?,
        icon: l
            .opt(4)
            .map(|i| text_max(i, MAX_ICON).map(str::to_owned))
            .transpose()
            .map_err(malformed)?,
    };

    let att_items = array_max(f.req(4).map_err(malformed)?, MAX_ATTACHMENTS).map_err(malformed)?;
    let mut attachments = Vec::with_capacity(att_items.len());
    for a in att_items {
        let af = Fields::new(a, &[1, 2, 3, 4]).map_err(malformed)?;
        let size = uint_in(af.req(3).map_err(malformed)?, 0..=MAX_ATTACHMENT).map_err(malformed)?;
        let chunks = uint(af.req(4).map_err(malformed)?).map_err(malformed)?;
        if chunks != chunk_count(size) {
            return Err(refuse(ExportRefusal::Malformed));
        }
        attachments.push(AttachmentEntry {
            name: text_max(af.req(1).map_err(malformed)?, MAX_ATTACHMENT_NAME)
                .map_err(malformed)?
                .to_owned(),
            media_type: text_max(af.req(2).map_err(malformed)?, MAX_MEDIA_TYPE)
                .map_err(malformed)?
                .to_owned(),
            size,
            chunks,
        });
    }

    let sec_items = array_max(f.req(3).map_err(malformed)?, MAX_SECRETS).map_err(malformed)?;
    let mut secrets = Vec::with_capacity(sec_items.len());
    for (rank, s) in sec_items.iter().enumerate() {
        secrets.push(decode_secret(s, rank, sec_items.len(), attachments.len())?);
    }
    // Every attachment belongs to at least one secret: a writer never adds an orphan.
    let mut cited = vec![false; attachments.len()];
    for s in &secrets {
        for r in &s.attachments {
            if let Some(c) = cited.get_mut(*r as usize) {
                *c = true;
            }
        }
    }
    if cited.iter().any(|c| !c) {
        return Err(refuse(ExportRefusal::Malformed));
    }
    Ok(Manifest {
        created_ms,
        locker,
        secrets,
        attachments,
    })
}

/// Builds the version the importer will write, with placeholder links and attachments, to
/// check it against the rules of the vault (§ 7.3, § 8) before anything is written.
///
/// # Errors
/// [`ExportRefusal::Malformed`] if the vault would refuse the secret.
fn check_secret(s: &ExportSecret, attachments: &[(u64, u64)]) -> Result<(), VaultError> {
    let refs: Vec<AttachmentRef> = s
        .attachments
        .iter()
        .map(|r| {
            let (size, chunks) = attachments
                .get(*r as usize)
                .copied()
                .ok_or_else(|| refuse(ExportRefusal::Malformed))?;
            Ok(AttachmentRef {
                id: [0; 16],
                key: Zeroizing::new([0; 32]),
                name: String::new(),
                media_type: String::new(),
                size,
                chunks,
            })
        })
        .collect::<Result<_, VaultError>>()?;
    let placeholder = SecretLink {
        locker: [0; 16],
        secret: [1; 16],
    };
    let edit = edit_for(s, |_| placeholder, refs);
    let stamp = Stamp {
        lamport: 1,
        member: [0; 16],
        device: [0; 16],
    };
    let mut next = 0u8;
    apply_edit(
        None,
        [0; 16],
        s.secret_type,
        Vec::new(),
        edit,
        stamp,
        |idx| Dot {
            member: [0; 16],
            device: [0; 16],
            seq: 1,
            idx,
        },
        || {
            next = next.wrapping_add(1);
            [next; 16]
        },
    )
    .map(|_| ())
    .map_err(malformed)
}

/// Checks content before it is sealed or imported: counts, sizes, ranks of links and
/// attachments, folder paths, and every secret against the rules of the vault. Returns the
/// size and chunk count of each attachment.
///
/// # Errors
/// [`ExportRefusal::TooLarge`] past the limits, [`ExportRefusal::Malformed`] otherwise.
pub(crate) fn check_content(c: &ExportContent) -> Result<Vec<(u64, u64)>, VaultError> {
    let too_large = refuse(ExportRefusal::TooLarge);
    let bad = refuse(ExportRefusal::Malformed);
    if c.secrets.len() > MAX_SECRETS || c.attachments.len() > MAX_ATTACHMENTS {
        return Err(too_large);
    }
    let l = &c.locker;
    if l.name.is_empty()
        || l.name.len() > MAX_LOCKER_NAME
        || l.description
            .as_ref()
            .is_some_and(|d| d.len() > MAX_DESCRIPTION)
        || l.icon.as_ref().is_some_and(|i| i.len() > MAX_ICON)
    {
        return Err(bad);
    }
    let mut sizes = Vec::with_capacity(c.attachments.len());
    let mut volume = 0u64;
    for a in &c.attachments {
        let size = u64::try_from(a.data.len()).map_err(|_| too_large)?;
        if size > MAX_ATTACHMENT {
            return Err(too_large);
        }
        if a.name.len() > MAX_ATTACHMENT_NAME || a.media_type.len() > MAX_MEDIA_TYPE {
            return Err(bad);
        }
        volume = volume.saturating_add(size);
        sizes.push((size, chunk_count(size)));
    }
    let chunks: u64 = sizes.iter().map(|(_, n)| n).sum();
    if chunks > MAX_CHUNKS as u64 || volume > MAX_FILE as u64 {
        return Err(too_large);
    }
    let mut cited = vec![false; c.attachments.len()];
    for (rank, s) in c.secrets.iter().enumerate() {
        for (_, target) in &s.links {
            let t = *target as usize;
            if t >= c.secrets.len() || t == rank {
                return Err(bad);
            }
        }
        for r in &s.attachments {
            *cited.get_mut(*r as usize).ok_or(bad)? = true;
        }
        if s.folder.len() > MAX_FOLDER_DEPTH
            || s.folder
                .iter()
                .any(|n| n.is_empty() || n.len() > MAX_FOLDER_NAME)
        {
            return Err(bad);
        }
        check_secret(s, &sizes)?;
    }
    if cited.iter().any(|c| !c) {
        return Err(bad);
    }
    Ok(sizes)
}

/// The edit that creates `s` in a vault: `link` maps the rank of a link target to the link
/// written, `attachments` are the stored references of its attachments, in order.
pub(crate) fn edit_for(
    s: &ExportSecret,
    link: impl Fn(u32) -> SecretLink,
    attachments: Vec<AttachmentRef>,
) -> SecretEdit {
    let mut edit = SecretEdit {
        set: s.fields.clone(),
        set_custom: s.custom.iter().map(|c| (None, c.clone())).collect(),
        ..SecretEdit::default()
    };
    for (f, r) in &s.links {
        edit.set.push((*f, FieldValue::Link(link(*r))));
    }
    for (k, items) in &s.sets {
        for t in items {
            edit.add.push((*k, SetValue::Text(t.clone())));
        }
    }
    for a in attachments {
        edit.add
            .push((SetKind::Attachments, SetValue::Attachment(a)));
    }
    edit
}

// -----------------------------------------------------------------------------------------
// The file
// -----------------------------------------------------------------------------------------

/// The clear header of an export file, read before any derivation.
struct Header<'a> {
    export_id: Id16,
    params: PasswordParams,
    manifest: &'a [u8],
    chunks: &'a [Value],
}

fn decode_header(v: &Value) -> Result<Header<'_>, VaultError> {
    let Value::Map(_) = v else {
        return Err(refuse(ExportRefusal::NotExport));
    };
    let f = Fields::new(v, &[1, 2, 3, 4, 5, 6]).map_err(|_| refuse(ExportRefusal::NotExport))?;
    if f.opt(1).and_then(|m| text_max(m, 64).ok()) != Some(MAGIC) {
        return Err(refuse(ExportRefusal::NotExport));
    }
    if uint(f.req(2).map_err(malformed)?).map_err(malformed)? != VERSION {
        return Err(refuse(ExportRefusal::Unsupported));
    }
    let export_id: Id16 = fixed(f.req(3).map_err(malformed)?).map_err(malformed)?;
    let k = Fields::new(f.req(4).map_err(malformed)?, &[1, 2, 3, 4, 5]).map_err(malformed)?;
    let small = |key| -> Result<u32, VaultError> {
        let n = uint(k.req(key).map_err(malformed)?).map_err(malformed)?;
        u32::try_from(n).map_err(malformed)
    };
    if uint(k.req(5).map_err(malformed)?).map_err(malformed)? != ARGON2_VERSION {
        return Err(refuse(ExportRefusal::Malformed));
    }
    let salt: [u8; SALT_LEN] = fixed(k.req(4).map_err(malformed)?).map_err(malformed)?;
    // Out of the vault's bounds: refused here, before any computation (format.md § 4.2).
    let params = PasswordParams::new(small(1)?, small(2)?, small(3)?, salt).map_err(malformed)?;
    let manifest =
        bytes_max(f.req(5).map_err(malformed)?, max_manifest_box()).map_err(malformed)?;
    let chunks = array_max(f.req(6).map_err(malformed)?, MAX_CHUNKS).map_err(malformed)?;
    for c in chunks {
        bytes_max(c, max_chunk_box()).map_err(malformed)?;
    }
    Ok(Header {
        export_id,
        params,
        manifest,
        chunks,
    })
}

/// Seals `content` into an export file under `password`.
///
/// The password is checked by [`check_password`] and normalised (NFC). Every check that the
/// importer makes is made here first: a file this function writes always opens.
///
/// # Errors
/// [`ExportRefusal::WeakPassword`], [`ExportRefusal::TooLarge`] past the limits of this
/// format, [`VaultError::InvalidInput`] for content the vault would refuse, or a
/// cryptographic failure.
pub fn seal(
    content: &ExportContent,
    password: &str,
    cost: ExportCost,
) -> Result<Vec<u8>, VaultError> {
    check_password(password)?;
    let too_large = refuse(ExportRefusal::TooLarge);
    let sizes = check_content(content)?;
    let total_chunks: u64 = sizes.iter().map(|(_, c)| c).sum();

    let params = PasswordParams::generate(cost.m_kib, cost.t, cost.p)?;
    let export_id: Id16 = random_array()?;
    let key = export_key(password, &params, &export_id)?;

    let chunk_len = usize::try_from(CHUNK_LEN).map_err(|_| too_large)?;
    let mut chunks = Vec::with_capacity(usize::try_from(total_chunks).unwrap_or(0));
    let mut total = 0usize;
    for (i, a) in content.attachments.iter().enumerate() {
        let n = chunk_count(sizes.get(i).map_or(0, |s| s.0));
        for rank in 0..n {
            let start = usize::try_from(rank).map_err(|_| too_large)? * chunk_len;
            let part = a
                .data
                .get(start..a.data.len().min(start + chunk_len))
                .unwrap_or(&[]);
            let aad = aad_chunk(&export_id, i as u64, rank, n)?;
            let sealed = seal_padded(&key, &aad, part)?;
            total = total.saturating_add(sealed.len());
            if total > MAX_FILE {
                return Err(too_large);
            }
            chunks.push(Value::Bytes(sealed));
        }
    }

    let manifest = cbor::encode(&manifest_value(content)?)?;
    if manifest.len() > MAX_MANIFEST {
        return Err(too_large);
    }
    let manifest_box = seal_padded(&key, &aad_manifest(&export_id, total_chunks)?, &manifest)?;
    drop(manifest);
    let file = Value::map(vec![
        (1, Value::text(MAGIC)),
        (2, Value::Uint(VERSION)),
        (3, Value::bytes(&export_id)),
        (
            4,
            Value::map(vec![
                (1, Value::Uint(u64::from(params.m_kib()))),
                (2, Value::Uint(u64::from(params.t()))),
                (3, Value::Uint(u64::from(params.p()))),
                (4, Value::bytes(params.salt())),
                (5, Value::Uint(ARGON2_VERSION)),
            ]),
        ),
        (5, Value::Bytes(manifest_box)),
        (6, Value::Array(chunks)),
    ]);
    let bytes = cbor::encode(&file)?;
    if bytes.len() > MAX_FILE {
        return Err(too_large);
    }
    Ok(bytes.to_vec())
}

/// Opens an export file with `password`: checks the header and its bounds before deriving
/// the key, then unseals and checks everything — manifest, every chunk, every secret against
/// the rules of the vault. Nothing is returned unless the whole file is sound.
///
/// # Errors
/// [`VaultError::Export`]: `NotExport`, `Unsupported` (another version), `TooLarge`,
/// `Malformed` (bad structure, altered chunk, secret the vault would refuse), `WrongKey`
/// (wrong password or altered manifest; the cause is not given).
pub fn open(bytes: &[u8], password: &str) -> Result<ExportContent, VaultError> {
    if bytes.len() > MAX_FILE {
        return Err(refuse(ExportRefusal::TooLarge));
    }
    let v = cbor::decode(bytes).map_err(|_| refuse(ExportRefusal::NotExport))?;
    let header = decode_header(&v)?;
    if password.is_empty() {
        return Err(refuse(ExportRefusal::WrongKey));
    }
    let key = export_key(password, &header.params, &header.export_id)?;
    let chunk_total = header.chunks.len() as u64;
    let manifest_bytes = unseal_padded(
        &key,
        &aad_manifest(&header.export_id, chunk_total)?,
        header.manifest,
    )
    .map_err(|_| refuse(ExportRefusal::WrongKey))?;
    let manifest = decode_manifest(&manifest_bytes)?;
    drop(manifest_bytes);
    let expected: u64 = manifest.attachments.iter().map(|a| a.chunks).sum();
    if expected != chunk_total {
        return Err(refuse(ExportRefusal::Malformed));
    }
    let sizes: Vec<(u64, u64)> = manifest
        .attachments
        .iter()
        .map(|a| (a.size, a.chunks))
        .collect();
    for s in &manifest.secrets {
        check_secret(s, &sizes)?;
    }
    let mut chunks = header.chunks.iter();
    let mut attachments = Vec::with_capacity(manifest.attachments.len());
    for (i, a) in manifest.attachments.into_iter().enumerate() {
        let mut data = Zeroizing::new(Vec::with_capacity(usize::try_from(a.size).unwrap_or(0)));
        for rank in 0..a.chunks {
            let Some(Value::Bytes(sealed)) = chunks.next() else {
                return Err(refuse(ExportRefusal::Malformed));
            };
            let aad = aad_chunk(&header.export_id, i as u64, rank, a.chunks)?;
            let part = unseal_padded(&key, &aad, sealed).map_err(malformed)?;
            // Every chunk but the last is full (§ 8.4).
            let last = rank + 1 == a.chunks;
            if !last && part.len() as u64 != CHUNK_LEN {
                return Err(refuse(ExportRefusal::Malformed));
            }
            data.extend_from_slice(&part);
        }
        if data.len() as u64 != a.size {
            return Err(refuse(ExportRefusal::Malformed));
        }
        attachments.push(ExportAttachment {
            name: a.name,
            media_type: a.media_type,
            data,
        });
    }
    Ok(ExportContent {
        created_ms: manifest.created_ms,
        locker: manifest.locker,
        secrets: manifest.secrets,
        attachments,
    })
}

/// Fuzzing entry point (feature `fuzzing`, never in a release build): the clear header of a
/// file, then, as if it were an unsealed manifest, the same bytes. Random input cannot reach
/// the manifest decoder through [`open`], every part being authenticated.
#[cfg(feature = "fuzzing")]
pub fn decode_for_fuzzing(data: &[u8]) {
    if let Ok(v) = cbor::decode(data) {
        let _ = decode_header(&v);
    }
    if let Ok(m) = decode_manifest(data) {
        let sizes: Vec<(u64, u64)> = m.attachments.iter().map(|a| (a.size, a.chunks)).collect();
        for s in &m.secrets {
            let _ = check_secret(s, &sizes);
        }
    }
}

#[cfg(test)]
mod tests;
