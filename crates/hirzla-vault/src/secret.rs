//! Secret versions (`SecretBody`, § 7.3), locker metadata (`LockerBody`, § 7.4), the field
//! schema of the six secret types (§ 8), the merge rules (`sync-protocol.md` § 8) and the
//! index entries (§ 10).

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::cbor::{
    self, array_max, boolean, bytes_max, check_sorted, fixed, text_max, uint, uint_in, CborError,
    Fields, Value,
};
use crate::model::{op_ids_value, Dot, Id16, OpId, Stamp};

/// Type of a secret (§ 8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretType {
    /// Password.
    Password = 1,
    /// SSH key.
    SshKey = 2,
    /// TOTP code.
    Totp = 3,
    /// Passkey.
    Passkey = 4,
    /// Note.
    Note = 5,
    /// File.
    File = 6,
}

impl SecretType {
    /// All types.
    pub const ALL: [SecretType; 6] = [
        SecretType::Password,
        SecretType::SshKey,
        SecretType::Totp,
        SecretType::Passkey,
        SecretType::Note,
        SecretType::File,
    ];

    fn from_u64(n: u64) -> Result<Self, CborError> {
        SecretType::ALL
            .into_iter()
            .find(|t| *t as u64 == n)
            .ok_or(CborError::Malformed)
    }
}

/// A field of `fields` (§ 8.2, § 8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Field {
    /// Title.
    Title = 1,
    /// Notes.
    Notes = 2,
    /// Favourite.
    Favorite = 3,
    /// User name.
    Username = 10,
    /// Password.
    Password = 11,
    /// TOTP configuration.
    Totp = 12,
    /// SSH private key.
    SshPrivateKey = 20,
    /// SSH public key.
    SshPublicKey = 21,
    /// SSH key passphrase.
    SshPassphrase = 22,
    /// Passkey relying party.
    RpId = 40,
    /// Passkey credential identifier.
    CredentialId = 41,
    /// Passkey user handle.
    UserHandle = 42,
    /// Passkey display name.
    DisplayName = 43,
    /// Passkey private key (COSE_Key).
    PasskeyPrivateKey = 44,
    /// Passkey COSE algorithm.
    Alg = 45,
    /// Passkey signature counter.
    SignCount = 46,
    /// Discoverable passkey.
    Discoverable = 47,
}

impl Field {
    const ALL: [Field; 17] = [
        Field::Title,
        Field::Notes,
        Field::Favorite,
        Field::Username,
        Field::Password,
        Field::Totp,
        Field::SshPrivateKey,
        Field::SshPublicKey,
        Field::SshPassphrase,
        Field::RpId,
        Field::CredentialId,
        Field::UserHandle,
        Field::DisplayName,
        Field::PasskeyPrivateKey,
        Field::Alg,
        Field::SignCount,
        Field::Discoverable,
    ];

    fn from_u64(n: u64) -> Option<Self> {
        Field::ALL.into_iter().find(|f| *f as u64 == n)
    }
}

/// A set of `sets` (§ 8.2, § 8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SetKind {
    /// Tags.
    Tags = 1,
    /// URLs.
    Urls = 2,
    /// Attachments.
    Attachments = 3,
    /// SSH hosts.
    Hosts = 4,
}

impl SetKind {
    const ALL: [SetKind; 4] = [
        SetKind::Tags,
        SetKind::Urls,
        SetKind::Attachments,
        SetKind::Hosts,
    ];

    fn from_u64(n: u64) -> Option<Self> {
        SetKind::ALL.into_iter().find(|s| *s as u64 == n)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Text(usize),
    Bytes(usize),
    Bool,
    Uint,
    Alg,
    Totp,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Merge {
    Register,
    Counter,
}

struct FieldSpec {
    kind: Kind,
    merge: Merge,
    sensitive: bool,
}

const MIB: usize = 1024 * 1024;

fn field_spec(t: SecretType, f: Field) -> Option<FieldSpec> {
    use SecretType as T;
    let s = |kind, sensitive| {
        Some(FieldSpec {
            kind,
            merge: Merge::Register,
            sensitive,
        })
    };
    match f {
        Field::Title => s(Kind::Text(1024), false),
        Field::Notes => s(Kind::Text(MIB), true),
        Field::Favorite => s(Kind::Bool, false),
        Field::Username if matches!(t, T::Password | T::SshKey | T::Totp | T::Passkey) => {
            s(Kind::Text(1024), false)
        }
        Field::Password if t == T::Password => s(Kind::Text(4096), true),
        Field::Totp if matches!(t, T::Password | T::Totp) => s(Kind::Totp, true),
        Field::SshPrivateKey if t == T::SshKey => s(Kind::Bytes(64 * 1024), true),
        Field::SshPublicKey if t == T::SshKey => s(Kind::Text(16 * 1024), false),
        Field::SshPassphrase if t == T::SshKey => s(Kind::Text(1024), true),
        Field::RpId if t == T::Passkey => s(Kind::Text(255), false),
        Field::CredentialId if t == T::Passkey => s(Kind::Bytes(1023), false),
        Field::UserHandle if t == T::Passkey => s(Kind::Bytes(64), false),
        Field::DisplayName if t == T::Passkey => s(Kind::Text(256), false),
        Field::PasskeyPrivateKey if t == T::Passkey => s(Kind::Bytes(16 * 1024), true),
        Field::Alg if t == T::Passkey => s(Kind::Alg, false),
        Field::SignCount if t == T::Passkey => Some(FieldSpec {
            kind: Kind::Uint,
            merge: Merge::Counter,
            sensitive: false,
        }),
        Field::Discoverable if t == T::Passkey => s(Kind::Bool, false),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ElemKind {
    Text(usize),
    Attachment,
}

struct SetSpec {
    elem: ElemKind,
    max: usize,
}

fn set_spec(t: SecretType, s: SetKind) -> Option<SetSpec> {
    use SecretType as T;
    match s {
        SetKind::Tags => Some(SetSpec {
            elem: ElemKind::Text(128),
            max: 64,
        }),
        SetKind::Attachments => Some(SetSpec {
            elem: ElemKind::Attachment,
            max: 64,
        }),
        SetKind::Urls if matches!(t, T::Password | T::Totp) => Some(SetSpec {
            elem: ElemKind::Text(2048),
            max: 32,
        }),
        SetKind::Hosts if t == T::SshKey => Some(SetSpec {
            elem: ElemKind::Text(255),
            max: 64,
        }),
        _ => None,
    }
}

fn required_fields(t: SecretType) -> &'static [Field] {
    match t {
        SecretType::Passkey => &[
            Field::Title,
            Field::RpId,
            Field::CredentialId,
            Field::PasskeyPrivateKey,
        ],
        _ => &[Field::Title],
    }
}

/// Whether a field never enters the index (§ 8).
#[must_use]
pub fn is_sensitive(t: SecretType, f: Field) -> bool {
    field_spec(t, f).is_none_or(|s| s.sensitive)
}

// -----------------------------------------------------------------------------------------
// Values
// -----------------------------------------------------------------------------------------

/// TOTP configuration (§ 8.3).
#[derive(Clone, PartialEq, Eq)]
pub struct TotpConfig {
    /// Shared secret, 10 to 128 bytes.
    pub secret: Zeroizing<Vec<u8>>,
    /// 1 SHA-1, 2 SHA-256, 3 SHA-512.
    pub algorithm: u8,
    /// 6 to 8.
    pub digits: u8,
    /// 15 to 300 seconds.
    pub period: u16,
    /// Issuer.
    pub issuer: Option<String>,
}

/// Reference to an attachment (§ 8.4). Holds its key: erased on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentRef {
    /// Identifier.
    pub id: Id16,
    /// Key of the attachment.
    pub key: Zeroizing<[u8; 32]>,
    /// File name.
    pub name: String,
    /// Media type.
    pub media_type: String,
    /// Size in bytes.
    pub size: u64,
    /// Number of chunks.
    pub chunks: u64,
}

/// Value of a field.
#[derive(Clone, PartialEq, Eq)]
pub enum FieldValue {
    /// Text.
    Text(Zeroizing<String>),
    /// Bytes.
    Bytes(Zeroizing<Vec<u8>>),
    /// Boolean.
    Bool(bool),
    /// Unsigned integer.
    Uint(u64),
    /// COSE algorithm (−7, −8 or −257).
    Alg(i64),
    /// TOTP configuration.
    Totp(TotpConfig),
}

impl FieldValue {
    /// Text value.
    #[must_use]
    pub fn text(s: &str) -> Self {
        FieldValue::Text(Zeroizing::new(s.to_owned()))
    }

    /// Bytes value.
    #[must_use]
    pub fn bytes(b: &[u8]) -> Self {
        FieldValue::Bytes(Zeroizing::new(b.to_vec()))
    }
}

/// Element of a set.
#[derive(Clone, PartialEq, Eq)]
pub enum SetValue {
    /// Tag, URL or host.
    Text(Zeroizing<String>),
    /// Attachment.
    Attachment(AttachmentRef),
}

impl SetValue {
    /// Text element.
    #[must_use]
    pub fn text(s: &str) -> Self {
        SetValue::Text(Zeroizing::new(s.to_owned()))
    }
}

/// User-defined field.
#[derive(Clone, PartialEq, Eq)]
pub struct CustomField {
    /// Label.
    pub label: String,
    /// Value.
    pub value: Zeroizing<String>,
    /// Masked and kept out of the index.
    pub sensitive: bool,
}

fn field_to_value(v: &FieldValue) -> Value {
    match v {
        FieldValue::Text(t) => Value::text(t),
        FieldValue::Bytes(b) => Value::bytes(b),
        FieldValue::Bool(b) => Value::Bool(*b),
        FieldValue::Uint(n) => Value::Uint(*n),
        FieldValue::Alg(a) => Value::int(*a),
        FieldValue::Totp(t) => {
            let mut e = vec![
                (1, Value::bytes(&t.secret)),
                (2, Value::Uint(u64::from(t.algorithm))),
                (3, Value::Uint(u64::from(t.digits))),
                (4, Value::Uint(u64::from(t.period))),
            ];
            if let Some(i) = &t.issuer {
                e.push((5, Value::text(i)));
            }
            Value::map(e)
        }
    }
}

fn field_from_value(kind: Kind, v: &Value) -> Result<FieldValue, CborError> {
    Ok(match kind {
        Kind::Text(max) => FieldValue::Text(Zeroizing::new(text_max(v, max)?.to_owned())),
        Kind::Bytes(max) => FieldValue::Bytes(Zeroizing::new(bytes_max(v, max)?.to_vec())),
        Kind::Bool => FieldValue::Bool(boolean(v)?),
        Kind::Uint => FieldValue::Uint(uint(v)?),
        Kind::Alg => match v {
            Value::Nint(6) => FieldValue::Alg(-7),
            Value::Nint(7) => FieldValue::Alg(-8),
            Value::Nint(256) => FieldValue::Alg(-257),
            _ => return Err(CborError::Malformed),
        },
        Kind::Totp => {
            let f = Fields::new(v, &[1, 2, 3, 4, 5])?;
            let secret = bytes_max(f.req(1)?, 128)?;
            if secret.len() < 10 {
                return Err(CborError::Malformed);
            }
            let small = |v: &Value, r: core::ops::RangeInclusive<u64>| {
                uint_in(v, r).and_then(|n| u16::try_from(n).map_err(|_| CborError::Malformed))
            };
            FieldValue::Totp(TotpConfig {
                secret: Zeroizing::new(secret.to_vec()),
                algorithm: small(f.req(2)?, 1..=3)? as u8,
                digits: small(f.req(3)?, 6..=8)? as u8,
                period: small(f.req(4)?, 15..=300)?,
                issuer: f
                    .opt(5)
                    .map(|i| text_max(i, 256).map(str::to_owned))
                    .transpose()?,
            })
        }
    })
}

fn kind_matches(kind: Kind, v: &FieldValue) -> bool {
    match (kind, v) {
        (Kind::Text(max), FieldValue::Text(t)) => t.len() <= max,
        (Kind::Bytes(max), FieldValue::Bytes(b)) => b.len() <= max,
        (Kind::Bool, FieldValue::Bool(_)) | (Kind::Uint, FieldValue::Uint(_)) => true,
        (Kind::Alg, FieldValue::Alg(a)) => matches!(a, -7 | -8 | -257),
        (Kind::Totp, FieldValue::Totp(t)) => {
            (10..=128).contains(&t.secret.len())
                && (1..=3).contains(&t.algorithm)
                && (6..=8).contains(&t.digits)
                && (15..=300).contains(&t.period)
                && t.issuer.as_ref().is_none_or(|i| i.len() <= 256)
        }
        _ => false,
    }
}

/// Size of an attachment chunk before padding (§ 8.4).
pub const CHUNK_LEN: u64 = 1_048_572;
/// Largest attachment.
pub const MAX_ATTACHMENT: u64 = 104_857_600;

fn set_value_to_value(v: &SetValue) -> Value {
    match v {
        SetValue::Text(t) => Value::text(t),
        SetValue::Attachment(a) => Value::map(vec![
            (1, Value::bytes(&a.id)),
            (2, Value::bytes(a.key.as_ref())),
            (3, Value::text(&a.name)),
            (4, Value::text(&a.media_type)),
            (5, Value::Uint(a.size)),
            (6, Value::Uint(a.chunks)),
        ]),
    }
}

/// Number of chunks of an attachment of `size` bytes.
#[must_use]
pub fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK_LEN).max(1)
}

fn set_value_from_value(kind: ElemKind, v: &Value) -> Result<SetValue, CborError> {
    Ok(match kind {
        ElemKind::Text(max) => SetValue::Text(Zeroizing::new(text_max(v, max)?.to_owned())),
        ElemKind::Attachment => {
            let f = Fields::new(v, &[1, 2, 3, 4, 5, 6])?;
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&fixed::<32>(f.req(2)?)?);
            let size = uint_in(f.req(5)?, 0..=MAX_ATTACHMENT)?;
            let chunks = uint(f.req(6)?)?;
            if chunks != chunk_count(size) {
                return Err(CborError::Malformed);
            }
            SetValue::Attachment(AttachmentRef {
                id: fixed::<16>(f.req(1)?)?,
                key,
                name: text_max(f.req(3)?, 512)?.to_owned(),
                media_type: text_max(f.req(4)?, 128)?.to_owned(),
                size,
                chunks,
            })
        }
    })
}

// -----------------------------------------------------------------------------------------
// SecretBody
// -----------------------------------------------------------------------------------------

/// A field with the stamp of the write that set it.
#[derive(Clone, PartialEq, Eq)]
pub struct FieldEntry {
    /// Value.
    pub value: FieldValue,
    /// Write that set it.
    pub stamp: Stamp,
}

/// An element of an add-wins set.
#[derive(Clone, PartialEq, Eq)]
pub struct OrElem {
    /// Value.
    pub value: SetValue,
    /// Adding point.
    pub dot: Dot,
}

/// Add-wins set.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct OrSet {
    /// Added elements.
    pub elems: Vec<OrElem>,
    /// Removed adding points.
    pub removed: Vec<Dot>,
}

impl OrSet {
    /// Elements whose adding point was not removed.
    pub fn visible(&self) -> impl Iterator<Item = &SetValue> {
        self.elems
            .iter()
            .filter(|e| !self.removed.contains(&e.dot))
            .map(|e| &e.value)
    }
}

/// A custom field entry; `None` marks a deletion.
#[derive(Clone, PartialEq, Eq)]
pub struct CustomEntry {
    /// Value, or deleted.
    pub value: Option<CustomField>,
    /// Write that set it.
    pub stamp: Stamp,
}

/// State of a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretState {
    /// Active.
    Active = 0,
    /// In the trash.
    Trash = 1,
    /// Purged, final.
    Purged = 2,
}

/// A version of a secret: its complete state as written.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBody {
    /// Secret identifier.
    pub secret_id: Id16,
    /// Type, immutable.
    pub secret_type: SecretType,
    /// Heads merged by the author.
    pub parents: Vec<OpId>,
    /// Fields.
    pub fields: BTreeMap<Field, FieldEntry>,
    /// Sets.
    pub sets: BTreeMap<SetKind, OrSet>,
    /// Custom fields.
    pub custom: BTreeMap<Id16, CustomEntry>,
    /// State and the write that set it.
    pub state: (SecretState, Stamp),
    /// Reseal-only version.
    pub reseal: bool,
}

/// Most custom fields per secret.
pub const MAX_CUSTOM: usize = 64;

impl SecretBody {
    /// Canonical value.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn to_value(&self) -> Result<Value, CborError> {
        let fields = Value::Map(
            self.fields
                .iter()
                .map(|(k, e)| {
                    (
                        Value::Uint(*k as u64),
                        Value::map(vec![(1, field_to_value(&e.value)), (2, e.stamp.to_value())]),
                    )
                })
                .collect(),
        );
        let mut sets = Vec::new();
        for (k, s) in &self.sets {
            let elems = cbor::sorted(
                s.elems
                    .iter()
                    .map(|e| {
                        Value::map(vec![
                            (1, set_value_to_value(&e.value)),
                            (2, e.dot.to_value()),
                        ])
                    })
                    .collect(),
            )?;
            let removed = cbor::sorted(s.removed.iter().map(Dot::to_value).collect())?;
            sets.push((
                Value::Uint(*k as u64),
                Value::map(vec![(1, Value::Array(elems)), (2, Value::Array(removed))]),
            ));
        }
        let custom = Value::Map(
            self.custom
                .iter()
                .map(|(k, e)| {
                    let v = match &e.value {
                        Some(c) => Value::map(vec![
                            (1, Value::text(&c.label)),
                            (2, Value::text(&c.value)),
                            (3, Value::Bool(c.sensitive)),
                        ]),
                        None => Value::Null,
                    };
                    (
                        Value::bytes(k),
                        Value::map(vec![(1, v), (2, e.stamp.to_value())]),
                    )
                })
                .collect(),
        );
        Ok(Value::map(vec![
            (1, Value::bytes(&self.secret_id)),
            (2, Value::Uint(self.secret_type as u64)),
            (3, op_ids_value(&self.parents)?),
            (4, fields),
            (5, Value::Map(sets)),
            (6, custom),
            (
                7,
                Value::map(vec![
                    (1, Value::Uint(self.state.0 as u64)),
                    (2, self.state.1.to_value()),
                ]),
            ),
            (8, Value::Bool(self.reseal)),
        ]))
    }

    /// Strict decoding against the schema of its type, required fields included.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8])?;
        let secret_type = SecretType::from_u64(uint(f.req(2)?)?)?;
        let parent_items = array_max(f.req(3)?, crate::model::MAX_DEPS)?;
        check_sorted(parent_items)?;
        let parents = parent_items
            .iter()
            .map(fixed::<48>)
            .collect::<Result<_, _>>()?;

        let mut fields = BTreeMap::new();
        let Value::Map(fm) = f.req(4)? else {
            return Err(CborError::Malformed);
        };
        for (k, e) in fm {
            let field = Field::from_u64(uint(k)?).ok_or(CborError::Malformed)?;
            let spec = field_spec(secret_type, field).ok_or(CborError::Malformed)?;
            let ef = Fields::new(e, &[1, 2])?;
            fields.insert(
                field,
                FieldEntry {
                    value: field_from_value(spec.kind, ef.req(1)?)?,
                    stamp: Stamp::from_value(ef.req(2)?)?,
                },
            );
        }

        let mut sets = BTreeMap::new();
        let Value::Map(sm) = f.req(5)? else {
            return Err(CborError::Malformed);
        };
        for (k, s) in sm {
            let kind = SetKind::from_u64(uint(k)?).ok_or(CborError::Malformed)?;
            let spec = set_spec(secret_type, kind).ok_or(CborError::Malformed)?;
            let sf = Fields::new(s, &[1, 2])?;
            let elems_v = array_max(sf.req(1)?, 4096)?;
            check_sorted(elems_v)?;
            let removed_v = array_max(sf.req(2)?, 4096)?;
            check_sorted(removed_v)?;
            let mut elems = Vec::with_capacity(elems_v.len());
            for e in elems_v {
                let ef = Fields::new(e, &[1, 2])?;
                elems.push(OrElem {
                    value: set_value_from_value(spec.elem, ef.req(1)?)?,
                    dot: Dot::from_value(ef.req(2)?)?,
                });
            }
            let set = OrSet {
                elems,
                removed: removed_v
                    .iter()
                    .map(Dot::from_value)
                    .collect::<Result<_, _>>()?,
            };
            if set.visible().count() > spec.max {
                return Err(CborError::Malformed);
            }
            sets.insert(kind, set);
        }

        let mut custom = BTreeMap::new();
        let Value::Map(cm) = f.req(6)? else {
            return Err(CborError::Malformed);
        };
        if cm.len() > MAX_CUSTOM {
            return Err(CborError::Malformed);
        }
        for (k, e) in cm {
            let ef = Fields::new(e, &[1, 2])?;
            let value = match ef.req(1)? {
                Value::Null => None,
                c => {
                    let cf = Fields::new(c, &[1, 2, 3])?;
                    Some(CustomField {
                        label: text_max(cf.req(1)?, 256)?.to_owned(),
                        value: Zeroizing::new(text_max(cf.req(2)?, 65_536)?.to_owned()),
                        sensitive: boolean(cf.req(3)?)?,
                    })
                }
            };
            custom.insert(
                fixed::<16>(k)?,
                CustomEntry {
                    value,
                    stamp: Stamp::from_value(ef.req(2)?)?,
                },
            );
        }

        let st = Fields::new(f.req(7)?, &[1, 2])?;
        let state = match uint_in(st.req(1)?, 0..=2)? {
            0 => SecretState::Active,
            1 => SecretState::Trash,
            _ => SecretState::Purged,
        };
        let body = SecretBody {
            secret_id: fixed::<16>(f.req(1)?)?,
            secret_type,
            parents,
            fields,
            sets,
            custom,
            state: (state, Stamp::from_value(st.req(2)?)?),
            reseal: boolean(f.req(8)?)?,
        };
        body.check_required()?;
        Ok(body)
    }

    fn check_required(&self) -> Result<(), CborError> {
        for r in required_fields(self.secret_type) {
            if !self.fields.contains_key(r) {
                return Err(CborError::Malformed);
            }
        }
        if self.secret_type == SecretType::File
            && self
                .sets
                .get(&SetKind::Attachments)
                .is_none_or(|s| s.visible().next().is_none())
        {
            return Err(CborError::Malformed);
        }
        Ok(())
    }

    /// Largest stamp of the secret.
    #[must_use]
    pub fn updated(&self) -> Stamp {
        let mut max = self.state.1;
        for e in self.fields.values() {
            max = max.max(e.stamp);
        }
        for e in self.custom.values() {
            max = max.max(e.stamp);
        }
        max
    }
}

/// Merges the head versions of one secret (`sync-protocol.md` § 8.2).
///
/// # Errors
/// [`CborError::Malformed`] if the heads disagree on identity or type.
pub fn merge(heads: &[SecretBody]) -> Result<SecretBody, CborError> {
    let first = heads.first().ok_or(CborError::Malformed)?;
    let mut out = first.clone();
    for h in &heads[1..] {
        if h.secret_id != out.secret_id || h.secret_type != out.secret_type {
            return Err(CborError::Malformed);
        }
        for (k, e) in &h.fields {
            let merge_kind = field_spec(out.secret_type, *k).map_or(Merge::Register, |s| s.merge);
            match out.fields.get(k) {
                Some(cur) => {
                    let take = match (merge_kind, &cur.value, &e.value) {
                        (Merge::Counter, FieldValue::Uint(a), FieldValue::Uint(b)) => {
                            b > a || (b == a && e.stamp > cur.stamp)
                        }
                        _ => e.stamp > cur.stamp,
                    };
                    if take {
                        out.fields.insert(*k, e.clone());
                    }
                }
                None => {
                    out.fields.insert(*k, e.clone());
                }
            }
        }
        for (k, s) in &h.sets {
            let cur = out.sets.entry(*k).or_default();
            for e in &s.elems {
                if !cur.elems.iter().any(|c| c.dot == e.dot) {
                    cur.elems.push(e.clone());
                }
            }
            for d in &s.removed {
                if !cur.removed.contains(d) {
                    cur.removed.push(*d);
                }
            }
        }
        for (k, e) in &h.custom {
            if out.custom.get(k).is_none_or(|c| e.stamp > c.stamp) {
                out.custom.insert(*k, e.clone());
            }
        }
        let purged = out.state.0 == SecretState::Purged || h.state.0 == SecretState::Purged;
        if h.state.1 > out.state.1 {
            out.state = h.state;
        }
        if purged {
            out.state.0 = SecretState::Purged;
        }
    }
    Ok(out)
}

/// A change to apply to a secret.
#[derive(Default)]
pub struct SecretEdit {
    /// Fields to set.
    pub set: Vec<(Field, FieldValue)>,
    /// Fields to clear.
    pub clear: Vec<Field>,
    /// Set elements to add.
    pub add: Vec<(SetKind, SetValue)>,
    /// Set elements to remove (every element with this value).
    pub remove: Vec<(SetKind, SetValue)>,
    /// Custom fields to set: existing identifier, or `None` for a new one.
    pub set_custom: Vec<(Option<Id16>, CustomField)>,
    /// Custom fields to delete.
    pub remove_custom: Vec<Id16>,
    /// New state.
    pub state: Option<SecretState>,
}

/// Errors when applying an edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditError {
    /// A field or set is not allowed for the type, or a value is out of bounds.
    NotAllowed,
    /// A required field is missing.
    Incomplete,
    /// The secret is purged.
    Purged,
}

/// Builds the next version of a secret from the merged heads (or nothing, for a creation).
///
/// `stamp` is the stamp of the new operation; `dot` gives the adding point of new elements.
///
/// # Errors
/// [`EditError`].
#[allow(clippy::too_many_arguments)] // each argument is a distinct part of the version
pub fn apply_edit(
    base: Option<&SecretBody>,
    secret_id: Id16,
    secret_type: SecretType,
    parents: Vec<OpId>,
    edit: SecretEdit,
    stamp: Stamp,
    dot: impl Fn(u64) -> Dot,
    mut new_custom_id: impl FnMut() -> Id16,
) -> Result<SecretBody, EditError> {
    let mut body = match base {
        Some(b) => {
            if b.state.0 == SecretState::Purged {
                return Err(EditError::Purged);
            }
            let mut b = b.clone();
            b.parents = parents;
            b.reseal = false;
            b
        }
        None => SecretBody {
            secret_id,
            secret_type,
            parents,
            fields: BTreeMap::new(),
            sets: BTreeMap::new(),
            custom: BTreeMap::new(),
            state: (SecretState::Active, stamp),
            reseal: false,
        },
    };
    for (f, v) in edit.set {
        let spec = field_spec(body.secret_type, f).ok_or(EditError::NotAllowed)?;
        if !kind_matches(spec.kind, &v) {
            return Err(EditError::NotAllowed);
        }
        body.fields.insert(f, FieldEntry { value: v, stamp });
    }
    for f in edit.clear {
        body.fields.remove(&f);
    }
    for (k, v) in edit.remove {
        let target = cbor::encode(&set_value_to_value(&v)).map_err(|_| EditError::NotAllowed)?;
        if let Some(set) = body.sets.get_mut(&k) {
            let dots: Vec<Dot> = set
                .elems
                .iter()
                .filter(|e| cbor::encode(&set_value_to_value(&e.value)).is_ok_and(|x| x == target))
                .map(|e| e.dot)
                .collect();
            for d in dots {
                if !set.removed.contains(&d) {
                    set.removed.push(d);
                }
            }
        }
    }
    for (idx, (k, v)) in (0u64..).zip(edit.add) {
        let spec = set_spec(body.secret_type, k).ok_or(EditError::NotAllowed)?;
        let ok = match (&spec.elem, &v) {
            (ElemKind::Text(max), SetValue::Text(t)) => t.len() <= *max,
            (ElemKind::Attachment, SetValue::Attachment(a)) => {
                a.size <= MAX_ATTACHMENT && a.chunks == chunk_count(a.size)
            }
            _ => false,
        };
        if !ok {
            return Err(EditError::NotAllowed);
        }
        body.sets.entry(k).or_default().elems.push(OrElem {
            value: v,
            dot: dot(idx),
        });
    }
    for (id, c) in edit.set_custom {
        if c.label.len() > 256 || c.value.len() > 65_536 {
            return Err(EditError::NotAllowed);
        }
        let id = id.unwrap_or_else(&mut new_custom_id);
        body.custom.insert(
            id,
            CustomEntry {
                value: Some(c),
                stamp,
            },
        );
    }
    for id in edit.remove_custom {
        body.custom.insert(id, CustomEntry { value: None, stamp });
    }
    if let Some(s) = edit.state {
        body.state = (s, stamp);
    }
    if body.custom.len() > MAX_CUSTOM {
        return Err(EditError::NotAllowed);
    }
    for (k, s) in &body.sets {
        let max = set_spec(body.secret_type, *k).map_or(0, |s| s.max);
        if s.visible().count() > max {
            return Err(EditError::NotAllowed);
        }
    }
    body.check_required().map_err(|_| EditError::Incomplete)?;
    Ok(body)
}

// -----------------------------------------------------------------------------------------
// LockerBody (§ 7.4)
// -----------------------------------------------------------------------------------------

/// Locker metadata field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LockerField {
    /// Name.
    Name = 1,
    /// Description.
    Description = 2,
    /// Colour index.
    Color = 3,
    /// Icon.
    Icon = 4,
    /// Versions kept per secret.
    KeepVersions = 10,
    /// Quarantine timeout, hours.
    QuarantineTimeoutH = 11,
}

impl LockerField {
    const ALL: [LockerField; 6] = [
        LockerField::Name,
        LockerField::Description,
        LockerField::Color,
        LockerField::Icon,
        LockerField::KeepVersions,
        LockerField::QuarantineTimeoutH,
    ];

    fn check(self, v: &FieldValue) -> bool {
        match (self, v) {
            (LockerField::Name, FieldValue::Text(t)) => !t.is_empty() && t.len() <= 256,
            (LockerField::Description, FieldValue::Text(t)) => t.len() <= 4096,
            (LockerField::Icon, FieldValue::Text(t)) => t.len() <= 64,
            (LockerField::Color, FieldValue::Uint(_)) => true,
            (LockerField::KeepVersions, FieldValue::Uint(n)) => (1..=1000).contains(n),
            (LockerField::QuarantineTimeoutH, FieldValue::Uint(n)) => (1..=2160).contains(n),
            _ => false,
        }
    }
}

/// Locker metadata version.
#[derive(Clone, PartialEq, Eq)]
pub struct LockerBody {
    /// Heads merged by the author.
    pub parents: Vec<OpId>,
    /// Fields.
    pub fields: BTreeMap<LockerField, FieldEntry>,
}

impl LockerBody {
    /// Canonical value.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn to_value(&self) -> Result<Value, CborError> {
        Ok(Value::map(vec![
            (1, op_ids_value(&self.parents)?),
            (
                2,
                Value::Map(
                    self.fields
                        .iter()
                        .map(|(k, e)| {
                            (
                                Value::Uint(*k as u64),
                                Value::map(vec![
                                    (1, field_to_value(&e.value)),
                                    (2, e.stamp.to_value()),
                                ]),
                            )
                        })
                        .collect(),
                ),
            ),
        ]))
    }

    /// Strict decoding; the name is required.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2])?;
        let parent_items = array_max(f.req(1)?, crate::model::MAX_DEPS)?;
        check_sorted(parent_items)?;
        let Value::Map(fm) = f.req(2)? else {
            return Err(CborError::Malformed);
        };
        let mut fields = BTreeMap::new();
        for (k, e) in fm {
            let n = uint(k)?;
            let lf = LockerField::ALL
                .into_iter()
                .find(|l| *l as u64 == n)
                .ok_or(CborError::Malformed)?;
            let ef = Fields::new(e, &[1, 2])?;
            let value = match ef.req(1)? {
                Value::Text(t) => FieldValue::Text(Zeroizing::new(t.clone())),
                Value::Uint(n) => FieldValue::Uint(*n),
                _ => return Err(CborError::Malformed),
            };
            if !lf.check(&value) {
                return Err(CborError::Malformed);
            }
            fields.insert(
                lf,
                FieldEntry {
                    value,
                    stamp: Stamp::from_value(ef.req(2)?)?,
                },
            );
        }
        if !fields.contains_key(&LockerField::Name) {
            return Err(CborError::Malformed);
        }
        Ok(LockerBody {
            parents: parent_items
                .iter()
                .map(fixed::<48>)
                .collect::<Result<_, _>>()?,
            fields,
        })
    }

    /// Applies field changes, refusing invalid values.
    ///
    /// # Errors
    /// [`EditError::NotAllowed`].
    pub fn edit(
        base: Option<&LockerBody>,
        parents: Vec<OpId>,
        set: Vec<(LockerField, FieldValue)>,
        stamp: Stamp,
    ) -> Result<LockerBody, EditError> {
        let mut body = base.cloned().unwrap_or(LockerBody {
            parents: Vec::new(),
            fields: BTreeMap::new(),
        });
        body.parents = parents;
        for (k, v) in set {
            if !k.check(&v) {
                return Err(EditError::NotAllowed);
            }
            body.fields.insert(k, FieldEntry { value: v, stamp });
        }
        if !body.fields.contains_key(&LockerField::Name) {
            return Err(EditError::Incomplete);
        }
        Ok(body)
    }

    /// The locker name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self.fields.get(&LockerField::Name).map(|e| &e.value) {
            Some(FieldValue::Text(t)) => t,
            _ => "",
        }
    }
}

/// Merges locker metadata heads (registers only).
#[must_use]
pub fn merge_locker(heads: &[LockerBody]) -> Option<LockerBody> {
    let mut out = heads.first()?.clone();
    for h in &heads[1..] {
        for (k, e) in &h.fields {
            if out.fields.get(k).is_none_or(|c| e.stamp > c.stamp) {
                out.fields.insert(*k, e.clone());
            }
        }
    }
    Some(out)
}

// -----------------------------------------------------------------------------------------
// Index (§ 10)
// -----------------------------------------------------------------------------------------

/// One secret in the index. Holds no sensitive field.
#[derive(Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// Secret.
    pub secret_id: Id16,
    /// Type.
    pub secret_type: SecretType,
    /// Head versions.
    pub heads: Vec<OpId>,
    /// Title.
    pub title: Zeroizing<String>,
    /// User name.
    pub username: Option<Zeroizing<String>>,
    /// Hosts of the URLs (WHATWG URL Standard, ASCII), sorted.
    pub hosts: Vec<String>,
    /// Tags.
    pub tags: Vec<Zeroizing<String>>,
    /// Favourite.
    pub favorite: bool,
    /// State.
    pub state: SecretState,
    /// Largest stamp.
    pub updated: Stamp,
}

/// Host of a URL per the WHATWG URL Standard, in ASCII, or `None`.
#[must_use]
pub fn url_host(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .host_str()
        .filter(|h| !h.is_empty())
        .map(str::to_ascii_lowercase)
}

impl IndexEntry {
    /// Builds the entry of a merged secret.
    #[must_use]
    pub fn of(body: &SecretBody, heads: Vec<OpId>) -> Self {
        let text = |f: Field| match body.fields.get(&f).map(|e| &e.value) {
            Some(FieldValue::Text(t)) => Some(t.clone()),
            _ => None,
        };
        let set_texts = |k: SetKind| -> Vec<Zeroizing<String>> {
            body.sets
                .get(&k)
                .map(|s| {
                    s.visible()
                        .filter_map(|v| match v {
                            SetValue::Text(t) => Some(t.clone()),
                            SetValue::Attachment(_) => None,
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut hosts: Vec<String> = set_texts(SetKind::Urls)
            .iter()
            .filter_map(|u| url_host(u))
            .collect();
        hosts.sort();
        hosts.dedup();
        let mut tags = set_texts(SetKind::Tags);
        tags.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        tags.dedup_by(|a, b| a.as_str() == b.as_str());
        IndexEntry {
            secret_id: body.secret_id,
            secret_type: body.secret_type,
            heads,
            title: text(Field::Title).unwrap_or_default(),
            username: text(Field::Username),
            hosts,
            tags,
            favorite: matches!(
                body.fields.get(&Field::Favorite).map(|e| &e.value),
                Some(FieldValue::Bool(true))
            ),
            state: body.state.0,
            updated: body.updated(),
        }
    }

    fn to_value(&self) -> Result<Value, CborError> {
        let mut e = vec![
            (1, Value::bytes(&self.secret_id)),
            (2, Value::Uint(self.secret_type as u64)),
            (3, op_ids_value(&self.heads)?),
            (4, Value::text(&self.title)),
            (
                6,
                Value::Array(cbor::sorted(
                    self.hosts.iter().map(|h| Value::text(h)).collect(),
                )?),
            ),
            (
                7,
                Value::Array(cbor::sorted(
                    self.tags.iter().map(|t| Value::text(t)).collect(),
                )?),
            ),
            (8, Value::Bool(self.favorite)),
            (9, Value::Uint(self.state as u64)),
            (10, self.updated.to_value()),
        ];
        if let Some(u) = &self.username {
            e.push((5, Value::text(u)));
        }
        Ok(Value::map(e))
    }

    fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
        let texts = |v: &Value, max_len: usize| -> Result<Vec<String>, CborError> {
            let items = array_max(v, 4096)?;
            check_sorted(items)?;
            items
                .iter()
                .map(|t| text_max(t, max_len).map(str::to_owned))
                .collect()
        };
        Ok(IndexEntry {
            secret_id: fixed::<16>(f.req(1)?)?,
            secret_type: SecretType::from_u64(uint(f.req(2)?)?)?,
            heads: {
                let items = array_max(f.req(3)?, crate::model::MAX_DEPS)?;
                check_sorted(items)?;
                items.iter().map(fixed::<48>).collect::<Result<_, _>>()?
            },
            title: Zeroizing::new(text_max(f.req(4)?, 1024)?.to_owned()),
            username: f
                .opt(5)
                .map(|u| text_max(u, 1024).map(|s| Zeroizing::new(s.to_owned())))
                .transpose()?,
            hosts: texts(f.req(6)?, 2048)?,
            tags: texts(f.req(7)?, 128)?
                .into_iter()
                .map(Zeroizing::new)
                .collect(),
            favorite: boolean(f.req(8)?)?,
            state: match uint_in(f.req(9)?, 0..=2)? {
                0 => SecretState::Active,
                1 => SecretState::Trash,
                _ => SecretState::Purged,
            },
            updated: Stamp::from_value(f.req(10)?)?,
        })
    }
}

/// Index fragment of one locker (§ 10). Erased on drop through its fields.
#[derive(Clone, PartialEq, Eq)]
pub struct IndexShard {
    /// Locker.
    pub locker_id: Id16,
    /// Heads of the locker journal when built.
    pub built_from: Vec<OpId>,
    /// Locker name.
    pub name: Zeroizing<String>,
    /// `LockerMetaPut` heads.
    pub meta_heads: Vec<OpId>,
    /// Entries, sorted by secret.
    pub entries: BTreeMap<Id16, IndexEntry>,
}

impl IndexShard {
    /// Canonical encoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CborError> {
        let entries = self
            .entries
            .values()
            .map(IndexEntry::to_value)
            .collect::<Result<Vec<_>, _>>()?;
        cbor::encode(&Value::map(vec![
            (1, Value::bytes(&self.locker_id)),
            (2, op_ids_value(&self.built_from)?),
            (3, Value::text(&self.name)),
            (4, op_ids_value(&self.meta_heads)?),
            (5, Value::Array(entries)),
        ]))
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CborError> {
        let v = cbor::decode(bytes)?;
        let f = Fields::new(&v, &[1, 2, 3, 4, 5])?;
        let ids = |v: &Value| -> Result<Vec<OpId>, CborError> {
            let items = array_max(v, crate::model::MAX_DEPS)?;
            check_sorted(items)?;
            items.iter().map(fixed::<48>).collect()
        };
        let mut entries = BTreeMap::new();
        let mut last: Option<Id16> = None;
        for e in array_max(f.req(5)?, 1 << 20)? {
            let entry = IndexEntry::from_value(e)?;
            if last.is_some_and(|l| l >= entry.secret_id) {
                return Err(CborError::NonCanonical);
            }
            last = Some(entry.secret_id);
            entries.insert(entry.secret_id, entry);
        }
        Ok(IndexShard {
            locker_id: fixed::<16>(f.req(1)?)?,
            built_from: ids(f.req(2)?)?,
            name: Zeroizing::new(text_max(f.req(3)?, 256)?.to_owned()),
            meta_heads: ids(f.req(4)?)?,
            entries,
        })
    }
}

#[cfg(test)]
mod tests;
