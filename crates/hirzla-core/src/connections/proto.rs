//! Connection operations of the local API (`docs/api-locale.md` § 17): version 6, operation
//! codes 100 to 119. Same frames, same CBOR profile and same strict decoding as the rest of
//! the API (`crate::proto`). The general error codes of § 7 are the only ones used.

use hirzla_vault::cbor::{
    self, array_max, boolean, bytes_max, fixed, text_max, uint, uint_in, Fields, Value,
};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{SecretLink, SecretType};
use zeroize::Zeroizing;

use crate::proto::{ErrorCode, MAX_ITEMS, MAX_TEXT};

/// Version of the protocol that carries the connection operations.
pub const CONNECTION_VERSION: u64 = 6;
/// Operation codes reserved for connections.
pub const CONNECTION_OPS: std::ops::RangeInclusive<u64> = 100..=119;
/// Largest SSH private key file, in bytes (`docs/format.md` § 8.3).
pub const MAX_PRIVATE_KEY: usize = 64 * 1024;
/// Longest SSH public key line, in bytes.
pub const MAX_PUBLIC_KEY: usize = 16 * 1024;
/// Most jump hosts followed from a connection (`docs/format.md` § 8.5).
pub const MAX_JUMPS: usize = 8;
/// Longest short text (title, host, user name, domain, fingerprint, tag) on the wire; the
/// vault applies its own, smaller, limits per field.
const MAX_SHORT: usize = 4096;

/// Connection operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOp {
    /// Create an SSH or RDP connection.
    ConnectionCreate = 100,
    /// The card of a connection, without sensitive values.
    ConnectionRead = 101,
    /// Set or clear fields of a connection.
    ConnectionUpdate = 102,
    /// Store an existing SSH key.
    SshKeyCreate = 103,
}

impl ConnectionOp {
    /// All operations.
    pub const ALL: [ConnectionOp; 4] = [
        ConnectionOp::ConnectionCreate,
        ConnectionOp::ConnectionRead,
        ConnectionOp::ConnectionUpdate,
        ConnectionOp::SshKeyCreate,
    ];

    /// The operation from its number.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<ConnectionOp> {
        ConnectionOp::ALL.into_iter().find(|o| *o as u64 == n)
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ConnectionOp::ConnectionCreate => "connection_create",
            ConnectionOp::ConnectionRead => "connection_read",
            ConnectionOp::ConnectionUpdate => "connection_update",
            ConnectionOp::SshKeyCreate => "ssh_key_create",
        }
    }
}

/// A key of the connection map (§ 17.2): the same numbers for creation, update and reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConnectionKey {
    /// Title.
    Title = 1,
    /// Host.
    Host = 2,
    /// Port.
    Port = 3,
    /// User name.
    Username = 4,
    /// Domain (RDP).
    Domain = 5,
    /// Password (write only).
    Password = 6,
    /// SSH key link (SSH).
    SshKey = 7,
    /// Jump host link.
    Jump = 8,
    /// Host key fingerprint.
    HostKey = 9,
    /// Notes (write only).
    Notes = 10,
    /// Favourite.
    Favorite = 11,
}

impl ConnectionKey {
    const ALL: [ConnectionKey; 11] = [
        ConnectionKey::Title,
        ConnectionKey::Host,
        ConnectionKey::Port,
        ConnectionKey::Username,
        ConnectionKey::Domain,
        ConnectionKey::Password,
        ConnectionKey::SshKey,
        ConnectionKey::Jump,
        ConnectionKey::HostKey,
        ConnectionKey::Notes,
        ConnectionKey::Favorite,
    ];

    /// The key from its number.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<ConnectionKey> {
        ConnectionKey::ALL.into_iter().find(|k| *k as u64 == n)
    }

    /// Whether `ConnectionUpdate` may clear this key (§ 17.3): everything but the title, the
    /// host and the favourite flag.
    #[must_use]
    pub fn clearable(self) -> bool {
        !matches!(
            self,
            ConnectionKey::Title | ConnectionKey::Host | ConnectionKey::Favorite
        )
    }
}

/// The fields of a connection, each present or absent (§ 17.2). Texts are erased on drop:
/// the password and the notes are secret.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ConnectionFields {
    /// Title.
    pub title: Option<Zeroizing<String>>,
    /// Host.
    pub host: Option<Zeroizing<String>>,
    /// Port.
    pub port: Option<u16>,
    /// User name.
    pub username: Option<Zeroizing<String>>,
    /// Domain (RDP).
    pub domain: Option<Zeroizing<String>>,
    /// Password; never present in a reply.
    pub password: Option<Zeroizing<String>>,
    /// SSH key (SSH).
    pub ssh_key: Option<SecretLink>,
    /// Jump host.
    pub jump: Option<SecretLink>,
    /// Host key fingerprint.
    pub host_key: Option<Zeroizing<String>>,
    /// Notes; never present in a reply.
    pub notes: Option<Zeroizing<String>>,
    /// Favourite.
    pub favorite: Option<bool>,
}

impl ConnectionFields {
    /// Whether no field is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys().is_empty()
    }

    /// The keys present.
    #[must_use]
    pub fn keys(&self) -> Vec<ConnectionKey> {
        use ConnectionKey as K;
        [
            (K::Title, self.title.is_some()),
            (K::Host, self.host.is_some()),
            (K::Port, self.port.is_some()),
            (K::Username, self.username.is_some()),
            (K::Domain, self.domain.is_some()),
            (K::Password, self.password.is_some()),
            (K::SshKey, self.ssh_key.is_some()),
            (K::Jump, self.jump.is_some()),
            (K::HostKey, self.host_key.is_some()),
            (K::Notes, self.notes.is_some()),
            (K::Favorite, self.favorite.is_some()),
        ]
        .into_iter()
        .filter_map(|(k, present)| present.then_some(k))
        .collect()
    }

    fn to_value(&self) -> Value {
        use ConnectionKey as K;
        let mut e = Vec::new();
        let mut text = |k: K, v: &Option<Zeroizing<String>>| {
            if let Some(t) = v {
                e.push((k as u64, Value::text(t)));
            }
        };
        text(K::Title, &self.title);
        text(K::Host, &self.host);
        text(K::Username, &self.username);
        text(K::Domain, &self.domain);
        text(K::Password, &self.password);
        text(K::HostKey, &self.host_key);
        text(K::Notes, &self.notes);
        if let Some(p) = self.port {
            e.push((K::Port as u64, Value::Uint(u64::from(p))));
        }
        if let Some(l) = &self.ssh_key {
            e.push((K::SshKey as u64, link_value(l)));
        }
        if let Some(l) = &self.jump {
            e.push((K::Jump as u64, link_value(l)));
        }
        if let Some(b) = self.favorite {
            e.push((K::Favorite as u64, Value::Bool(b)));
        }
        Value::map(e)
    }

    fn from_value(v: &Value) -> Result<Self, cbor::CborError> {
        use ConnectionKey as K;
        let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])?;
        let text = |k: K, max: usize| -> Result<Option<Zeroizing<String>>, cbor::CborError> {
            f.opt(k as u64)
                .map(|t| text_max(t, max).map(|s| Zeroizing::new(s.to_owned())))
                .transpose()
        };
        Ok(ConnectionFields {
            title: text(K::Title, MAX_SHORT)?,
            host: text(K::Host, MAX_SHORT)?,
            port: f
                .opt(K::Port as u64)
                .map(|p| {
                    uint_in(p, 1..=u64::from(u16::MAX))
                        .and_then(|n| u16::try_from(n).map_err(|_| cbor::CborError::Malformed))
                })
                .transpose()?,
            username: text(K::Username, MAX_SHORT)?,
            domain: text(K::Domain, MAX_SHORT)?,
            password: text(K::Password, MAX_SHORT)?,
            ssh_key: f.opt(K::SshKey as u64).map(link_from).transpose()?,
            jump: f.opt(K::Jump as u64).map(link_from).transpose()?,
            host_key: text(K::HostKey, MAX_SHORT)?,
            notes: text(K::Notes, MAX_TEXT)?,
            favorite: f.opt(K::Favorite as u64).map(boolean).transpose()?,
        })
    }
}

fn link_value(l: &SecretLink) -> Value {
    Value::map(vec![
        (1, Value::bytes(&l.locker)),
        (2, Value::bytes(&l.secret)),
    ])
}

fn link_from(v: &Value) -> Result<SecretLink, cbor::CborError> {
    let f = Fields::new(v, &[1, 2])?;
    Ok(SecretLink {
        locker: f.req(1).and_then(fixed::<16>)?,
        secret: f.req(2).and_then(fixed::<16>)?,
    })
}

/// State of a link, as the core sees its target (§ 17.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// The target exists, is active and has the expected type.
    Valid = 0,
    /// The target is missing, purged, or in a locker this device does not hold.
    Broken = 1,
    /// The target is in the trash.
    Trashed = 2,
    /// The target has another type than expected.
    WrongType = 3,
    /// The chain of jump hosts loops or is longer than [`MAX_JUMPS`].
    Loop = 4,
}

impl LinkState {
    fn from_u64(n: u64) -> Option<LinkState> {
        [
            LinkState::Valid,
            LinkState::Broken,
            LinkState::Trashed,
            LinkState::WrongType,
            LinkState::Loop,
        ]
        .into_iter()
        .find(|s| *s as u64 == n)
    }

    /// Whether the details of the target are given with this state.
    #[must_use]
    pub fn has_details(self) -> bool {
        matches!(self, LinkState::Valid | LinkState::Trashed)
    }
}

/// A link with what the core knows of its target (§ 17.2). Never holds a sensitive value.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedLink {
    /// The link.
    pub link: SecretLink,
    /// Its state.
    pub state: LinkState,
    /// Title of the target.
    pub title: Option<Zeroizing<String>>,
    /// Host of a jump host.
    pub host: Option<Zeroizing<String>>,
    /// Effective port of a jump host.
    pub port: Option<u16>,
    /// User name of the target.
    pub username: Option<Zeroizing<String>>,
    /// Public key of an SSH key.
    pub public_key: Option<Zeroizing<String>>,
}

impl ResolvedLink {
    /// A link whose target gives no details.
    #[must_use]
    pub fn bare(link: SecretLink, state: LinkState) -> Self {
        ResolvedLink {
            link,
            state,
            title: None,
            host: None,
            port: None,
            username: None,
            public_key: None,
        }
    }

    fn to_value(&self) -> Value {
        let mut e = vec![
            (1, Value::bytes(&self.link.locker)),
            (2, Value::bytes(&self.link.secret)),
            (3, Value::Uint(self.state as u64)),
        ];
        let mut text = |k: u64, v: &Option<Zeroizing<String>>| {
            if let Some(t) = v {
                e.push((k, Value::text(t)));
            }
        };
        text(4, &self.title);
        text(5, &self.host);
        text(7, &self.username);
        text(8, &self.public_key);
        if let Some(p) = self.port {
            e.push((6, Value::Uint(u64::from(p))));
        }
        Value::map(e)
    }

    fn from_value(v: &Value) -> Result<Self, cbor::CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8])?;
        let text = |k: u64, max: usize| -> Result<Option<Zeroizing<String>>, cbor::CborError> {
            f.opt(k)
                .map(|t| text_max(t, max).map(|s| Zeroizing::new(s.to_owned())))
                .transpose()
        };
        let state = f
            .req(3)
            .and_then(uint)
            .ok()
            .and_then(LinkState::from_u64)
            .ok_or(cbor::CborError::Malformed)?;
        let out = ResolvedLink {
            link: SecretLink {
                locker: f.req(1).and_then(fixed::<16>)?,
                secret: f.req(2).and_then(fixed::<16>)?,
            },
            state,
            title: text(4, MAX_SHORT)?,
            host: text(5, MAX_SHORT)?,
            port: f
                .opt(6)
                .map(|p| {
                    uint_in(p, 1..=u64::from(u16::MAX))
                        .and_then(|n| u16::try_from(n).map_err(|_| cbor::CborError::Malformed))
                })
                .transpose()?,
            username: text(7, MAX_SHORT)?,
            public_key: text(8, MAX_PUBLIC_KEY)?,
        };
        let details = out.title.is_some()
            || out.host.is_some()
            || out.port.is_some()
            || out.username.is_some()
            || out.public_key.is_some();
        if details && !state.has_details() {
            return Err(cbor::CborError::Malformed);
        }
        Ok(out)
    }
}

/// The card of a connection (§ 17.2): everything but the password and the notes.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionCard {
    /// SSH or RDP connection.
    pub secret_type: SecretType,
    /// Whether the connection is in the trash.
    pub trashed: bool,
    /// Its fields, without the password and the notes.
    pub fields: ConnectionFields,
    /// Whether a password is stored.
    pub has_password: bool,
    /// Whether notes are stored.
    pub has_notes: bool,
    /// Tags, sorted.
    pub tags: Vec<Zeroizing<String>>,
    /// The port, or the default port of the type.
    pub effective_port: u16,
    /// The SSH key, if the connection links one.
    pub ssh_key: Option<ResolvedLink>,
    /// The chain of jump hosts, nearest first.
    pub jumps: Vec<ResolvedLink>,
}

/// A connection request.
#[derive(Clone, PartialEq, Eq)]
pub enum ConnectionRequest {
    /// Create a connection.
    Create {
        /// Locker; the personal locker when absent.
        locker: Option<Id16>,
        /// SSH or RDP connection.
        secret_type: SecretType,
        /// Fields: a title and a host at least.
        fields: ConnectionFields,
        /// Tags.
        tags: Vec<Zeroizing<String>>,
    },
    /// Read the card of a connection.
    Read {
        /// Locker.
        locker: Id16,
        /// Secret.
        id: Id16,
    },
    /// Change a connection.
    Update {
        /// Locker.
        locker: Id16,
        /// Secret.
        id: Id16,
        /// Fields to set.
        set: ConnectionFields,
        /// Keys to clear.
        clear: Vec<ConnectionKey>,
    },
    /// Store an existing SSH key.
    SshKeyCreate {
        /// Locker; the personal locker when absent.
        locker: Option<Id16>,
        /// Title.
        title: Zeroizing<String>,
        /// Private key file, as OpenSSH writes it.
        private_key: Zeroizing<Vec<u8>>,
        /// Public key line.
        public_key: Option<Zeroizing<String>>,
        /// Passphrase of the private key.
        passphrase: Option<Zeroizing<String>>,
        /// User name.
        username: Option<Zeroizing<String>>,
        /// Tags.
        tags: Vec<Zeroizing<String>>,
    },
}

impl std::fmt::Debug for ConnectionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The operation only: arguments may be secret.
        write!(f, "ConnectionRequest::{}", self.op().name())
    }
}

/// A successful reply to a connection request.
#[derive(Clone, PartialEq, Eq)]
pub enum ConnectionReply {
    /// Nothing to return.
    Done,
    /// A secret was created.
    Created {
        /// Its locker.
        locker: Id16,
        /// Its identifier.
        id: Id16,
    },
    /// The card of a connection.
    Card(Box<ConnectionCard>),
}

impl std::fmt::Debug for ConnectionReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print content: hosts and user names are not for logs.
        f.write_str(match self {
            ConnectionReply::Done => "ConnectionReply::Done",
            ConnectionReply::Created { .. } => "ConnectionReply::Created",
            ConnectionReply::Card(_) => "ConnectionReply::Card",
        })
    }
}

/// Whether `frame` is a connection request: its operation code (key 3) is in
/// [`CONNECTION_OPS`].
#[must_use]
pub fn is_connection_request(frame: &[u8]) -> bool {
    let Ok(v) = cbor::decode(frame) else {
        return false;
    };
    let Ok(f) = Fields::new(&v, &[1, 2, 3, 4]) else {
        return false;
    };
    f.req(3)
        .and_then(uint)
        .is_ok_and(|op| CONNECTION_OPS.contains(&op))
}

fn m<T>(r: Result<T, cbor::CborError>) -> Result<T, ErrorCode> {
    r.map_err(|_| ErrorCode::Malformed)
}

fn tags_value(tags: &[Zeroizing<String>]) -> Value {
    Value::Array(tags.iter().map(|t| Value::text(t)).collect())
}

fn tags_from(v: &Value) -> Result<Vec<Zeroizing<String>>, cbor::CborError> {
    array_max(v, MAX_ITEMS)?
        .iter()
        .map(|t| text_max(t, MAX_SHORT).map(|s| Zeroizing::new(s.to_owned())))
        .collect()
}

fn opt_text(
    f: &Fields<'_>,
    key: u64,
    max: usize,
) -> Result<Option<Zeroizing<String>>, cbor::CborError> {
    f.opt(key)
        .map(|t| text_max(t, max).map(|s| Zeroizing::new(s.to_owned())))
        .transpose()
}

fn connection_type(n: u64) -> Result<SecretType, ErrorCode> {
    [SecretType::SshConnection, SecretType::RdpConnection]
        .into_iter()
        .find(|t| *t as u64 == n)
        .ok_or(ErrorCode::InvalidInput)
}

impl ConnectionRequest {
    /// Its operation.
    #[must_use]
    pub fn op(&self) -> ConnectionOp {
        match self {
            ConnectionRequest::Create { .. } => ConnectionOp::ConnectionCreate,
            ConnectionRequest::Read { .. } => ConnectionOp::ConnectionRead,
            ConnectionRequest::Update { .. } => ConnectionOp::ConnectionUpdate,
            ConnectionRequest::SshKeyCreate { .. } => ConnectionOp::SshKeyCreate,
        }
    }

    fn args(&self) -> Value {
        match self {
            ConnectionRequest::Create {
                locker,
                secret_type,
                fields,
                tags,
            } => {
                let mut e = vec![
                    (2, Value::Uint(*secret_type as u64)),
                    (3, fields.to_value()),
                ];
                if let Some(l) = locker {
                    e.push((1, Value::bytes(l)));
                }
                if !tags.is_empty() {
                    e.push((4, tags_value(tags)));
                }
                Value::map(e)
            }
            ConnectionRequest::Read { locker, id } => {
                Value::map(vec![(1, Value::bytes(locker)), (2, Value::bytes(id))])
            }
            ConnectionRequest::Update {
                locker,
                id,
                set,
                clear,
            } => {
                let mut e = vec![(1, Value::bytes(locker)), (2, Value::bytes(id))];
                if !set.is_empty() {
                    e.push((3, set.to_value()));
                }
                if !clear.is_empty() {
                    e.push((
                        4,
                        Value::Array(clear.iter().map(|k| Value::Uint(*k as u64)).collect()),
                    ));
                }
                Value::map(e)
            }
            ConnectionRequest::SshKeyCreate {
                locker,
                title,
                private_key,
                public_key,
                passphrase,
                username,
                tags,
            } => {
                let mut e = vec![(2, Value::text(title)), (3, Value::bytes(private_key))];
                if let Some(l) = locker {
                    e.push((1, Value::bytes(l)));
                }
                for (k, v) in [(4, public_key), (5, passphrase), (6, username)] {
                    if let Some(t) = v {
                        e.push((k, Value::text(t)));
                    }
                }
                if !tags.is_empty() {
                    e.push((7, tags_value(tags)));
                }
                Value::map(e)
            }
        }
    }

    /// Encodes the request with identifier `id` (client side, tests).
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(&self, id: u64) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        cbor::encode(&Value::map(vec![
            (1, Value::Uint(CONNECTION_VERSION)),
            (2, Value::Uint(id)),
            (3, Value::Uint(self.op() as u64)),
            (4, self.args()),
        ]))
        .map_err(|_| ErrorCode::Internal)
    }

    /// Strict decoding of a connection request. Returns the identifier (0 if unreadable)
    /// with the code to answer on failure.
    ///
    /// # Errors
    /// `(id, code)`.
    pub fn decode(frame: &[u8]) -> Result<(u64, ConnectionRequest), (u64, ErrorCode)> {
        let malformed = ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(|_| (0, malformed))?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(|_| (0, malformed))?;
        let id = f.req(2).and_then(uint).map_err(|_| (0, malformed))?;
        let version = f.req(1).and_then(uint).map_err(|_| (id, malformed))?;
        if version != CONNECTION_VERSION {
            return Err((id, ErrorCode::UnsupportedVersion));
        }
        let op = f.req(3).and_then(uint).map_err(|_| (id, malformed))?;
        let op = ConnectionOp::from_u64(op).ok_or((id, ErrorCode::UnknownOperation))?;
        let args = f.opt(4).ok_or((id, malformed))?;
        Self::decode_args(op, args)
            .map(|r| (id, r))
            .map_err(|c| (id, c))
    }

    fn decode_args(op: ConnectionOp, args: &Value) -> Result<ConnectionRequest, ErrorCode> {
        match op {
            ConnectionOp::ConnectionCreate => {
                let f = m(Fields::new(args, &[1, 2, 3, 4]))?;
                let secret_type = connection_type(m(f.req(2).and_then(uint))?)?;
                let fields = m(f.req(3).and_then(ConnectionFields::from_value))?;
                if fields.title.is_none() || fields.host.is_none() {
                    return Err(ErrorCode::InvalidInput);
                }
                Ok(ConnectionRequest::Create {
                    locker: m(f.opt(1).map(fixed::<16>).transpose())?,
                    secret_type,
                    fields,
                    tags: m(f.opt(4).map(tags_from).transpose())?.unwrap_or_default(),
                })
            }
            ConnectionOp::ConnectionRead => {
                let f = m(Fields::new(args, &[1, 2]))?;
                Ok(ConnectionRequest::Read {
                    locker: m(f.req(1).and_then(fixed::<16>))?,
                    id: m(f.req(2).and_then(fixed::<16>))?,
                })
            }
            ConnectionOp::ConnectionUpdate => {
                let f = m(Fields::new(args, &[1, 2, 3, 4]))?;
                let set =
                    m(f.opt(3).map(ConnectionFields::from_value).transpose())?.unwrap_or_default();
                let mut clear = Vec::new();
                if let Some(list) = f.opt(4) {
                    for k in m(array_max(list, ConnectionKey::ALL.len()))? {
                        let key =
                            ConnectionKey::from_u64(m(uint(k))?).ok_or(ErrorCode::InvalidInput)?;
                        if !key.clearable() || clear.contains(&key) {
                            return Err(ErrorCode::InvalidInput);
                        }
                        clear.push(key);
                    }
                }
                // At least one change, and no key both set and cleared.
                if (set.is_empty() && clear.is_empty())
                    || set.keys().iter().any(|k| clear.contains(k))
                {
                    return Err(ErrorCode::InvalidInput);
                }
                Ok(ConnectionRequest::Update {
                    locker: m(f.req(1).and_then(fixed::<16>))?,
                    id: m(f.req(2).and_then(fixed::<16>))?,
                    set,
                    clear,
                })
            }
            ConnectionOp::SshKeyCreate => {
                let f = m(Fields::new(args, &[1, 2, 3, 4, 5, 6, 7]))?;
                let private_key = Zeroizing::new(
                    m(f.req(3).and_then(|b| bytes_max(b, MAX_PRIVATE_KEY)))?.to_vec(),
                );
                if private_key.is_empty() {
                    return Err(ErrorCode::InvalidInput);
                }
                Ok(ConnectionRequest::SshKeyCreate {
                    locker: m(f.opt(1).map(fixed::<16>).transpose())?,
                    title: Zeroizing::new(
                        m(f.req(2).and_then(|t| text_max(t, MAX_SHORT)))?.to_owned(),
                    ),
                    private_key,
                    public_key: m(opt_text(&f, 4, MAX_PUBLIC_KEY))?,
                    passphrase: m(opt_text(&f, 5, MAX_SHORT))?,
                    username: m(opt_text(&f, 6, MAX_SHORT))?,
                    tags: m(f.opt(7).map(tags_from).transpose())?.unwrap_or_default(),
                })
            }
        }
    }
}

fn card_value(c: &ConnectionCard) -> Value {
    let mut e = vec![
        (1, Value::Uint(c.secret_type as u64)),
        (2, Value::Uint(u64::from(c.trashed))),
        (3, c.fields.to_value()),
        (4, Value::Bool(c.has_password)),
        (5, Value::Bool(c.has_notes)),
        (6, tags_value(&c.tags)),
        (7, Value::Uint(u64::from(c.effective_port))),
        (
            9,
            Value::Array(c.jumps.iter().map(ResolvedLink::to_value).collect()),
        ),
    ];
    if let Some(k) = &c.ssh_key {
        e.push((8, k.to_value()));
    }
    Value::map(e)
}

fn card_from(v: &Value) -> Result<ConnectionCard, cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    let secret_type =
        connection_type(f.req(1).and_then(uint)?).map_err(|_| cbor::CborError::Malformed)?;
    let fields = f.req(3).and_then(ConnectionFields::from_value)?;
    // A card never carries the password nor the notes.
    if fields.password.is_some() || fields.notes.is_some() {
        return Err(cbor::CborError::Malformed);
    }
    let port = f.req(7).and_then(|p| uint_in(p, 1..=u64::from(u16::MAX)))?;
    Ok(ConnectionCard {
        secret_type,
        trashed: f.req(2).and_then(|s| uint_in(s, 0..=1))? == 1,
        fields,
        has_password: f.req(4).and_then(boolean)?,
        has_notes: f.req(5).and_then(boolean)?,
        tags: f.req(6).and_then(tags_from)?,
        effective_port: u16::try_from(port).map_err(|_| cbor::CborError::Malformed)?,
        ssh_key: f.opt(8).map(ResolvedLink::from_value).transpose()?,
        jumps: f
            .req(9)
            .and_then(|l| array_max(l, MAX_JUMPS + 1))?
            .iter()
            .map(ResolvedLink::from_value)
            .collect::<Result<_, _>>()?,
    })
}

impl ConnectionReply {
    fn body(&self) -> Option<Value> {
        match self {
            ConnectionReply::Done => None,
            ConnectionReply::Created { locker, id } => Some(Value::map(vec![
                (1, Value::bytes(locker)),
                (2, Value::bytes(id)),
            ])),
            ConnectionReply::Card(c) => Some(card_value(c)),
        }
    }

    /// Encodes a reply (success or refusal) to request `id`.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(
        id: u64,
        result: &Result<ConnectionReply, ErrorCode>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![(1, Value::Uint(CONNECTION_VERSION)), (2, Value::Uint(id))];
        match result {
            Ok(r) => {
                e.push((3, Value::Uint(0)));
                if let Some(b) = r.body() {
                    e.push((4, b));
                }
            }
            Err(c) => {
                e.push((3, Value::Uint(*c as u64)));
                if *c == ErrorCode::UnsupportedVersion {
                    e.push((
                        4,
                        Value::map(vec![(
                            2,
                            Value::Array(vec![Value::Uint(CONNECTION_VERSION)]),
                        )]),
                    ));
                }
            }
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Decodes the reply to a connection request of operation `op` (client side, tests).
    ///
    /// # Errors
    /// [`ErrorCode::Malformed`].
    pub fn decode(
        op: ConnectionOp,
        frame: &[u8],
    ) -> Result<(u64, Result<ConnectionReply, ErrorCode>), ErrorCode> {
        let bad = |_| ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(bad)?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(bad)?;
        if f.req(1).and_then(uint).map_err(bad)? != CONNECTION_VERSION {
            return Err(ErrorCode::Malformed);
        }
        let id = f.req(2).and_then(uint).map_err(bad)?;
        let status = f.req(3).and_then(uint).map_err(bad)?;
        if status != 0 {
            let code = ErrorCode::from_u64(status).ok_or(ErrorCode::Malformed)?;
            return Ok((id, Err(code)));
        }
        let body = || f.opt(4).ok_or(ErrorCode::Malformed);
        let reply = match op {
            ConnectionOp::ConnectionUpdate => {
                if f.opt(4).is_some() {
                    return Err(ErrorCode::Malformed);
                }
                ConnectionReply::Done
            }
            ConnectionOp::ConnectionCreate | ConnectionOp::SshKeyCreate => {
                let b = Fields::new(body()?, &[1, 2]).map_err(bad)?;
                ConnectionReply::Created {
                    locker: b.req(1).and_then(fixed::<16>).map_err(bad)?,
                    id: b.req(2).and_then(fixed::<16>).map_err(bad)?,
                }
            }
            ConnectionOp::ConnectionRead => {
                ConnectionReply::Card(Box::new(card_from(body()?).map_err(bad)?))
            }
        };
        Ok((id, Ok(reply)))
    }
}
