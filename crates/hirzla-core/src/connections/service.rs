//! What the core does with a connection request (`docs/api-locale.md` § 17): it stores and
//! reads connection secrets, checks links when they are written and resolves them when they
//! are read. It never connects to a host.

use std::collections::BTreeSet;

use hirzla_vault::model::Id16;
use hirzla_vault::secret::{
    Field, FieldValue, SecretBody, SecretEdit, SecretLink, SecretState, SecretType, SetKind,
    SetValue,
};
use zeroize::Zeroizing;

use super::proto::{
    ConnectionCard, ConnectionFields, ConnectionKey, ConnectionReply, ConnectionRequest, LinkState,
    ResolvedLink, MAX_JUMPS,
};
use crate::events::Event;
use crate::proto::{ErrorCode, ErrorReply};
use crate::service::{vault_error, Core};

/// First line of a private key file written by OpenSSH (`docs/format.md` § 8.3).
const OPENSSH_ARMOR: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----";

fn invalid() -> ErrorCode {
    ErrorCode::InvalidInput
}

fn text_of(body: &SecretBody, field: Field) -> Option<Zeroizing<String>> {
    match body.fields.get(&field).map(|e| &e.value) {
        Some(FieldValue::Text(t)) => Some(t.clone()),
        _ => None,
    }
}

fn link_of(body: &SecretBody, field: Field) -> Option<SecretLink> {
    match body.fields.get(&field).map(|e| &e.value) {
        Some(FieldValue::Link(l)) => Some(*l),
        _ => None,
    }
}

fn port_of(body: &SecretBody) -> Option<u16> {
    match body.fields.get(&Field::Port).map(|e| &e.value) {
        Some(FieldValue::Uint(n)) => u16::try_from(*n).ok(),
        _ => None,
    }
}

fn effective_port(body: &SecretBody) -> u16 {
    port_of(body)
        .or_else(|| body.secret_type.default_port())
        .unwrap_or(0)
}

/// The vault field a connection key is stored in.
fn field_of(key: ConnectionKey) -> Field {
    match key {
        ConnectionKey::Title => Field::Title,
        ConnectionKey::Host => Field::Host,
        ConnectionKey::Port => Field::Port,
        ConnectionKey::Username => Field::Username,
        ConnectionKey::Domain => Field::Domain,
        ConnectionKey::Password => Field::Password,
        ConnectionKey::SshKey => Field::SshKeyLink,
        ConnectionKey::Jump => Field::Jump,
        ConnectionKey::HostKey => Field::HostKey,
        ConnectionKey::Notes => Field::Notes,
        ConnectionKey::Favorite => Field::Favorite,
    }
}

/// The fields to set in the vault for the connection fields given.
fn fields_to_set(f: ConnectionFields) -> Vec<(Field, FieldValue)> {
    let mut set = Vec::new();
    let texts = [
        (Field::Title, f.title),
        (Field::Host, f.host),
        (Field::Username, f.username),
        (Field::Domain, f.domain),
        (Field::Password, f.password),
        (Field::HostKey, f.host_key),
        (Field::Notes, f.notes),
    ];
    for (field, value) in texts {
        if let Some(t) = value {
            set.push((field, FieldValue::Text(t)));
        }
    }
    if let Some(p) = f.port {
        set.push((Field::Port, FieldValue::Uint(u64::from(p))));
    }
    if let Some(l) = f.ssh_key {
        set.push((Field::SshKeyLink, FieldValue::Link(l)));
    }
    if let Some(l) = f.jump {
        set.push((Field::Jump, FieldValue::Link(l)));
    }
    if let Some(b) = f.favorite {
        set.push((Field::Favorite, FieldValue::Bool(b)));
    }
    set
}

fn tags_to_add(tags: Vec<Zeroizing<String>>) -> Vec<(SetKind, SetValue)> {
    tags.into_iter()
        .map(|t| (SetKind::Tags, SetValue::Text(t)))
        .collect()
}

impl Core {
    /// Answers one connection request and logs its outcome (operation and result only).
    ///
    /// # Errors
    /// The general code of the refusal.
    pub fn handle_connection(
        &mut self,
        request: ConnectionRequest,
    ) -> Result<ConnectionReply, ErrorCode> {
        let op = request.op();
        let result = self.dispatch_connection(request);
        self.log.record(Event::ConnectionRequest {
            op,
            result: result.as_ref().err().map_or("ok", |c| c.name()),
        });
        result
    }

    fn dispatch_connection(
        &mut self,
        request: ConnectionRequest,
    ) -> Result<ConnectionReply, ErrorCode> {
        match request {
            ConnectionRequest::Create {
                locker,
                secret_type,
                fields,
                tags,
            } => {
                if !secret_type.is_connection() {
                    return Err(invalid());
                }
                let locker = self.target_locker(locker)?;
                self.check_links(None, &fields)?;
                let edit = SecretEdit {
                    set: fields_to_set(fields),
                    add: tags_to_add(tags),
                    ..SecretEdit::default()
                };
                let id = self.create_in(locker, secret_type, edit)?;
                Ok(ConnectionReply::Created { locker, id })
            }
            ConnectionRequest::Read { locker, id } => {
                let body = self.connection(&locker, &id)?;
                Ok(ConnectionReply::Card(Box::new(
                    self.card(&locker, &id, &body)?,
                )))
            }
            ConnectionRequest::Update {
                locker,
                id,
                set,
                clear,
            } => {
                let body = self.connection(&locker, &id)?;
                self.check_links(Some(SecretLink { locker, secret: id }), &set)?;
                let edit = SecretEdit {
                    set: fields_to_set(set),
                    clear: clear.into_iter().map(field_of).collect(),
                    ..SecretEdit::default()
                };
                if self.is_shared(&locker) {
                    self.write_shared(&locker, Some(id), body.secret_type, edit)
                        .map_err(|e| e.code)?;
                } else {
                    self.vault()
                        .map_err(|e| e.code)?
                        .update_secret(locker, id, edit)
                        .map_err(|e| vault_error(e).code)?;
                }
                Ok(ConnectionReply::Done)
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
                // Stored as OpenSSH wrote it; only the armour is checked, nothing is parsed.
                if !private_key.starts_with(OPENSSH_ARMOR) {
                    return Err(invalid());
                }
                let locker = self.target_locker(locker)?;
                let mut set = vec![
                    (Field::Title, FieldValue::Text(title)),
                    (Field::SshPrivateKey, FieldValue::Bytes(private_key)),
                ];
                let texts = [
                    (Field::SshPublicKey, public_key),
                    (Field::SshPassphrase, passphrase),
                    (Field::Username, username),
                ];
                for (field, value) in texts {
                    if let Some(t) = value {
                        set.push((field, FieldValue::Text(t)));
                    }
                }
                let edit = SecretEdit {
                    set,
                    add: tags_to_add(tags),
                    ..SecretEdit::default()
                };
                let id = self.create_in(locker, SecretType::SshKey, edit)?;
                Ok(ConnectionReply::Created { locker, id })
            }
        }
    }

    /// The locker a creation goes to: the one given, or the personal locker.
    pub(crate) fn target_locker(&mut self, locker: Option<Id16>) -> Result<Id16, ErrorCode> {
        let personal = self.vault().map_err(|e| e.code)?.personal_locker();
        Ok(locker.unwrap_or(personal))
    }

    /// Creates a secret in a locker of the vault or in a shared locker.
    pub(crate) fn create_in(
        &mut self,
        locker: Id16,
        secret_type: SecretType,
        edit: SecretEdit,
    ) -> Result<Id16, ErrorCode> {
        if self.is_shared(&locker) {
            return self
                .write_shared(&locker, None, secret_type, edit)
                .map_err(|e| e.code);
        }
        self.vault()
            .map_err(|e| e.code)?
            .create_secret(locker, secret_type, edit)
            .map_err(|e| vault_error(e).code)
    }

    /// The merged body of a secret this device holds, in the vault or in a shared locker;
    /// `None` if the locker or the secret is unknown. A purged secret is returned as such
    /// from the vault, and as `None` from a shared locker.
    pub(crate) fn secret_body(
        &mut self,
        locker: &Id16,
        id: &Id16,
    ) -> Result<Option<SecretBody>, ErrorReply> {
        self.vault()?;
        if self.is_shared(locker) {
            return Ok(self.server().and_then(|s| s.read(locker, id)).cloned());
        }
        let vault = self.vault()?;
        let Ok(entries) = vault.list(*locker) else {
            return Ok(None);
        };
        if !entries.iter().any(|e| e.secret_id == *id) {
            return Ok(None);
        }
        vault
            .read_secret(*locker, *id)
            .map(Some)
            .map_err(vault_error)
    }

    /// A connection that is not purged, or `NotFound`.
    fn connection(&mut self, locker: &Id16, id: &Id16) -> Result<SecretBody, ErrorCode> {
        self.secret_body(locker, id)
            .map_err(|e| e.code)?
            .filter(|b| b.secret_type.is_connection() && b.state.0 != SecretState::Purged)
            .ok_or(ErrorCode::NotFound)
    }

    /// The target of a link, if it exists, is not purged and has the type `expected`.
    fn link_target(
        &mut self,
        link: &SecretLink,
        expected: SecretType,
    ) -> Result<Result<SecretBody, LinkState>, ErrorCode> {
        let body = self
            .secret_body(&link.locker, &link.secret)
            .map_err(|e| e.code)?
            .filter(|b| b.state.0 != SecretState::Purged);
        Ok(match body {
            None => Err(LinkState::Broken),
            Some(b) if b.secret_type != expected => Err(LinkState::WrongType),
            Some(b) => Ok(b),
        })
    }

    /// Checks the links a write sets (§ 17.3, point 2): each target exists, is not purged and
    /// has the expected type; the chain of jump hosts neither comes back to `this` (the
    /// connection being changed), nor loops, nor exceeds [`MAX_JUMPS`].
    fn check_links(
        &mut self,
        this: Option<SecretLink>,
        fields: &ConnectionFields,
    ) -> Result<(), ErrorCode> {
        if let Some(key) = &fields.ssh_key {
            self.link_target(key, SecretType::SshKey)?
                .map_err(|_| invalid())?;
        }
        let mut seen: BTreeSet<SecretLink> = this.into_iter().collect();
        let mut next = fields.jump;
        let mut hops = 0;
        while let Some(link) = next {
            hops += 1;
            if hops > MAX_JUMPS || !seen.insert(link) {
                return Err(invalid());
            }
            let Ok(target) = self.link_target(&link, SecretType::SshConnection)? else {
                // The first link must be valid; further down, a chain already broken is
                // shown as such when read, and is no reason to refuse this write.
                return if hops == 1 { Err(invalid()) } else { Ok(()) };
            };
            next = link_of(&target, Field::Jump);
        }
        Ok(())
    }

    /// The chain of jump hosts of a connection, nearest first (§ 17.2).
    fn jumps(
        &mut self,
        this: SecretLink,
        body: &SecretBody,
    ) -> Result<Vec<ResolvedLink>, ErrorCode> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::from([this]);
        let mut next = link_of(body, Field::Jump);
        while let Some(link) = next {
            if out.len() == MAX_JUMPS || !seen.insert(link) {
                out.push(ResolvedLink::bare(link, LinkState::Loop));
                break;
            }
            match self.link_target(&link, SecretType::SshConnection)? {
                Err(state) => {
                    out.push(ResolvedLink::bare(link, state));
                    break;
                }
                Ok(target) => {
                    out.push(ResolvedLink {
                        link,
                        state: if target.state.0 == SecretState::Trash {
                            LinkState::Trashed
                        } else {
                            LinkState::Valid
                        },
                        title: text_of(&target, Field::Title),
                        host: text_of(&target, Field::Host),
                        port: Some(effective_port(&target)),
                        username: text_of(&target, Field::Username),
                        public_key: None,
                    });
                    next = link_of(&target, Field::Jump);
                }
            }
        }
        Ok(out)
    }

    /// The card of a connection: its fields without the password and the notes, and its
    /// links resolved.
    fn card(
        &mut self,
        locker: &Id16,
        id: &Id16,
        body: &SecretBody,
    ) -> Result<ConnectionCard, ErrorCode> {
        let ssh_key = match link_of(body, Field::SshKeyLink) {
            None => None,
            Some(link) => Some(match self.link_target(&link, SecretType::SshKey)? {
                Err(state) => ResolvedLink::bare(link, state),
                Ok(target) => ResolvedLink {
                    link,
                    state: if target.state.0 == SecretState::Trash {
                        LinkState::Trashed
                    } else {
                        LinkState::Valid
                    },
                    title: text_of(&target, Field::Title),
                    host: None,
                    port: None,
                    username: text_of(&target, Field::Username),
                    public_key: text_of(&target, Field::SshPublicKey),
                },
            }),
        };
        let jumps = self.jumps(
            SecretLink {
                locker: *locker,
                secret: *id,
            },
            body,
        )?;
        let mut tags: Vec<Zeroizing<String>> = body
            .sets
            .get(&SetKind::Tags)
            .map(|s| {
                s.visible()
                    .filter_map(|v| match v {
                        SetValue::Text(t) => Some(t.clone()),
                        SetValue::Attachment(_) => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        tags.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        tags.dedup_by(|a, b| a.as_str() == b.as_str());
        Ok(ConnectionCard {
            secret_type: body.secret_type,
            trashed: body.state.0 == SecretState::Trash,
            fields: ConnectionFields {
                title: text_of(body, Field::Title),
                host: text_of(body, Field::Host),
                port: port_of(body),
                username: text_of(body, Field::Username),
                domain: text_of(body, Field::Domain),
                password: None,
                ssh_key: link_of(body, Field::SshKeyLink),
                jump: link_of(body, Field::Jump),
                host_key: text_of(body, Field::HostKey),
                notes: None,
                favorite: Some(matches!(
                    body.fields.get(&Field::Favorite).map(|e| &e.value),
                    Some(FieldValue::Bool(true))
                )),
            },
            has_password: body.fields.contains_key(&Field::Password),
            has_notes: body.fields.contains_key(&Field::Notes),
            tags,
            effective_port: effective_port(body),
            ssh_key,
            jumps,
        })
    }
}
