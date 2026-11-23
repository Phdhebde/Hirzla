//! Enrolment of a new device of the member through the server (`sync-protocol.md` § 14,
//! ADR 0081).
//!
//! - **New device N** ([`Enrolling`], held by the core while it has no vault): draws its keys,
//!   drops its public keys before `Auth` at the rendezvous derived from its control code,
//!   then looks for its package in its own mailbox. Its private keys stay in memory only.
//! - **Certification device E** ([`ServerMode::enrol_fetch`], [`ServerMode::enrol_approve`],
//!   [`ServerMode::enrol_complete`]): fetches the keys by the code the user typed, checks
//!   them against it, certifies them inside the vault, sends the package, and once N has
//!   authenticated (its certificate inscribed in the key log) adds it to every shared locker
//!   where the member has a role.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use hirzla_sync::enrol::{self, EnrolRequest, Enrolment, PendingDevice};
use hirzla_sync::net::client::{Client, Identity};
use hirzla_sync::net::proto::code;
use hirzla_sync::net::{tls, NetError};
use hirzla_sync::text::Invitation;
use hirzla_vault::model::{DeviceCert, Id16};
use hirzla_vault::{Vault, VaultError};

use super::proto::{ServerCode, ServerReply};
use super::{
    emit_error, fingerprint, general, internal, net, parse_address, write_log, Address, ServerMode,
};
use crate::proto::ErrorCode;

/// An enrolment in progress on the new device: its keys, the server of the invitation, and
/// the package once received. Neither `Debug` nor `Clone`: it holds private keys.
pub struct Enrolling {
    pending: PendingDevice,
    address: Address,
    roots: Vec<u8>,
    server_fingerprint: String,
    code: String,
    received: Option<Enrolment>,
}

/// Opens a session as a device being enrolled (`Hello` only), checking the server key
/// against the fingerprint of the invitation before anything is sent.
fn connect(
    address: &Address,
    roots: &[u8],
    server_fingerprint: &str,
    device: Id16,
) -> Result<Client, ServerCode> {
    let config = tls::client_config(
        tls::roots(tls::certs_from_pem(roots).map_err(|_| ServerCode::InvitationInvalid)?)
            .map_err(|_| ServerCode::InvitationInvalid)?,
        None,
    )
    .map_err(net)?;
    // Name resolution of the server of the invitation only (rule 7).
    let addr: SocketAddr = match address.host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, address.port),
        Err(_) => (address.host.as_str(), address.port)
            .to_socket_addrs()
            .map_err(|_| ServerCode::ServerUnreachable)?
            .next()
            .ok_or(ServerCode::ServerUnreachable)?,
    };
    let mut mismatch = false;
    let who = Identity::Enrolling {
        member: [0; 16],
        device,
    };
    Client::connect_checked(
        addr,
        &address.host,
        &config,
        |k| {
            mismatch = fingerprint(k.as_bytes()) != server_fingerprint;
            !mismatch
        },
        &who,
    )
    .map_err(|e| {
        if mismatch {
            ServerCode::FingerprintMismatch
        } else {
            net(e)
        }
    })
}

impl Enrolling {
    /// `DeviceEnrolStart` (130): draws the keys, drops the request at the rendezvous.
    ///
    /// # Errors
    /// [`ServerCode::InvitationInvalid`], [`ServerCode::FingerprintMismatch`], network errors;
    /// [`ServerCode::ServerRefused`] when the server does not accept a drop before `Auth`
    /// (a server older than ADR 0081).
    pub fn start(link: &str) -> Result<(Enrolling, ServerReply), ServerCode> {
        let inv = Invitation::decode(link).map_err(|_| ServerCode::InvitationInvalid)?;
        let address = parse_address(&inv.address).ok_or(ServerCode::InvitationInvalid)?;
        let server_fingerprint = super::proto::normalise_fingerprint(&inv.fingerprint)
            .ok_or(ServerCode::InvitationInvalid)?;
        let pending = PendingDevice::generate().map_err(internal)?;
        let code = pending.code().map_err(internal)?;
        let request = pending.request().encode().map_err(internal)?;
        let mut client = connect(
            &address,
            &inv.roots,
            &server_fingerprint,
            pending.device_id(),
        )?;
        let dropped = client.mailbox_put(&enrol::rendezvous(&code), &request);
        let _ = client.bye();
        dropped.map_err(|e| match e {
            NetError::Refused(c) => ServerCode::ServerRefused(c),
            // The refusal of an old server arrives instead of the `Pong`.
            NetError::Protocol => ServerCode::ServerRefused(code::ACCESS),
            e => net(e),
        })?;
        let reply = ServerReply::EnrolCode(code.clone());
        Ok((
            Enrolling {
                pending,
                address,
                roots: inv.roots,
                server_fingerprint,
                code,
                received: None,
            },
            reply,
        ))
    }

    /// `DeviceEnrolWait` (131): looks once for the package in the device's own mailbox. The
    /// member fingerprint once it arrived and opened, `None` while waiting.
    ///
    /// # Errors
    /// Network errors; [`ServerCode::ApprovalInvalid`] for a package that does not open or
    /// does not verify (it is dropped: the server cannot forge one).
    pub fn wait(&mut self) -> Result<ServerReply, ServerCode> {
        if let Some(e) = &self.received {
            return Ok(ServerReply::EnrolState(Some(fingerprint(&e.member.sig))));
        }
        let mut client = connect(
            &self.address,
            &self.roots,
            &self.server_fingerprint,
            self.pending.device_id(),
        )?;
        let got = client.mailbox_get(&self.pending.device_id());
        let _ = client.bye();
        let bytes = match got {
            Ok(b) => b,
            Err(NetError::Refused(c)) if c == code::ACCESS => {
                return Ok(ServerReply::EnrolState(None))
            }
            Err(e) => return Err(net(e)),
        };
        let opened = self
            .pending
            .open_package(&bytes)
            .map_err(|_| ServerCode::ApprovalInvalid)?;
        let fp = fingerprint(&opened.member.sig);
        self.received = Some(opened);
        Ok(ServerReply::EnrolState(Some(fp)))
    }

    /// The control code shown to the user.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Whether the package arrived and was verified.
    #[must_use]
    pub fn received(&self) -> bool {
        self.received.is_some()
    }

    /// The identity for the new vault, the server to join (address, roots, fingerprint) and
    /// the certificate of E, once the package arrived.
    ///
    /// # Errors
    /// [`ErrorCode::NotFound`] while the package has not arrived.
    pub fn finish(self) -> Result<Enrolled, ServerCode> {
        let received = self.received.ok_or(general(ErrorCode::NotFound))?;
        let (_, sign, kem) = self.pending.into_keys();
        Ok(Enrolled {
            identity: hirzla_vault::EnrolledIdentity {
                member: received.member,
                cert: received.cert,
                sign,
                kem,
            },
            url: format!(
                "hirzla://{}:{}",
                bracket(&self.address.host),
                self.address.port
            ),
            roots: self.roots,
            server_fingerprint: self.server_fingerprint,
            issuer: received.issuer,
        })
    }
}

fn bracket(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// What the new device needs to create its vault and join the server.
pub struct Enrolled {
    /// Identity for [`Vault::create_enrolled`].
    pub identity: hirzla_vault::EnrolledIdentity,
    /// Server address.
    pub url: String,
    /// Site CA.
    pub roots: Vec<u8>,
    /// Server fingerprint, from the invitation.
    pub server_fingerprint: String,
    /// Certificate of the certification device that enrolled this one.
    pub issuer: DeviceCert,
}

impl ServerMode {
    /// Joins the server of the enrolment, with the fingerprint of the invitation, expects
    /// the certificate of E in the key log (no alert « unknown device ») and synchronises
    /// once: authenticating inscribes this device's certificate.
    ///
    /// # Errors
    /// As `ServerJoin`.
    pub fn join_enrolled(
        &mut self,
        vault: &Vault,
        url: &str,
        roots: Vec<u8>,
        server_fingerprint: &str,
        issuer: &DeviceCert,
    ) -> Result<(), ServerCode> {
        self.join(vault, url, roots, Some(server_fingerprint))?;
        write_log(&self.joined()?.keylog.monitor)?
            .expect_own_device(issuer)
            .map_err(internal)?;
        Ok(())
    }

    /// `DeviceEnrolFetch` (134): the keys dropped at the rendezvous of `typed`, checked
    /// against it.
    pub(super) fn enrol_fetch(
        &mut self,
        vault: &Vault,
        typed: &str,
    ) -> Result<ServerReply, ServerCode> {
        if !vault.holds_member_key() {
            return Err(ServerCode::Forbidden);
        }
        let code = enrol::normalise_code(typed).ok_or(general(ErrorCode::InvalidInput))?;
        // Nothing to give the new device without a shared locker: refused before the
        // request is taken from the rendezvous, so the same code still works afterwards.
        if !self.holds_any_role(&self.device.member_id()) {
            return Err(general(ErrorCode::Unsupported));
        }
        let mut client = self.session()?;
        let got = client.mailbox_get(&enrol::rendezvous(&code));
        let _ = client.bye();
        let bytes = match got {
            Ok(b) => b,
            Err(NetError::Refused(c)) if c == code::ACCESS => {
                return Err(general(ErrorCode::NotFound))
            }
            Err(e) => return Err(net(e)),
        };
        let request = EnrolRequest::decode(&bytes).map_err(|_| general(ErrorCode::Malformed))?;
        // Keys that do not give the typed code were substituted (or the code mistyped).
        if !request.matches(&code) {
            return Err(ServerCode::FingerprintMismatch);
        }
        if request.device == self.device.device_id() {
            return Err(general(ErrorCode::InvalidInput));
        }
        let device = request.device;
        self.enrol_fetched = Some(request);
        Ok(ServerReply::EnrolPeer {
            fingerprint: fingerprint(&self.device.member_keys().sig),
            device,
        })
    }

    /// `DeviceEnrolApprove` (135): certifies the device fetched, inside the vault, seals its
    /// package and sends it to the device's mailbox. Its certificate is expected in the key
    /// log from now on.
    pub(super) fn enrol_approve(
        &mut self,
        vault: &Vault,
        device: Id16,
    ) -> Result<ServerReply, ServerCode> {
        let request = match self.enrol_fetched.take() {
            Some(r) if r.device == device => r,
            other => {
                self.enrol_fetched = other;
                return Err(general(ErrorCode::NotFound));
            }
        };
        let cert = vault
            .certify_device(request.device, &request.sig, &request.kem)
            .map_err(|e| match e {
                VaultError::Unsupported => ServerCode::Forbidden,
                VaultError::InvalidInput => general(ErrorCode::InvalidInput),
                other => internal(other),
            })?;
        let info = self.joined()?.info.clone();
        let package =
            enrol::seal_package(&self.device, &cert, vault.personal_locker(), 1, Some(info))
                .map_err(internal)?;
        write_log(&self.joined()?.keylog.monitor)?
            .expect_own_device(&cert)
            .map_err(internal)?;
        let mut client = self.session()?;
        let sent = client.mailbox_put(&cert.device, &package);
        let _ = client.bye();
        sent.map_err(net)?;
        self.enrol_issued = Some(cert);
        Ok(ServerReply::Done)
    }

    /// `DeviceEnrolComplete` (136): once the new device authenticated (its certificate is in
    /// the key log), a `DeviceAdd` in every shared locker where the member has a role and
    /// writes are not frozen. `None` while it has not.
    pub(super) fn enrol_complete(
        &mut self,
        vault: &Vault,
        device: Id16,
    ) -> Result<ServerReply, ServerCode> {
        let cert = match &self.enrol_issued {
            Some(c) if c.device == device => c.clone(),
            _ => return Err(general(ErrorCode::NotFound)),
        };
        let me = self.device.member_id();
        let mut client = self.session()?;
        self.update_keylog(vault, &mut client)?;
        self.keylog_sound()?;
        let inscribed = super::read_log(&self.joined()?.keylog.monitor)?
            .check_recipient(self.device.member_keys(), &cert)
            .is_ok();
        if !inscribed {
            let _ = client.bye();
            return Ok(ServerReply::EnrolCompleted(None));
        }
        let now = self.now();
        let frozen = self.frozen_lockers(now)?;
        let mut added = Vec::new();
        {
            let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
            for (id, s) in &mut j.lockers {
                let Some(state) = s.replica.authorization().map(|a| a.access().state()) else {
                    continue;
                };
                if state.role(&me).is_none()
                    || frozen.contains(id)
                    || state.active_device(&me, &cert.device).is_some()
                {
                    continue;
                }
                s.replica.device_add(cert.clone()).map_err(emit_error)?;
                added.push(*id);
            }
        }
        if added.is_empty() && !self.holds_any_role(&me) {
            let _ = client.bye();
            // Nothing to give the new device: no shared locker yet (ADR 0081).
            return Err(general(ErrorCode::Unsupported));
        }
        let mut failure = None;
        for id in &added {
            if let Err(e) = self.publish(vault, &mut client, id) {
                failure = Some(e);
                break;
            }
        }
        let _ = client.bye();
        if let Some(e) = failure {
            return Err(e);
        }
        self.enrol_issued = None;
        Ok(ServerReply::EnrolCompleted(Some(added.len() as u64)))
    }

    fn holds_any_role(&self, me: &Id16) -> bool {
        self.joined.as_ref().is_some_and(|j| {
            j.lockers.values().any(|s| {
                s.replica
                    .authorization()
                    .is_some_and(|a| a.access().state().role(me).is_some())
            })
        })
    }
}
