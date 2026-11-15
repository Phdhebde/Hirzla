//! Network front of `hirzlad`: the device port and the administration port, one thread per
//! connection, over TLS 1.3 ([`crate::tls`]).
//!
//! The server only **accepts** connections. It opens none: no telemetry, no update check, no
//! name resolution, no CDN (`CLAUDE.md`, rule 7). The test `no_outbound_connection` checks it
//! on the binary.
//!
//! Before the quorum of custodians has unsealed the root key, the device port answers every
//! request with code 10 (unavailable) and the administration port accepts only the status and
//! the shares.

use std::io::{ErrorKind, Read};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hirzla_audit::field::AccountId;
use hirzla_audit::Event;
use hirzla_crypto::util::sha384;
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::core::{Core, Session};
use crate::proto::{
    self, code, kind, AdminStatus, FrameBuffer, Message, ALPN, EXPORTER_LABEL, EXPORTER_LEN,
};
use crate::seal::{SealProvider, Unsealer};
use crate::store::SealHeader;
use crate::ServerError;

/// Handshake and first-message deadline.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Poll period of a connection (spontaneous messages, stop flag).
const POLL: Duration = Duration::from_millis(50);
/// A connection silent for this long is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// What `hirzlad serve` needs.
pub struct Config {
    /// Data directory.
    pub data_dir: PathBuf,
    /// Device port.
    pub listen: SocketAddr,
    /// Administration port: another port, ideally on a management interface.
    pub admin_listen: SocketAddr,
    /// TLS of the device port.
    pub tls: Arc<ServerConfig>,
    /// TLS of the administration port (client certificate required).
    pub admin_tls: Arc<ServerConfig>,
}

struct Shared {
    dir: PathBuf,
    header: SealHeader,
    core: Mutex<Option<Core>>,
    unsealer: Mutex<Unsealer>,
    /// Administration events seen while sealed, recorded once the audit log opens.
    pending_admin: Mutex<Vec<Event>>,
    stop: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>, ServerError> {
    m.lock().map_err(|_| ServerError::Storage)
}

/// A running server.
pub struct Running {
    /// Bound device address.
    pub addr: SocketAddr,
    /// Bound administration address.
    pub admin_addr: SocketAddr,
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl Running {
    /// Stops accepting and waits for the listeners.
    pub fn stop(self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        for t in self.threads {
            let _ = t.join();
        }
    }

    /// Blocks until the listeners end.
    pub fn wait(self) {
        for t in self.threads {
            let _ = t.join();
        }
    }

    /// Runs `f` on the unsealed core (tests: memory image, members).
    ///
    /// # Errors
    /// [`ServerError::Sealed`].
    #[doc(hidden)]
    pub fn with_core<R>(&self, f: impl FnOnce(&mut Core) -> R) -> Result<R, ServerError> {
        let mut g = lock(&self.shared.core)?;
        g.as_mut().map(f).ok_or(ServerError::Sealed)
    }
}

/// Binds both ports and starts serving, sealed.
///
/// # Errors
/// [`ServerError::Config`] if both ports are the same, [`ServerError::Io`], header errors.
pub fn start(config: Config) -> Result<Running, ServerError> {
    if config.listen.port() != 0 && config.listen.port() == config.admin_listen.port() {
        return Err(ServerError::Config(
            "the administration port must differ from the device port",
        ));
    }
    let header = SealHeader::read(&config.data_dir)?;
    let dealer = header.dealer.clone().ok_or(ServerError::SealUnavailable)?;
    let shared = Arc::new(Shared {
        dir: config.data_dir.clone(),
        header,
        core: Mutex::new(None),
        unsealer: Mutex::new(Unsealer::new(dealer)),
        pending_admin: Mutex::new(Vec::new()),
        stop: AtomicBool::new(false),
    });
    let device = TcpListener::bind(config.listen)?;
    let admin = TcpListener::bind(config.admin_listen)?;
    let addr = device.local_addr()?;
    let admin_addr = admin.local_addr()?;
    let mut threads = Vec::new();
    {
        let shared = Arc::clone(&shared);
        let tls = config.tls;
        threads.push(std::thread::spawn(move || {
            accept_loop(&device, &shared, move |sh, tcp| {
                device_connection(sh, &tls, tcp)
            });
        }));
    }
    {
        let shared = Arc::clone(&shared);
        let tls = config.admin_tls;
        threads.push(std::thread::spawn(move || {
            accept_loop(&admin, &shared, move |sh, tcp| {
                admin_connection(sh, &tls, tcp)
            });
        }));
    }
    Ok(Running {
        addr,
        admin_addr,
        shared,
        threads,
    })
}

fn accept_loop<F>(listener: &TcpListener, shared: &Arc<Shared>, handler: F)
where
    F: Fn(&Arc<Shared>, TcpStream) -> Result<(), ServerError> + Send + Sync + Clone + 'static,
{
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    while !shared.stop.load(Ordering::SeqCst) {
        let tcp = match listener.accept() {
            Ok((tcp, _)) => tcp,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(POLL);
                continue;
            }
            Err(_) => continue,
        };
        if tcp.set_nonblocking(false).is_err() {
            continue;
        }
        let shared = Arc::clone(shared);
        let handler = handler.clone();
        std::thread::spawn(move || {
            let _ = handler(&shared, tcp);
        });
    }
}

type Tls = StreamOwned<ServerConnection, TcpStream>;

/// TLS handshake, ALPN check, exporter (§ 11.3).
fn handshake(
    tls: &Arc<ServerConfig>,
    tcp: TcpStream,
) -> Result<(Tls, IpAddr, [u8; EXPORTER_LEN]), ServerError> {
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    tcp.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let ip = tcp.peer_addr()?.ip();
    let mut s = StreamOwned::new(ServerConnection::new(Arc::clone(tls))?, tcp);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    if s.conn.alpn_protocol() != Some(ALPN) {
        return Err(ServerError::Protocol);
    }
    let mut exporter = [0u8; EXPORTER_LEN];
    s.conn
        .export_keying_material(&mut exporter, EXPORTER_LABEL, Some(&[]))?;
    s.sock.set_read_timeout(Some(POLL))?;
    Ok((s, ip, exporter))
}

/// Reads what is available; `Ok(false)` when the peer closed.
fn fill(s: &mut Tls, fb: &mut FrameBuffer) -> Result<bool, ServerError> {
    let mut buf = [0u8; 16 * 1024];
    match s.read(&mut buf) {
        Ok(0) => Ok(false),
        Ok(n) => {
            fb.extend(&buf[..n]);
            Ok(true)
        }
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(true),
        Err(e) => Err(e.into()),
    }
}

fn device_connection(
    shared: &Arc<Shared>,
    tls: &Arc<ServerConfig>,
    tcp: TcpStream,
) -> Result<(), ServerError> {
    let (mut s, ip, exporter) = handshake(tls, tcp)?;
    let mut session = Session::new(ip, exporter);
    let mut fb = FrameBuffer::default();
    let mut last = Instant::now();
    loop {
        if shared.stop.load(Ordering::SeqCst) || last.elapsed() > IDLE_TIMEOUT {
            return Ok(());
        }
        if !fill(&mut s, &mut fb)? {
            return Ok(());
        }
        while let Some(m) = fb.next_message()? {
            last = Instant::now();
            let out = {
                let mut g = lock(&shared.core)?;
                match g.as_mut() {
                    Some(core) => core.handle(&mut session, m),
                    None => vec![Message::error(m.req, code::UNAVAILABLE)],
                }
            };
            for o in &out {
                proto::write_message(&mut s, o)?;
            }
            if session.closed() {
                return Ok(());
            }
        }
        let spontaneous = {
            let mut g = lock(&shared.core)?;
            g.as_mut()
                .map(|c| c.pending(&mut session))
                .unwrap_or_default()
        };
        for o in &spontaneous {
            proto::write_message(&mut s, o)?;
        }
    }
}

fn status(shared: &Shared) -> Result<AdminStatus, ServerError> {
    let sealed = lock(&shared.core)?.is_none();
    let u = lock(&shared.unsealer)?;
    Ok(AdminStatus {
        sealed,
        shares: u.received(),
        threshold: u.threshold(),
        server_id: shared.header.server_id,
        server_key_fingerprint: sha384(shared.header.server_key.as_bytes()),
    })
}

fn admin_event(shared: &Shared, e: Event) -> Result<(), ServerError> {
    let mut g = lock(&shared.core)?;
    match g.as_mut() {
        Some(core) => core.audit_admin(e),
        None => {
            lock(&shared.pending_admin)?.push(e);
            Ok(())
        }
    }
}

fn unseal(shared: &Shared, share: &[u8]) -> Result<(), ServerError> {
    if lock(&shared.core)?.is_some() {
        return Ok(());
    }
    let Some(seal) = lock(&shared.unsealer)?.add(share)? else {
        return Ok(());
    };
    let storage = seal.unwrap(&shared.header.wrapped_storage_key)?;
    drop(seal);
    let mut core = Core::open(&shared.dir, &shared.header, storage)?;
    for e in lock(&shared.pending_admin)?.drain(..) {
        core.audit_admin(e)?;
    }
    *lock(&shared.core)? = Some(core);
    Ok(())
}

fn admin_handle(shared: &Shared, m: &Message) -> Result<Message, ServerError> {
    let req = m.req;
    Ok(match m.kind {
        kind::ADMIN_STATUS => {
            Message::new(kind::ADMIN_STATUS_RESULT, req, status(shared)?.to_value())
        }
        kind::ADMIN_UNSEAL => {
            let share = proto::read_blob(&m.body, 64 * 1024)?;
            match unseal(shared, &share) {
                Ok(()) => Message::new(kind::ADMIN_STATUS_RESULT, req, status(shared)?.to_value()),
                Err(ServerError::ShareRefused) => Message::error(req, code::AUTH),
                Err(_) => Message::error(req, code::UNAVAILABLE),
            }
        }
        kind::ADMIN_CREATE_ACCOUNT => {
            let keys = proto::read_create_account(&m.body)?;
            let mut g = lock(&shared.core)?;
            let Some(core) = g.as_mut() else {
                return Ok(Message::error(req, code::UNAVAILABLE));
            };
            match core.create_account(&keys) {
                Ok((account, index)) => Message::new(
                    kind::ADMIN_ACCOUNT,
                    req,
                    proto::account_value(&account, index),
                ),
                Err(ServerError::Config(_) | ServerError::Malformed) => {
                    Message::error(req, code::ACCESS)
                }
                Err(_) => Message::error(req, code::UNAVAILABLE),
            }
        }
        kind::ADMIN_CHECKPOINT => {
            let mut g = lock(&shared.core)?;
            let Some(core) = g.as_mut() else {
                return Ok(Message::error(req, code::UNAVAILABLE));
            };
            let cp = core.audit_checkpoint()?;
            let bytes = hirzla_audit::Record::Checkpoint(cp).to_bytes()?;
            Message::new(
                kind::ADMIN_CHECKPOINT_RESULT,
                req,
                proto::blob_value(&bytes),
            )
        }
        kind::ADMIN_SHUTDOWN => {
            // Graceful stop by an authenticated administrator: the listeners end, then the
            // process. Every record is already on disk; the next start records `log_resumed`
            // (the catalogue has no stop event, `evenements.md`).
            shared.stop.store(true, Ordering::SeqCst);
            Message::new(kind::BYE, req, proto::empty())
        }
        kind::PING => Message::new(kind::PONG, req, proto::empty()),
        kind::BYE => Message::new(kind::BYE, req, proto::empty()),
        _ => Message::error(req, code::MALFORMED),
    })
}

fn admin_connection(
    shared: &Arc<Shared>,
    tls: &Arc<ServerConfig>,
    tcp: TcpStream,
) -> Result<(), ServerError> {
    let peer_ip = tcp.peer_addr().map(|a| a.ip()).ok();
    let (mut s, ip, _) = match handshake(tls, tcp) {
        Ok(x) => x,
        Err(e) => {
            if let Some(ip) = peer_ip {
                let _ = admin_event(shared, Event::AdminLoginFailed { ip });
            }
            return Err(e);
        }
    };
    // The verifier required a certificate of the administration CA: name the account after it.
    let account = s
        .conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| {
            let h = sha384(c.as_ref());
            let mut a = [0u8; 16];
            a.copy_from_slice(&h[..16]);
            a
        })
        .ok_or(ServerError::Protocol)?;
    admin_event(
        shared,
        Event::AdminLogin {
            account: AccountId::from_bytes(account),
            ip,
        },
    )?;
    let mut fb = FrameBuffer::default();
    let mut last = Instant::now();
    loop {
        if shared.stop.load(Ordering::SeqCst) || last.elapsed() > IDLE_TIMEOUT {
            return Ok(());
        }
        if !fill(&mut s, &mut fb)? {
            return Ok(());
        }
        while let Some(m) = fb.next_message()? {
            last = Instant::now();
            let out =
                admin_handle(shared, &m).unwrap_or_else(|_| Message::error(m.req, code::MALFORMED));
            proto::write_message(&mut s, &out)?;
            if m.kind == kind::BYE || m.kind == kind::ADMIN_SHUTDOWN {
                return Ok(());
            }
        }
    }
}
