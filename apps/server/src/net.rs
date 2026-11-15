//! Network front of `hirzlad`: the device port and the administration port, one thread per
//! connection, over TLS 1.3 ([`crate::tls`]).
//!
//! Each port is bounded ([`Limits`], ADR 0051): a ceiling of simultaneous connections, a
//! ceiling per source address (IPv4 address, IPv6 /64 prefix), a total deadline for the TLS
//! handshake and, on the device port, a deadline to authenticate. A connection beyond a
//! ceiling is closed at once, before any TLS work and without a thread. An `accept` that fails
//! (descriptors exhausted) backs off progressively instead of spinning.
//!
//! The server only **accepts** connections. It opens none: no telemetry, no update check, no
//! name resolution, no CDN (`CLAUDE.md`, rule 7). The test `no_outbound_connection` checks it
//! on the binary.
//!
//! Before the quorum of custodians has unsealed the root key, the device port answers every
//! request with code 10 (unavailable) and the administration port accepts only the status and
//! the shares.

use std::collections::HashMap;
use std::io::{ErrorKind, Read};
use std::net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hirzla_audit::field::AccountId;
use hirzla_audit::Event;
use hirzla_crypto::util::sha384;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use zeroize::{Zeroize, Zeroizing};

use crate::core::{Core, Session};
use crate::proto::{
    self, code, kind, AdminStatus, FrameBuffer, Message, ALPN, EXPORTER_LABEL, EXPORTER_LEN,
};
use crate::seal::{SealProvider, Unsealer};
use crate::store::SealHeader;
use crate::ServerError;

/// Total deadline of the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Poll period of a connection (spontaneous messages, stop flag).
const POLL: Duration = Duration::from_millis(50);
/// A connection silent for this long is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Longest pause of the accept loop after repeated `accept` errors.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Bounds of one port (ADR 0051). Beyond a ceiling, a new connection is closed at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Simultaneous connections on the port, handshakes included.
    pub max_connections: usize,
    /// Simultaneous connections from one source: an IPv4 address or an IPv6 /64 prefix.
    pub max_per_source: usize,
    /// Total deadline of the TLS handshake, from the accepted connection.
    pub handshake_timeout: Duration,
    /// Deadline, from the accepted connection, for a device to authenticate (`Auth`
    /// accepted). The administration port authenticates during the handshake (client
    /// certificate): this value is not used there.
    pub auth_timeout: Duration,
}

impl Limits {
    /// Device port: a thousand postes at once, 32 per source (a NAT of a small site),
    /// one minute to authenticate (an enrolling device fetches its package before `Auth`).
    pub const DEVICE: Limits = Limits {
        max_connections: 1024,
        max_per_source: 32,
        handshake_timeout: HANDSHAKE_TIMEOUT,
        auth_timeout: Duration::from_secs(60),
    };
    /// Administration port: a few administrators and custodians at once.
    pub const ADMIN: Limits = Limits {
        max_connections: 16,
        max_per_source: 4,
        handshake_timeout: HANDSHAKE_TIMEOUT,
        auth_timeout: HANDSHAKE_TIMEOUT,
    };
}

/// The key a source is counted under: the IPv4 address, or the /64 prefix of an IPv6 address
/// (one host usually holds a whole /64). An IPv4-mapped IPv6 address counts as IPv4.
fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// Counts the open connections of one port.
#[derive(Debug)]
struct Gate {
    limits: Limits,
    open: Mutex<GateState>,
}

#[derive(Debug, Default)]
struct GateState {
    total: usize,
    per_source: HashMap<IpAddr, usize>,
}

/// One admitted connection; frees its place when dropped.
#[derive(Debug)]
struct Slot {
    gate: Arc<Gate>,
    source: IpAddr,
}

impl Gate {
    fn new(limits: Limits) -> Arc<Gate> {
        Arc::new(Gate {
            limits,
            open: Mutex::new(GateState::default()),
        })
    }

    /// A place for a connection from `ip`, or `None` beyond a ceiling.
    fn enter(self: &Arc<Gate>, ip: IpAddr) -> Option<Slot> {
        let source = source_key(ip);
        let mut g = self.open.lock().ok()?;
        let n = g.per_source.get(&source).copied().unwrap_or(0);
        if g.total >= self.limits.max_connections || n >= self.limits.max_per_source {
            return None;
        }
        g.total += 1;
        g.per_source.insert(source, n + 1);
        Some(Slot {
            gate: Arc::clone(self),
            source,
        })
    }

    #[cfg(test)]
    fn open_connections(&self) -> usize {
        self.open.lock().map(|g| g.total).unwrap_or(usize::MAX)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        // A poisoned lock is left as is: the gate then admits nobody, which fails closed.
        if let Ok(mut g) = self.gate.open.lock() {
            g.total = g.total.saturating_sub(1);
            if let Some(n) = g.per_source.get_mut(&self.source) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    g.per_source.remove(&self.source);
                }
            }
        }
    }
}

/// Pause of the accept loop after `errors` consecutive `accept` failures: the poll period,
/// doubled at each failure up to [`ACCEPT_BACKOFF_MAX`].
fn accept_backoff(errors: u32) -> Duration {
    let factor = 1u32 << errors.saturating_sub(1).min(5);
    POLL.saturating_mul(factor).min(ACCEPT_BACKOFF_MAX)
}

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

/// Binds both ports and starts serving, sealed, with the default bounds
/// ([`Limits::DEVICE`], [`Limits::ADMIN`]).
///
/// # Errors
/// [`ServerError::Config`] if both ports are the same, [`ServerError::Io`], header errors.
pub fn start(config: Config) -> Result<Running, ServerError> {
    start_with_limits(config, Limits::DEVICE, Limits::ADMIN)
}

/// Binds both ports and starts serving, sealed, with the given bounds.
///
/// # Errors
/// [`ServerError::Config`] if both ports are the same or a ceiling is zero,
/// [`ServerError::Io`], header errors.
pub fn start_with_limits(
    config: Config,
    device_limits: Limits,
    admin_limits: Limits,
) -> Result<Running, ServerError> {
    for l in [device_limits, admin_limits] {
        if l.max_connections == 0 || l.max_per_source == 0 {
            return Err(ServerError::Config("a connection ceiling cannot be zero"));
        }
    }
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
        let gate = Gate::new(device_limits);
        threads.push(std::thread::spawn(move || {
            accept_loop(&device, &shared, &gate, move |sh, tcp| {
                device_connection(sh, &tls, device_limits, tcp)
            });
        }));
    }
    {
        let shared = Arc::clone(&shared);
        let tls = config.admin_tls;
        let gate = Gate::new(admin_limits);
        threads.push(std::thread::spawn(move || {
            accept_loop(&admin, &shared, &gate, move |sh, tcp| {
                admin_connection(sh, &tls, admin_limits, tcp)
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

fn accept_loop<F>(listener: &TcpListener, shared: &Arc<Shared>, gate: &Arc<Gate>, handler: F)
where
    F: Fn(&Arc<Shared>, TcpStream) -> Result<(), ServerError> + Send + Sync + Clone + 'static,
{
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    let mut errors: u32 = 0;
    while !shared.stop.load(Ordering::SeqCst) {
        let (tcp, peer) = match listener.accept() {
            Ok(x) => {
                errors = 0;
                x
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(POLL);
                continue;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            // EMFILE, ENFILE, ENOBUFS…: the condition lasts; back off instead of spinning.
            Err(_) => {
                errors = errors.saturating_add(1);
                std::thread::sleep(accept_backoff(errors));
                continue;
            }
        };
        // Beyond a ceiling: closed at once, before any TLS work, without a thread.
        let Some(slot) = gate.enter(peer.ip()) else {
            let _ = tcp.shutdown(Shutdown::Both);
            continue;
        };
        if tcp.set_nonblocking(false).is_err() {
            continue;
        }
        let shared = Arc::clone(shared);
        let handler = handler.clone();
        let spawned = std::thread::Builder::new().spawn(move || {
            let _slot = slot;
            let _ = handler(&shared, tcp);
        });
        if spawned.is_err() {
            // No thread left: the connection (and its slot) went with the closure.
            errors = errors.saturating_add(1);
            std::thread::sleep(accept_backoff(errors));
        }
    }
}

type Tls = StreamOwned<ServerConnection, TcpStream>;

/// TLS handshake, ALPN check, exporter (§ 11.3). The handshake must end before `deadline`,
/// however slowly the peer sends its bytes.
fn handshake(
    tls: &Arc<ServerConfig>,
    tcp: TcpStream,
    deadline: Instant,
) -> Result<(Tls, IpAddr, [u8; EXPORTER_LEN]), ServerError> {
    tcp.set_nodelay(true)?;
    let ip = tcp.peer_addr()?.ip();
    let mut s = StreamOwned::new(ServerConnection::new(Arc::clone(tls))?, tcp);
    while s.conn.is_handshaking() {
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(ServerError::Protocol)?;
        s.sock.set_read_timeout(Some(left))?;
        s.sock.set_write_timeout(Some(left))?;
        s.conn.complete_io(&mut s.sock)?;
    }
    if s.conn.alpn_protocol() != Some(ALPN) {
        return Err(ServerError::Protocol);
    }
    let mut exporter = [0u8; EXPORTER_LEN];
    s.conn
        .export_keying_material(&mut exporter, EXPORTER_LABEL, Some(&[]))?;
    s.sock.set_read_timeout(Some(POLL))?;
    s.sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    Ok((s, ip, exporter))
}

/// Reads what is available; `Ok(false)` when the peer closed.
fn fill(s: &mut Tls, fb: &mut FrameBuffer) -> Result<bool, ServerError> {
    let mut buf = [0u8; 16 * 1024];
    match s.read(&mut buf) {
        Ok(0) => Ok(false),
        Ok(n) => {
            fb.extend(&buf[..n]);
            buf[..n].zeroize();
            Ok(true)
        }
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(true),
        Err(e) => Err(e.into()),
    }
}

fn device_connection(
    shared: &Arc<Shared>,
    tls: &Arc<ServerConfig>,
    limits: Limits,
    tcp: TcpStream,
) -> Result<(), ServerError> {
    let accepted = Instant::now();
    let (mut s, ip, exporter) = handshake(tls, tcp, accepted + limits.handshake_timeout)?;
    let mut session = Session::new(ip, exporter);
    let mut fb = FrameBuffer::default();
    let mut last = Instant::now();
    loop {
        if shared.stop.load(Ordering::SeqCst) || last.elapsed() > IDLE_TIMEOUT {
            return Ok(());
        }
        // Not authenticated in time: the place goes to another device.
        if session.device().is_none() && accepted.elapsed() > limits.auth_timeout {
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
            let share = Zeroizing::new(proto::read_blob(&m.body, 64 * 1024)?);
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
    limits: Limits,
    tcp: TcpStream,
) -> Result<(), ServerError> {
    let peer_ip = tcp.peer_addr().map(|a| a.ip()).ok();
    let deadline = Instant::now() + limits.handshake_timeout;
    let (mut s, ip, _) = match handshake(tls, tcp, deadline) {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn limits(total: usize, per: usize) -> Limits {
        Limits {
            max_connections: total,
            max_per_source: per,
            ..Limits::DEVICE
        }
    }

    #[test]
    fn gate_bounds_per_source_and_in_total() {
        let gate = Gate::new(limits(3, 2));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let c: IpAddr = "192.0.2.3".parse().unwrap();
        let a1 = gate.enter(a).unwrap();
        let _a2 = gate.enter(a).unwrap();
        assert!(gate.enter(a).is_none(), "third from the same source");
        let _b1 = gate.enter(b).unwrap();
        assert!(gate.enter(c).is_none(), "global ceiling");
        assert_eq!(gate.open_connections(), 3);
        drop(a1);
        assert_eq!(gate.open_connections(), 2);
        let _c1 = gate.enter(c).unwrap();
        assert!(gate.enter(a).is_none());
    }

    #[test]
    fn slots_are_freed_and_sources_forgotten() {
        let gate = Gate::new(limits(8, 1));
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        for _ in 0..100 {
            let s = gate.enter(ip).unwrap();
            assert!(gate.enter(ip).is_none());
            drop(s);
        }
        assert_eq!(gate.open_connections(), 0);
        assert!(gate.open.lock().unwrap().per_source.is_empty());
    }

    #[test]
    fn ipv6_counts_per_slash_64_and_mapped_ipv4_as_ipv4() {
        let gate = Gate::new(limits(8, 1));
        let _x = gate.enter("2001:db8:1:2::1".parse().unwrap()).unwrap();
        assert!(
            gate.enter("2001:db8:1:2:ffff::9".parse().unwrap())
                .is_none(),
            "same /64"
        );
        let _y = gate.enter("2001:db8:1:3::1".parse().unwrap()).unwrap();
        let _z = gate.enter("192.0.2.7".parse().unwrap()).unwrap();
        assert!(gate.enter("::ffff:192.0.2.7".parse().unwrap()).is_none());
    }

    #[test]
    fn accept_backoff_grows_then_caps() {
        assert_eq!(accept_backoff(1), POLL);
        assert_eq!(accept_backoff(2), POLL * 2);
        assert_eq!(accept_backoff(3), POLL * 4);
        assert!(accept_backoff(5) > accept_backoff(4));
        assert_eq!(accept_backoff(100), ACCEPT_BACKOFF_MAX);
        assert_eq!(accept_backoff(u32::MAX), ACCEPT_BACKOFF_MAX);
    }
}
