//! Connection bounds of `hirzlad` (ADR 0051, internal review R1): ceilings per source and in
//! total, refused at once before any TLS work; total handshake deadline; deadline to
//! authenticate on the device port.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::panic, missing_docs)]

mod common;

use std::io::{ErrorKind, Read};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use common::{init_data, Pki, Server, SERVER_NAME};
use hirzla_server::net::Limits;
use hirzla_sync::net::client::connect_tls;

/// What a read on a connection says within `wait`.
#[derive(Debug, PartialEq, Eq)]
enum Fate {
    /// Still open: nothing to read, no close.
    Open,
    /// Closed by the server (end of stream or reset).
    Closed,
}

fn fate(s: &mut impl Read, sock: &TcpStream, wait: Duration) -> Fate {
    sock.set_read_timeout(Some(wait)).unwrap();
    let mut b = [0u8; 64];
    match s.read(&mut b) {
        Ok(0) => Fate::Closed,
        Ok(n) => panic!("unexpected {n} bytes"),
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Fate::Open,
        Err(_) => Fate::Closed,
    }
}

fn raw(addr: SocketAddr) -> TcpStream {
    TcpStream::connect(addr).unwrap()
}

fn fate_raw(t: &mut TcpStream, wait: Duration) -> Fate {
    let sock = t.try_clone().unwrap();
    fate(t, &sock, wait)
}

fn server(device: Limits, admin: Limits) -> (tempfile::TempDir, Server) {
    let tmp = tempfile::tempdir().unwrap();
    let data = init_data(&tmp.path().join("data"));
    let pki = Pki::new(tmp.path());
    let s = Server::start_with_limits(pki, &data, device, admin);
    (tmp, s)
}

/// Lets the accept loop (polling every 50 ms) take the pending connections.
fn settle() {
    std::thread::sleep(Duration::from_millis(300));
}

#[test]
fn ceiling_per_source_refuses_at_once_and_frees_on_close() {
    let device = Limits {
        max_connections: 64,
        max_per_source: 2,
        ..Limits::DEVICE
    };
    let (_tmp, s) = server(device, Limits::ADMIN);
    let addr = s.running.addr;
    let mut a = raw(addr);
    let mut b = raw(addr);
    settle();
    let mut c = raw(addr);
    let t = Instant::now();
    assert_eq!(fate_raw(&mut c, Duration::from_secs(5)), Fate::Closed);
    assert!(t.elapsed() < Duration::from_secs(2), "refused at once");
    assert_eq!(fate_raw(&mut a, Duration::from_millis(200)), Fate::Open);
    assert_eq!(fate_raw(&mut b, Duration::from_millis(200)), Fate::Open);
    drop(a);
    settle();
    let mut d = raw(addr);
    settle();
    assert_eq!(fate_raw(&mut d, Duration::from_millis(300)), Fate::Open);
    // The administration port has its own count.
    s.admin().status().unwrap();
}

#[test]
fn global_ceiling_refuses_beyond_it() {
    let device = Limits {
        max_connections: 3,
        max_per_source: 100,
        ..Limits::DEVICE
    };
    let (_tmp, s) = server(device, Limits::ADMIN);
    let addr = s.running.addr;
    let mut held: Vec<TcpStream> = (0..3).map(|_| raw(addr)).collect();
    settle();
    let mut over = raw(addr);
    assert_eq!(fate_raw(&mut over, Duration::from_secs(5)), Fate::Closed);
    for h in &mut held {
        assert_eq!(fate_raw(h, Duration::from_millis(100)), Fate::Open);
    }
}

#[test]
fn silent_handshake_is_cut_at_its_deadline() {
    let fast = Limits {
        handshake_timeout: Duration::from_millis(500),
        ..Limits::DEVICE
    };
    let admin = Limits {
        handshake_timeout: Duration::from_millis(500),
        ..Limits::ADMIN
    };
    let (_tmp, s) = server(fast, admin);
    for addr in [s.running.addr, s.running.admin_addr] {
        let mut t = raw(addr);
        let start = Instant::now();
        assert_eq!(fate_raw(&mut t, Duration::from_secs(5)), Fate::Closed);
        let e = start.elapsed();
        assert!(e >= Duration::from_millis(400), "{e:?}");
        assert!(e < Duration::from_secs(4), "{e:?}");
    }
}

#[test]
fn device_that_does_not_authenticate_is_closed() {
    let device = Limits {
        auth_timeout: Duration::from_millis(600),
        ..Limits::DEVICE
    };
    let (_tmp, s) = server(device, Limits::ADMIN);
    // A complete TLS handshake, then nothing: no `Hello`, no `Auth`.
    let mut tls = connect_tls(s.running.addr, SERVER_NAME, &s.device_tls).unwrap();
    let sock = tls.sock.try_clone().unwrap();
    assert_eq!(
        fate(&mut tls, &sock, Duration::from_millis(200)),
        Fate::Open
    );
    assert_eq!(fate(&mut tls, &sock, Duration::from_secs(5)), Fate::Closed);
}

#[test]
fn zero_ceiling_is_a_configuration_error() {
    let tmp = tempfile::tempdir().unwrap();
    let data = init_data(&tmp.path().join("data"));
    let pki = Pki::new(tmp.path());
    let config = common::config(&pki, &data);
    let zero = Limits {
        max_per_source: 0,
        ..Limits::DEVICE
    };
    assert!(hirzla_server::net::start_with_limits(config, zero, Limits::ADMIN).is_err());
}
