//! `hirzlad` opens no outbound connection (`CLAUDE.md` rule 7, `PROMPTS.md` step 11).
//!
//! Method: the real binary runs under `strace -f`, which records every `connect`, `sendto`,
//! `sendmsg`, `sendmmsg` and `accept` system call of the process and all its threads. The test drives a
//! full life cycle through it (init, start sealed, unseal by quorum, accounts, two postes that
//! share a locker over TLS, key log queries, mailbox, graceful stop), then fails if the trace
//! holds any `connect` (TCP, UDP or local socket: DNS, NSS, telemetry, a CDN would all show
//! there) or any datagram sent to an explicit address. The server only accepts connections;
//! its answers go through `write`/`sendto` on accepted sockets, without an address.
//!
//! A positive control runs first: the same detector applied to a process that does connect
//! must report it, so the test cannot pass because the tracing silently failed.
//!
//! `strace` is a test-time tool, never a dependency of the binary. Linux CI installs it and
//! sets `HIRZLA_REQUIRE_STRACE=1`, which turns a missing `strace` (or a kernel that refuses
//! `ptrace`) into a failure; elsewhere the test is skipped with a message. An isolated network
//! namespace (`unshare -rn`) was the alternative: it blocks connections instead of observing
//! them, needs unprivileged user namespaces (restricted by AppArmor on Ubuntu 24.04 runners),
//! and a blocked attempt is not visible unless the binary reports it (ADR 0028, point 8).

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Pki, R, SERVER_NAME};
use hirzla_access::Role;
use hirzla_server::client::{AdminClient, Client, Identity};
use hirzla_sync::testing::TestMember;
use hirzla_sync::AccessAuthorizer;
use hirzla_vault::secret::{Field, FieldValue, SecretEdit, SecretType};

const TRACED: &str = "trace=connect,sendto,sendmsg,sendmmsg,accept,accept4";

fn strace_usable() -> bool {
    Command::new("strace")
        .args(["-f", "-qq", "-o", "/dev/null", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn traced(log: &Path, program: &str, args: &[&str]) -> Command {
    let mut c = Command::new("strace");
    c.args(["-f", "-qq", "-e", TRACED, "-o"])
        .arg(log)
        .arg(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    c
}

/// Lines of a trace that are outbound connections or addressed datagrams.
fn outbound(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter(|l| {
            l.contains("connect(")
                || ((l.contains("sendto(") || l.contains("sendmsg(") || l.contains("sendmmsg("))
                    && (l.contains("sa_family=AF_INET") || l.contains("sa_family=AF_UNIX")))
        })
        .map(str::to_owned)
        .collect()
}

fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn wait_for(addr: SocketAddr, child: &mut Child) {
    let start = Instant::now();
    while TcpStream::connect(addr).is_err() {
        assert!(child.try_wait().unwrap().is_none(), "hirzlad exited early");
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "hirzlad did not listen"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn edit(password: &str) -> SecretEdit {
    SecretEdit {
        set: vec![
            (Field::Title, FieldValue::text("Routeur")),
            (Field::Password, FieldValue::text(password)),
        ],
        ..SecretEdit::default()
    }
}

#[test]
fn no_outbound_connection() {
    if !strace_usable() {
        assert!(
            std::env::var("HIRZLA_REQUIRE_STRACE").as_deref() != Ok("1"),
            "strace is required (HIRZLA_REQUIRE_STRACE) but unusable"
        );
        eprintln!("skipped: strace unavailable or ptrace refused");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();

    // Positive control: the detector sees a process that connects.
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let control_log = tmp.path().join("control.trace");
    let script = format!(
        "exec 3<>/dev/tcp/127.0.0.1/{}",
        target.local_addr().unwrap().port()
    );
    let st = traced(&control_log, "bash", &["-c", &script])
        .status()
        .unwrap();
    assert!(st.success());
    assert!(
        !outbound(&control_log).is_empty(),
        "the detector missed a real connection"
    );

    let bin = env!("CARGO_BIN_EXE_hirzlad");
    let pki = Pki::new(tmp.path());
    let data = tmp.path().join("data");
    let shares: PathBuf = tmp.path().join("shares");

    let init_log = tmp.path().join("init.trace");
    let st = traced(
        &init_log,
        bin,
        &[
            "init",
            "--data",
            data.to_str().unwrap(),
            "--threshold",
            "2",
            "--shares",
            "3",
            "--shares-out",
            shares.to_str().unwrap(),
        ],
    )
    .status()
    .unwrap();
    assert!(st.success());

    let listen = free_addr();
    let admin_listen = free_addr();
    let serve_log = tmp.path().join("serve.trace");
    let mut child = traced(
        &serve_log,
        bin,
        &[
            "serve",
            "--data",
            data.to_str().unwrap(),
            "--listen",
            &listen.to_string(),
            "--cert",
            pki.cert.to_str().unwrap(),
            "--key",
            pki.key.to_str().unwrap(),
            "--admin-listen",
            &admin_listen.to_string(),
            "--admin-cert",
            pki.cert.to_str().unwrap(),
            "--admin-key",
            pki.key.to_str().unwrap(),
            "--admin-client-ca",
            pki.admin_ca.to_str().unwrap(),
        ],
    )
    .spawn()
    .unwrap();
    wait_for(admin_listen, &mut child);

    // Unseal by quorum, accounts.
    let admin_tls = pki.admin_tls();
    let mut admin = AdminClient::connect(admin_listen, SERVER_NAME, &admin_tls).unwrap();
    assert!(admin.status().unwrap().sealed);
    for i in [1, 3] {
        let share = std::fs::read(shares.join(format!("share-{i}.bin"))).unwrap();
        admin.unseal(&share).unwrap();
    }
    assert!(!admin.status().unwrap().sealed);
    let alice = TestMember::new();
    let bob = TestMember::new();
    admin.create_account(&alice.keys).unwrap();
    admin.create_account(&bob.keys).unwrap();

    // Two postes share a locker over TLS.
    let tls = pki.device_tls();
    let a = alice.device();
    let b = bob.device();
    let connect = |d| {
        Client::connect(
            listen,
            SERVER_NAME,
            &tls,
            None,
            &Identity::Device {
                device: d,
                present_cert: true,
            },
        )
        .unwrap()
    };
    let mut bc = connect(&b);
    let mut ac = connect(&a);
    let mut ra = R::create_locker(Arc::clone(&a), AccessAuthorizer, false, "Équipe").unwrap();
    let devices = ac.member_keys(&bob.id()).unwrap().devices;
    ra.grant(bob.keys.clone(), Role::Editor, devices, None)
        .unwrap();
    let (sid, _) = ra
        .put_secret(None, SecretType::Password, edit("pw"))
        .unwrap();
    let mut ca = 0;
    ac.sync(&mut ra, &mut ca).unwrap();
    let mut rb = R::join(Arc::clone(&b), AccessAuthorizer, ra.locker_id(), None);
    let mut cb = 0;
    bc.sync(&mut rb, &mut cb).unwrap();
    assert!(rb.secret(&sid).is_some());
    ac.mailbox_put(&b.device_id(), b"blob").unwrap();
    assert_eq!(bc.mailbox_get(&b.device_id()).unwrap(), b"blob");
    admin.checkpoint().unwrap();
    ac.bye().unwrap();
    bc.bye().unwrap();

    // Graceful stop, then read the traces.
    admin.shutdown().unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > Duration::from_secs(30) {
            child.kill().ok();
            panic!("hirzlad did not stop");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let mut found = outbound(&init_log);
    found.extend(outbound(&serve_log));
    assert!(
        found.is_empty(),
        "hirzlad attempted outbound connections:\n{}",
        found.join("\n")
    );
    // The trace did cover the serving threads: the connections they accepted are there.
    let trace = std::fs::read_to_string(&serve_log).unwrap();
    assert!(
        trace
            .lines()
            .filter(|l| l.contains("accept4(") && !l.contains("EAGAIN"))
            .count()
            >= 3,
        "the trace does not cover the server"
    );
}
