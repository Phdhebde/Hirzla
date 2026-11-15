//! `hirzlad` — the blind server. It relays, orders and stores encrypted operations,
//! serves the key directory and keeps the audit log. It never holds a secret key
//! that could decrypt a user secret.
//!
//! ```text
//! hirzlad init  --data DIR --threshold T --shares N --shares-out DIR
//! hirzlad invitation --data DIR --address hirzla://HOST[:PORT] --ca PEM
//! hirzlad serve --data DIR --listen ADDR --cert PEM --key PEM
//!               --admin-listen ADDR --admin-cert PEM --admin-key PEM --admin-client-ca PEM
//!               [--max-connections N] [--max-per-source N] [--auth-timeout SECONDS]
//!               [--admin-max-connections N] [--admin-max-per-source N]
//! hirzlad admin etat|desceller|creer-compte|point-de-controle|arreter OPTIONS
//! ```
//!
//! One self-contained binary: no runtime dependency, no configuration service, no outbound
//! connection. `serve` starts sealed; custodians hand their shares over the administration
//! port until the quorum unseals the root key.

#![forbid(unsafe_code)]

mod admin;

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use hirzla_server::net::{self, Config, Limits};
use hirzla_server::seal::ShamirSeal;
use hirzla_server::store::{SealHeader, Store};
use hirzla_server::{tls, ServerError};
use hirzla_sync::text::{fingerprint, Invitation};

const USAGE: &str = "usage:
  hirzlad init  --data DIR --threshold T --shares N --shares-out DIR
  hirzlad invitation --data DIR --address hirzla://HOST[:PORT] --ca PEM
  hirzlad serve --data DIR --listen ADDR --cert PEM --key PEM \\
                --admin-listen ADDR --admin-cert PEM --admin-key PEM --admin-client-ca PEM \\
                [--max-connections N] [--max-per-source N] [--auth-timeout SECONDS] \\
                [--admin-max-connections N] [--admin-max-per-source N]
  hirzlad admin etat|desceller|creer-compte|point-de-controle|arreter …  (hirzlad admin aide)
  hirzlad --version";

fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(char::from(D[usize::from(x >> 4)]));
        s.push(char::from(D[usize::from(x & 15)]));
    }
    s
}

fn options(args: &[String]) -> Result<BTreeMap<String, String>, ServerError> {
    let mut m = BTreeMap::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let Some(name) = k.strip_prefix("--") else {
            return Err(ServerError::Config("unexpected argument"));
        };
        let v = it.next().ok_or(ServerError::Config("missing value"))?;
        if m.insert(name.to_owned(), v.clone()).is_some() {
            return Err(ServerError::Config("repeated option"));
        }
    }
    Ok(m)
}

fn get<'a>(o: &'a BTreeMap<String, String>, k: &'static str) -> Result<&'a str, ServerError> {
    o.get(k)
        .map(String::as_str)
        .ok_or(ServerError::Config("missing option"))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ServerError> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn init(o: &BTreeMap<String, String>) -> Result<(), ServerError> {
    let dir = PathBuf::from(get(o, "data")?);
    let out = PathBuf::from(get(o, "shares-out")?);
    let threshold: u8 = get(o, "threshold")?
        .parse()
        .map_err(|_| ServerError::Config("threshold"))?;
    let count: u8 = get(o, "shares")?
        .parse()
        .map_err(|_| ServerError::Config("shares"))?;
    let setup = ShamirSeal::generate(threshold, count)?;
    let header = Store::init(&dir, &setup.seal, Some(setup.dealer.clone()))?;
    std::fs::create_dir_all(&out)?;
    for s in &setup.shares {
        write_private(&out.join(format!("share-{}.bin", s.index())), s.as_bytes())?;
    }
    report(&format!(
        "server_id {}\nserver_key_fingerprint {}\nfingerprint {}\nshares {count}, threshold {threshold}: hand one to each custodian, then delete {}",
        hex(&header.server_id),
        hex(&hirzla_crypto::util::sha384(header.server_key.as_bytes())),
        fingerprint(header.server_key.as_bytes()),
        out.display()
    ));
    Ok(())
}

/// Writes the invitation link (`sync-protocol.md` § 11.10, ADR 0046) on standard output:
/// the address, the site CA and the fingerprint of the server key, read from the clear
/// header of the data directory without unsealing it.
fn invitation(o: &BTreeMap<String, String>) -> Result<(), ServerError> {
    let header = SealHeader::read(Path::new(get(o, "data")?))?;
    let address = get(o, "address")?;
    let ok = address
        .strip_prefix("hirzla://")
        .is_some_and(|h| !h.is_empty() && !h.contains(['/', '@', '?', '#']));
    if !ok {
        return Err(ServerError::Config("the address is hirzla://HOST[:PORT]"));
    }
    let ca = Path::new(get(o, "ca")?);
    tls::load_certs(ca)?;
    let roots = std::fs::read(ca)?;
    let link = Invitation {
        address: address.to_owned(),
        roots,
        fingerprint: fingerprint(header.server_key.as_bytes()),
    }
    .encode()
    .map_err(|_| ServerError::Config("the CA is too large for a link"))?;
    writeln!(std::io::stdout().lock(), "{link}")?;
    Ok(())
}

fn addr(o: &BTreeMap<String, String>, k: &'static str) -> Result<SocketAddr, ServerError> {
    // Addresses only: a name would need a resolver, that is an outbound request.
    get(o, k)?
        .parse()
        .map_err(|_| ServerError::Config("an address is IP:port, never a name"))
}

/// Options of `serve`. Any other is refused: a mistyped bound must not be ignored.
const SERVE_OPTIONS: &[&str] = &[
    "data",
    "listen",
    "cert",
    "key",
    "admin-listen",
    "admin-cert",
    "admin-key",
    "admin-client-ca",
    "max-connections",
    "max-per-source",
    "auth-timeout",
    "admin-max-connections",
    "admin-max-per-source",
];

/// Highest connection ceiling accepted on the command line: one thread per connection.
const MAX_CEILING: usize = 65_536;

/// Accepted deadline to authenticate, in seconds: at least the TLS handshake deadline, at
/// most an hour.
const AUTH_TIMEOUT_SECS: RangeInclusive<u64> = 10..=3600;

fn ceiling(o: &BTreeMap<String, String>, k: &str) -> Result<Option<usize>, ServerError> {
    let Some(v) = o.get(k) else {
        return Ok(None);
    };
    let n: usize = v
        .parse()
        .map_err(|_| ServerError::Config("a connection ceiling is a whole number"))?;
    if n == 0 {
        return Err(ServerError::Config("a connection ceiling cannot be zero"));
    }
    if n > MAX_CEILING {
        return Err(ServerError::Config("a connection ceiling is at most 65536"));
    }
    Ok(Some(n))
}

/// Bounds of the device and administration ports (ADR 0051): the defaults
/// ([`Limits::DEVICE`], [`Limits::ADMIN`]), changed by the options given.
fn limits(o: &BTreeMap<String, String>) -> Result<(Limits, Limits), ServerError> {
    let mut device = Limits::DEVICE;
    let mut admin = Limits::ADMIN;
    if let Some(n) = ceiling(o, "max-connections")? {
        device.max_connections = n;
    }
    if let Some(n) = ceiling(o, "max-per-source")? {
        device.max_per_source = n;
    }
    if let Some(n) = ceiling(o, "admin-max-connections")? {
        admin.max_connections = n;
    }
    if let Some(n) = ceiling(o, "admin-max-per-source")? {
        admin.max_per_source = n;
    }
    if let Some(v) = o.get("auth-timeout") {
        let secs: u64 = v
            .parse()
            .map_err(|_| ServerError::Config("the authentication deadline is in seconds"))?;
        if secs == 0 {
            return Err(ServerError::Config("a connection deadline cannot be zero"));
        }
        if !AUTH_TIMEOUT_SECS.contains(&secs) {
            return Err(ServerError::Config(
                "the authentication deadline is 10 to 3600 seconds",
            ));
        }
        device.auth_timeout = Duration::from_secs(secs);
    }
    for l in [&device, &admin] {
        if l.max_per_source > l.max_connections {
            return Err(ServerError::Config(
                "the per-source ceiling cannot exceed the total ceiling",
            ));
        }
        l.validate()?;
    }
    Ok((device, admin))
}

fn serve(o: &BTreeMap<String, String>) -> Result<(), ServerError> {
    if o.keys().any(|k| !SERVE_OPTIONS.contains(&k.as_str())) {
        return Err(ServerError::Config("unknown option"));
    }
    // Checked before reading any key or binding any port.
    let (device_limits, admin_limits) = limits(o)?;
    let device_tls = tls::device_server_config(
        tls::load_certs(Path::new(get(o, "cert")?))?,
        tls::load_key(Path::new(get(o, "key")?))?,
    )?;
    let admin_tls = tls::admin_server_config(
        tls::load_certs(Path::new(get(o, "admin-cert")?))?,
        tls::load_key(Path::new(get(o, "admin-key")?))?,
        tls::roots(tls::load_certs(Path::new(get(o, "admin-client-ca")?))?)?,
    )?;
    let running = net::start_with_limits(
        Config {
            data_dir: PathBuf::from(get(o, "data")?),
            listen: addr(o, "listen")?,
            admin_listen: addr(o, "admin-listen")?,
            tls: device_tls,
            admin_tls,
        },
        device_limits,
        admin_limits,
    )?;
    report(&format!(
        "listening {} admin {} (sealed)",
        running.addr, running.admin_addr
    ));
    report(&format!(
        "bounds: devices {} connections, {} per source, authentication within {} s; administration {} connections, {} per source",
        device_limits.max_connections,
        device_limits.max_per_source,
        device_limits.auth_timeout.as_secs(),
        admin_limits.max_connections,
        admin_limits.max_per_source
    ));
    running.wait();
    Ok(())
}

/// Operator output: to standard error, so that standard output stays free for scripting.
fn report(s: &str) {
    eprintln!("hirzlad: {s}");
}

/// Output of the administration tool, to standard error like the rest of `hirzlad`.
fn report_admin(s: &str) {
    eprintln!("{s}");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("--version") => {
            report(env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("init") => options(&args[1..]).and_then(|o| init(&o)),
        Some("invitation") => options(&args[1..]).and_then(|o| invitation(&o)),
        Some("serve") => options(&args[1..]).and_then(|o| serve(&o)),
        // Administration tool (ADR 0053): French messages, its own exit codes.
        Some("admin") => {
            return match args.get(1).map(String::as_str) {
                Some("aide" | "--help" | "-h") | None => {
                    report_admin(admin::USAGE);
                    ExitCode::SUCCESS
                }
                _ => match admin::run(&args[1..]) {
                    Ok(text) => {
                        report_admin(&text);
                        ExitCode::SUCCESS
                    }
                    Err(msg) => {
                        report_admin(&format!("erreur : {msg}"));
                        ExitCode::from(1)
                    }
                },
            };
        }
        _ => Err(ServerError::Config("unknown command")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report(&format!("{e}\n{USAGE}"));
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn opts(args: &[&str]) -> BTreeMap<String, String> {
        let v: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        options(&v).unwrap()
    }

    #[test]
    fn default_bounds_without_options() {
        let (device, admin) = limits(&opts(&[])).unwrap();
        assert_eq!(device, Limits::DEVICE);
        assert_eq!(admin, Limits::ADMIN);
    }

    #[test]
    fn options_set_the_bounds() {
        let (device, admin) = limits(&opts(&[
            "--max-connections",
            "4096",
            "--max-per-source",
            "256",
            "--auth-timeout",
            "120",
            "--admin-max-connections",
            "8",
            "--admin-max-per-source",
            "2",
        ]))
        .unwrap();
        assert_eq!(device.max_connections, 4096);
        assert_eq!(device.max_per_source, 256);
        assert_eq!(device.auth_timeout, Duration::from_secs(120));
        assert_eq!(device.handshake_timeout, Limits::DEVICE.handshake_timeout);
        assert_eq!(admin.max_connections, 8);
        assert_eq!(admin.max_per_source, 2);
        assert_eq!(admin.auth_timeout, Limits::ADMIN.auth_timeout);
    }

    #[test]
    fn invalid_bounds_are_configuration_errors() {
        for bad in [
            &["--max-connections", "0"][..],
            &["--max-per-source", "0"],
            &["--admin-max-connections", "0"],
            &["--admin-max-per-source", "0"],
            &["--auth-timeout", "0"],
            &["--max-connections", "-1"],
            &["--max-connections", "ten"],
            &["--max-connections", " 10"],
            &["--max-connections", "65537"],
            &["--auth-timeout", "9"],
            &["--auth-timeout", "3601"],
            &["--auth-timeout", "1.5"],
            // Above the default total ceiling (1024), or above an explicit one.
            &["--max-per-source", "2048"],
            &["--max-connections", "16", "--max-per-source", "17"],
            &["--admin-max-connections", "2"],
        ] {
            let r = limits(&opts(bad));
            assert!(matches!(r, Err(ServerError::Config(_))), "{bad:?}");
        }
    }

    #[test]
    fn bounds_at_the_edges_are_accepted() {
        let (device, _) = limits(&opts(&[
            "--max-connections",
            "65536",
            "--max-per-source",
            "65536",
            "--auth-timeout",
            "10",
        ]))
        .unwrap();
        assert_eq!(device.max_per_source, 65_536);
        let (device, _) =
            limits(&opts(&["--max-per-source", "1", "--auth-timeout", "3600"])).unwrap();
        assert_eq!(device.max_per_source, 1);
        assert_eq!(device.auth_timeout, Duration::from_secs(3600));
    }
}
