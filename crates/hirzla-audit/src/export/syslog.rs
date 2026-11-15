//! Syslog: messages in RFC 5424 format, framed by octet counting as RFC 5425 requires for
//! TLS (`docs/evenements.md` § 8.3).
//!
//! The network transport stays outside this crate (ADR 0022): [`SyslogTransport`] receives
//! finished frames. [`WriteTransport`] adapts any [`std::io::Write`], such as a TLS stream
//! opened by the caller to the address the site configured. This crate opens no connection.

use std::io::Write;

use crate::chain::{Checkpoint, Entry};
use crate::event::Severity;
use crate::time::Timestamp;
use crate::Error;

use super::value_text;

/// The SD-ID of Hirzla structured data. `32473` is the example enterprise number of RFC 5612:
/// replace it with Hirzla's own number once assigned by the IANA (ADR 0022).
pub const DEFAULT_SD_ID: &str = "hirzla@32473";

/// Syslog settings of the site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogConfig {
    facility: u8,
    hostname: String,
    app_name: String,
    procid: String,
    sd_id: String,
}

fn printable(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (33..=126).contains(&b))
}

impl SyslogConfig {
    /// Builds a configuration.
    ///
    /// - `facility`: 0 to 23 (13, « log audit », is the usual choice);
    /// - `hostname`: 1 to 255 printable ASCII characters, or `-`;
    /// - `app_name`: 1 to 48; `procid`: 1 to 128, or `-`;
    /// - `sd_id`: `name@number`, 1 to 32 characters, without `=`, space, `]` or `"`.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`].
    pub fn new(
        facility: u8,
        hostname: &str,
        app_name: &str,
        procid: &str,
        sd_id: &str,
    ) -> Result<Self, Error> {
        let sd_ok = printable(sd_id, 32)
            && !sd_id.contains(['=', ']', '"'])
            && sd_id.split_once('@').is_some_and(|(n, num)| {
                !n.is_empty()
                    && !num.is_empty()
                    && num.bytes().all(|b| b.is_ascii_digit())
                    && !n.contains('@')
            });
        if facility > 23
            || !printable(hostname, 255)
            || !printable(app_name, 48)
            || !printable(procid, 128)
            || !sd_ok
        {
            return Err(Error::InvalidConfig);
        }
        Ok(SyslogConfig {
            facility,
            hostname: hostname.to_owned(),
            app_name: app_name.to_owned(),
            procid: procid.to_owned(),
            sd_id: sd_id.to_owned(),
        })
    }

    fn header(&self, severity: u8, time: Timestamp, msgid: &str) -> String {
        let pri = u16::from(self.facility) * 8 + u16::from(severity);
        format!(
            "<{pri}>1 {time} {} {} {} {msgid} ",
            self.hostname, self.app_name, self.procid
        )
    }

    fn structured(&self, params: &[(&str, String)]) -> String {
        let mut sd = format!("[{}", self.sd_id);
        for (name, v) in params {
            sd.push(' ');
            sd.push_str(name);
            sd.push_str("=\"");
            for c in v.chars() {
                if matches!(c, '"' | '\\' | ']') {
                    sd.push('\\');
                }
                sd.push(c);
            }
            sd.push('"');
        }
        sd.push(']');
        sd
    }
}

/// Syslog severity (RFC 5424 § 6.2.1).
#[must_use]
pub fn severity(s: Severity) -> u8 {
    match s {
        Severity::Info => 6,
        Severity::Notice => 5,
        Severity::Warning => 4,
        Severity::Alert => 1,
    }
}

/// One entry as an RFC 5424 message: `MSGID` is the event name, the fields are structured
/// data, there is no free-form `MSG`.
///
/// # Errors
/// [`Error::Encoding`] (a bug).
pub fn entry(config: &SyslogConfig, e: &Entry) -> Result<Vec<u8>, Error> {
    let kind = e.event.kind();
    let mut params = vec![
        ("log", e.log_id.to_string()),
        ("seq", e.seq.to_string()),
        ("hash", e.hash()?.to_string()),
    ];
    for f in e.event.fields() {
        if let Some(text) = value_text(&f.value) {
            params.push((f.name, text));
        }
    }
    let mut msg = config.header(severity(kind.severity()), e.time, kind.name());
    msg.push_str(&config.structured(&params));
    Ok(msg.into_bytes())
}

/// One checkpoint as an RFC 5424 message, signature left out.
#[must_use]
pub fn checkpoint(config: &SyslogConfig, c: &Checkpoint) -> Vec<u8> {
    let params = [
        ("log", c.log_id.to_string()),
        ("keeper", c.keeper.name().to_owned()),
        ("seq", c.seq.to_string()),
        ("head", c.head.to_string()),
        ("signer", c.signer.to_string()),
    ];
    let mut msg = config.header(severity(Severity::Info), c.time, "audit_checkpoint");
    msg.push_str(&config.structured(&params));
    msg.into_bytes()
}

/// RFC 5425 § 4.3 framing: `MSG-LEN SP SYSLOG-MSG`.
#[must_use]
pub fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = format!("{} ", message.len()).into_bytes();
    out.extend_from_slice(message);
    out
}

/// Where framed messages go: a TLS connection to the collector, opened by the caller.
pub trait SyslogTransport {
    /// Sends one framed message.
    ///
    /// # Errors
    /// [`Error::Io`].
    fn send(&mut self, frame: &[u8]) -> Result<(), Error>;
}

/// A transport over any writer, such as an established TLS stream.
#[derive(Debug)]
pub struct WriteTransport<W: Write>(pub W);

impl<W: Write> SyslogTransport for WriteTransport<W> {
    fn send(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.0.write_all(frame)?;
        self.0.flush()?;
        Ok(())
    }
}

/// Formats, frames and sends records.
#[derive(Debug)]
pub struct SyslogExporter<T: SyslogTransport> {
    config: SyslogConfig,
    transport: T,
}

impl<T: SyslogTransport> SyslogExporter<T> {
    /// An exporter over `transport`.
    pub fn new(config: SyslogConfig, transport: T) -> Self {
        SyslogExporter { config, transport }
    }

    /// Sends one entry.
    ///
    /// # Errors
    /// [`Error::Io`].
    pub fn send_entry(&mut self, e: &Entry) -> Result<(), Error> {
        let msg = entry(&self.config, e)?;
        self.transport.send(&frame(&msg))
    }

    /// Sends one checkpoint.
    ///
    /// # Errors
    /// [`Error::Io`].
    pub fn send_checkpoint(&mut self, c: &Checkpoint) -> Result<(), Error> {
        self.transport.send(&frame(&checkpoint(&self.config, c)))
    }

    /// Gives the transport back.
    pub fn into_transport(self) -> T {
        self.transport
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn config_is_validated() {
        assert!(SyslogConfig::new(13, "host", "hirzlad", "-", DEFAULT_SD_ID).is_ok());
        for (f, h, a, p, sd) in [
            (24, "host", "hirzlad", "-", DEFAULT_SD_ID),
            (13, "", "hirzlad", "-", DEFAULT_SD_ID),
            (13, "two words", "hirzlad", "-", DEFAULT_SD_ID),
            (13, "host", &"a".repeat(49), "-", DEFAULT_SD_ID),
            (13, "host", "hirzlad", "-", "hirzla"),
            (13, "host", "hirzlad", "-", "hirzla@abc"),
            (13, "host", "hirzlad", "-", "hir\"zla@1"),
            (13, "hôte", "hirzlad", "-", DEFAULT_SD_ID),
        ] {
            assert_eq!(
                SyslogConfig::new(f, h, a, p, sd),
                Err(Error::InvalidConfig),
                "{h} {a} {sd}"
            );
        }
    }

    #[test]
    fn params_are_escaped_and_framed() {
        let c = SyslogConfig::new(13, "host", "hirzlad", "-", DEFAULT_SD_ID).unwrap();
        assert_eq!(
            c.structured(&[("a", "x\"y]z\\".to_owned())]),
            r#"[hirzla@32473 a="x\"y\]z\\"]"#
        );
        assert_eq!(frame(b"abc"), b"3 abc");
    }
}
