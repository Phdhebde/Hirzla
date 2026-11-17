//! The Hirzla core: the only process that ever holds keys or plaintext secrets.
//!
//! The desktop UI, the browser extension and the CLI talk to it over an
//! authenticated local channel and only ever receive the secret they asked for.
//! See ADR 0007, ADR 0015 and `docs/api-locale.md`.
//!
//! - [`proto`]: messages and framing of the local API;
//! - [`transport`] and [`auth`]: the channel and the authentication of both ends;
//! - [`service`]: what the core does with a request (vault, lock, automatic lock);
//! - [`daemon`]: the `hirzla-core` process;
//! - [`client`]: the client side, used by `hirzla` and `hirzla-native-host`;
//! - [`origin`]: web origins of the browser operations (version 2);
//! - [`agent`]: the machine member of a Hornn agent (`docs/integration-hornn.md`);
//! - [`server_mode`]: the client of `hirzlad` and the local API version 4 (ADR 0032);
//! - [`selfmode`]: the Self-mode operations (version 5): settings, history, recovery, import;
//! - [`connections`]: SSH and RDP connections (version 6, ADR 0067);
//! - [`methods`]: hardware unlock methods (version 12, ADR 0075): Windows Hello, Touch ID,
//!   FIDO2;
//! - [`locker_export`]: encrypted export and import of a locker (version 9, ADR 0077);
//! - [`codesign`]: the signature of the core's clients (ADR 0042);
//! - [`release`]: documents signed by the publisher key, client manifest and offline update
//!   package (ADR 0042, 0043).

#![forbid(unsafe_code)]

pub mod agent;
pub mod auth;
pub mod client;
pub mod codesign;
pub mod connections;
pub mod daemon;
pub mod events;
pub mod generator;
pub mod locker_export;
pub mod methods;
pub mod origin;
pub mod proto;
pub mod release;
pub mod selfmode;
pub mod server_mode;
pub mod service;
pub mod transport;
