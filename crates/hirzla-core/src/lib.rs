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
//! - [`origin`]: web origins of the browser operations (version 2).

#![forbid(unsafe_code)]

pub mod auth;
pub mod client;
pub mod daemon;
pub mod events;
pub mod generator;
pub mod origin;
pub mod proto;
pub mod service;
pub mod transport;
