//! The Hirzla core: the only process that ever holds keys or plaintext secrets.
//!
//! The desktop UI, the browser extension and the CLI talk to it over an
//! authenticated local channel and only ever receive the secret they asked for.
//! See ADR 0007.

#![forbid(unsafe_code)]
