//! `hirzla-core` — the core process. Holds the keys; talks only over the local channel.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    hirzla_core::daemon::main()
}
