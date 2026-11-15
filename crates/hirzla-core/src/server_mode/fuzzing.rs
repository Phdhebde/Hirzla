//! Entry point of the fuzz target `decode_server_annex` (`fuzz/`), behind the `fuzzing`
//! feature: the decoder of the unsealed annex content (`format.md` § 15). Never built in a
//! shipped binary.

use super::ServerMode;

impl ServerMode {
    /// Decodes `content` as the unsealed content of the annex, as [`ServerMode::load`] does
    /// once the annex is unsealed (every stored operation and key log entry validated
    /// again), and tells whether it was accepted. Nothing is kept.
    #[must_use]
    pub fn fuzz_decode_annex(&self, content: &[u8]) -> bool {
        self.decode(content).is_ok()
    }
}
