//! Time of an audit entry: milliseconds since the Unix epoch, UTC, from the keeper's clock.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since 1970-01-01T00:00:00Z.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub u64);

/// Largest accepted value: 9999-12-31T23:59:59.999Z, so that every value formats in RFC 3339.
pub const MAX_TIMESTAMP: u64 = 253_402_300_799_999;

impl Timestamp {
    /// The current time of the system clock. A clock before 1970 reads as 0.
    #[must_use]
    pub fn now() -> Self {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(MAX_TIMESTAMP))
            .unwrap_or(0);
        Timestamp(ms.min(MAX_TIMESTAMP))
    }

    /// Whether the value is in the accepted range.
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.0 <= MAX_TIMESTAMP
    }
}

/// RFC 3339 in UTC with milliseconds, e.g. `2026-11-15T08:30:00.000Z`.
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ms = self.0.min(MAX_TIMESTAMP);
        let secs = ms / 1000;
        let days = secs / 86_400;
        let rem = secs % 86_400;
        let (y, m, d) = civil_from_days(days);
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60,
            ms % 1000
        )
    }
}

/// Proleptic Gregorian date of a day count since 1970-01-01 (H. Hinnant's algorithm).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_rfc3339() {
        assert_eq!(Timestamp(0).to_string(), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            Timestamp(951_782_400_123).to_string(),
            "2000-02-29T00:00:00.123Z"
        );
        assert_eq!(
            Timestamp(1_794_729_600_000).to_string(),
            "2026-11-15T08:00:00.000Z"
        );
        assert_eq!(
            Timestamp(MAX_TIMESTAMP).to_string(),
            "9999-12-31T23:59:59.999Z"
        );
    }

    #[test]
    fn now_is_valid() {
        assert!(Timestamp::now().is_valid());
        assert!(!Timestamp(MAX_TIMESTAMP + 1).is_valid());
    }
}
