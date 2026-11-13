use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Wall clock in unix seconds with an adjustable offset so tests can move
/// time forward (request expiry) without sleeping.
#[derive(Debug, Default)]
pub struct Clock {
    offset_s: AtomicI64,
}

impl Clock {
    pub fn now(&self) -> i64 {
        let real = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        real + self.offset_s.load(Ordering::Relaxed)
    }

    /// Shift the clock forward by `secs` (test hook; never called in production paths).
    pub fn advance(&self, secs: i64) {
        self.offset_s.fetch_add(secs, Ordering::Relaxed);
    }
}
