use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::error::{ErrorCode, Result};

/// The watchdog thread only sleeps and then writes one short line; under
/// `mlockall` every stack counts against the locked-memory budget.
const WATCHDOG_STACK: usize = 64 * 1024;

/// Runs an action once a duration has passed, unless cancelled first.
pub struct Watchdog {
    cancelled: Arc<Mutex<bool>>,
}

impl Watchdog {
    /// Starts a thread that calls `on_expiry` after `after`.
    ///
    /// The expiry check and `on_expiry` run under the same lock as
    /// [`Watchdog::cancel`], so an action that ends the process never
    /// overlaps output written after a successful cancel.
    pub fn arm(after: Duration, on_expiry: impl FnOnce() + Send + 'static) -> Result<Self> {
        let cancelled = Arc::new(Mutex::new(false));
        let flag = Arc::clone(&cancelled);
        thread::Builder::new()
            .name("watchdog".into())
            .stack_size(WATCHDOG_STACK)
            .spawn(move || {
                thread::sleep(after);
                let cancelled = flag.lock().unwrap_or_else(|e| e.into_inner());
                if !*cancelled {
                    on_expiry();
                }
            })
            .map_err(|_| ErrorCode::Internal)?;
        Ok(Self { cancelled })
    }

    /// Once this returns, `on_expiry` has not run and never will. If it is
    /// already running, this blocks until it finishes.
    pub fn cancel(self) {
        *self.cancelled.lock().unwrap_or_else(|e| e.into_inner()) = true;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Instant;

    use super::*;

    #[test]
    fn fires_after_the_duration() {
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        let _dog = Watchdog::arm(Duration::from_millis(100), move || {
            tx.send(Instant::now()).unwrap();
        })
        .unwrap();
        let fired = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(fired - start >= Duration::from_millis(100));
    }

    #[test]
    fn cancel_prevents_firing() {
        let (tx, rx) = mpsc::channel();
        let dog = Watchdog::arm(Duration::from_millis(100), move || {
            tx.send(()).unwrap();
        })
        .unwrap();
        dog.cancel();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(400)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        );
    }

    #[test]
    fn cancel_waits_for_a_running_action() {
        let (tx, rx) = mpsc::channel();
        let dog = Watchdog::arm(Duration::from_millis(10), move || {
            tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(300));
        })
        .unwrap();
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let start = Instant::now();
        dog.cancel();
        assert!(start.elapsed() >= Duration::from_millis(200));
    }
}
