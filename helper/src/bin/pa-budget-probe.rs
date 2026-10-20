//! Test-only probe, built with `--features budget-probe`: hardens itself like
//! the helper, loads and decrypts the vault under the given root with a fixed
//! test key, and prints its locked-memory figures. Never shipped.

use std::path::PathBuf;
use std::process::ExitCode;

use pa_helper::app::{codes, CodesRequest, KeyProvider, LockState};
use pa_helper::error::Result;
use pa_helper::sys::harden;
use pa_helper::vault::{ProtonIdbVault, VaultSource};
use zeroize::Zeroizing;

/// Matches the root key of the budget test fixture; not a real key.
const TEST_ONLY_ROOT_KEY: [u8; 32] = [0x11; 32];

struct TestOnlyKeys;

impl KeyProvider for TestOnlyKeys {
    fn lock_state(&self, _key_id: &str) -> Result<LockState> {
        Ok(LockState::Unlocked)
    }

    fn root_key(&self, _key_id: &str) -> Result<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(TEST_ONLY_ROOT_KEY))
    }
}

/// A `kB` figure from `/proc/self/status`, 0 if missing.
fn status_kb(name: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix(name))
                .and_then(|v| v.trim().strip_suffix("kB"))
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0)
}

struct Baseline {
    lck: u64,
    peak: u64,
}

fn report(result: &str, base: &Baseline) {
    println!(
        "result={result} base_lck_kb={} base_peak_kb={} lck_kb={} peak_kb={} hwm_kb={}",
        base.lck,
        base.peak,
        status_kb("VmLck:"),
        status_kb("VmPeak:"),
        status_kb("VmHWM:")
    );
}

fn main() -> ExitCode {
    let hardened = harden();
    let base = Baseline {
        lck: status_kb("VmLck:"),
        peak: status_kb("VmPeak:"),
    };
    if let Err(code) = hardened {
        report(code.as_str(), &base);
        return ExitCode::from(2);
    }
    let mut args = std::env::args_os().skip(1);
    let (Some(root), None) = (args.next(), args.next()) else {
        report("INVALID_ARGUMENT", &base);
        return ExitCode::from(2);
    };
    let vault = ProtonIdbVault::new(PathBuf::from(root));
    let loaded = vault.snapshot().and_then(|snapshot| {
        snapshot.key_ref()?;
        snapshot.for_each_item(&mut |_| Ok(()))
    });
    let req = CodesRequest {
        only: None,
        allow_prompt: false,
        unix: 1_700_000_000,
    };
    match loaded.and_then(|_| codes(&vault, &TestOnlyKeys, &req)) {
        Ok(views) => {
            let with_code = views.iter().filter(|v| v.code.is_some()).count();
            report(
                &format!("OK items={} codes={with_code}", views.len()),
                &base,
            );
            ExitCode::SUCCESS
        }
        Err(code) => {
            report(code.as_str(), &base);
            ExitCode::from(1)
        }
    }
}
