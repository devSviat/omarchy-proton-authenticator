//! Runs without the libtest harness: `harden()` changes process-wide state
//! (dumpable flag, core limit, `mlockall`), so the checks run on the main
//! thread of a process that has nothing else to disturb.
//!
//! `mlockall(MCL_CURRENT)` fails when the mapped size already exceeds
//! `RLIMIT_MEMLOCK`, so this binary must not link SQLite or other test-only
//! libraries. Check the shipped limit with
//! `ulimit -l 8192 && cargo test --locked --test hardening`.

use pa_helper::sys::{harden, is_dumpable};

const BUDGET_KB: u64 = 8192;

fn status_kb(field: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix(field))
        .and_then(|rest| rest.trim().strip_suffix("kB"))
        .map(|v| v.trim().parse().unwrap())
        .unwrap_or_else(|| panic!("{field} missing from /proc/self/status"))
}

/// Soft limit of the `/proc/self/limits` row starting with `name`, `None`
/// when unlimited.
fn soft_limit(name: &str) -> Option<u64> {
    let limits = std::fs::read_to_string("/proc/self/limits").unwrap();
    let row = limits.lines().find(|l| l.starts_with(name)).unwrap();
    let soft = row[name.len()..].split_whitespace().next().unwrap();
    soft.parse().ok()
}

fn harden_sets_flags() {
    assert!(is_dumpable());
    harden().unwrap();
    assert!(!is_dumpable());
    assert_eq!(soft_limit("Max core file size"), Some(0));
    let locked = status_kb("VmLck:");
    eprintln!(
        "after harden: VmLck {locked} kB, VmRSS {} kB",
        status_kb("VmRSS:")
    );
    assert!(locked > 0);
    assert!(locked <= BUDGET_KB);
}

fn main() {
    match soft_limit("Max locked memory").map(|b| b / 1024) {
        Some(kb) if kb < BUDGET_KB => {
            eprintln!("hardening: skipped, RLIMIT_MEMLOCK is {kb} KiB (< {BUDGET_KB} KiB)");
            return;
        }
        Some(kb) if kb > BUDGET_KB => eprintln!(
            "hardening: RLIMIT_MEMLOCK is {kb} KiB; run under `ulimit -l {BUDGET_KB}` to \
             check the shipped budget"
        ),
        None => eprintln!("hardening: RLIMIT_MEMLOCK is unlimited"),
        Some(_) => {}
    }
    harden_sets_flags();
    eprintln!("test harden_sets_flags ... ok");
}
