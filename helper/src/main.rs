#![deny(unsafe_code)]

use std::ffi::OsString;
use std::process::ExitCode;

use pa_helper::cli;
use pa_helper::clipboard::WlCopy;
use pa_helper::holder::Holder;
use pa_helper::sys;

fn main() -> ExitCode {
    let hardened = sys::harden();
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if let Err(code) = hardened {
        return cli::harden_failed(&args, code);
    }
    cli::run(
        &args,
        &WlCopy::default(),
        &Holder::current_exe(),
        &cli::TIMEOUTS,
    )
}
