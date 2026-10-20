#![deny(unsafe_code)]

use std::ffi::OsString;
use std::process::ExitCode;

use pa_helper::cli;
use pa_helper::clipboard::WlCopy;
use pa_helper::holder::Holder;
use pa_helper::output::render_err;
use pa_helper::sys;

fn main() -> ExitCode {
    if let Err(code) = sys::harden() {
        cli::emit(&render_err(code));
        return ExitCode::FAILURE;
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    cli::run(
        &args,
        &WlCopy::default(),
        &Holder::current_exe(),
        &cli::TIMEOUTS,
    )
}
