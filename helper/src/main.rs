use pa_helper::error::ErrorCode;
use pa_helper::output::{render_err, render_ok};
use serde::Serialize;

#[derive(Serialize)]
struct VersionBody {
    version: &'static str,
}

fn main() {
    let mut args = std::env::args().skip(1);
    let reply = match (args.next().as_deref(), args.next()) {
        (Some("version"), None) => render_ok(&VersionBody {
            version: env!("CARGO_PKG_VERSION"),
        }),
        _ => render_err(ErrorCode::InvalidArgument),
    };
    println!("{reply}");
}
