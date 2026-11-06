use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use pharos_server::{init_tracing, load_config, run};

#[derive(Parser)]
#[command(
    name = "pharos-server",
    version,
    about = "Pharos tunnel server: publish authenticated TCP and HTTP tunnels"
)]
struct Args {
    /// Path to the TOML configuration file
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    config: PathBuf,
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("pharos-server: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = load_config(&args.config)?;
    init_tracing(&config.log)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(config))
}
