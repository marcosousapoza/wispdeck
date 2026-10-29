mod admin;
mod app;
mod auth;
mod config;
mod core;
mod protocol;
mod proxy;

use std::{env, path::PathBuf, process::ExitCode};

use anyhow::Result;
#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Wispdeck stopped: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "serve".to_owned());
    let data_dir = env::var_os("WISPDECK_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/data"));

    match command.as_str() {
        "serve" => app::serve(data_dir).await,
        "reset-admin-password" => {
            anyhow::ensure!(
                args.next().is_none(),
                "usage: wispdeck reset-admin-password (password is read from the terminal)"
            );
            let password = tokio::task::spawn_blocking(|| {
                rpassword::prompt_password("New administrator password: ")
            })
            .await??;
            auth::admin::reset_password(&data_dir, &password).await
        }
        _ => anyhow::bail!("unknown command {command:?}; expected serve or reset-admin-password"),
    }
}
