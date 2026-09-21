//! # forensic-api
//!
//! Axum/Tokio HTTP API for the DVR/NVR forensic platform (Req 7.1, 7.2, 7.4, 7.7, 1.10, 18.8).

use forensic_api::{app_router, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // Best-effort: bring up the bundled offline assistant runtime (project-local Ollama)
    // if it has been installed under vendor/ollama. This never blocks or fails startup.
    spawn_bundled_ollama();

    let db_pool = forensic_api::db::connection::init_pool("sqlite:forensic_metadata.db").await?;
    let state = AppState::new(db_pool);
    let app = app_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("DVR/NVR Forensic Analysis API listening on http://127.0.0.1:3000");

    axum::serve(listener, app).await?;
    Ok(())
}

/// Start the project-local Ollama daemon that powers the offline assistant, if the
/// bundled binary exists under `vendor/ollama/`. This is intentionally best-effort:
/// it only acts when the operator has run `scripts/ollama/setup`, it skips launching
/// when a daemon is already listening, and any failure is logged and ignored so the
/// forensic API is never affected. No new dependencies are used.
fn spawn_bundled_ollama() {
    use std::net::{SocketAddr, TcpStream};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let bin_name = if cfg!(windows) { "ollama.exe" } else { "ollama" };
    let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let vendor = root.join("vendor").join("ollama");

    // Look for the binary at vendor/ollama/bin/<name> or vendor/ollama/<name>.
    let candidates = [vendor.join("bin").join(bin_name), vendor.join(bin_name)];
    let bin = match candidates.iter().find(|p| p.exists()) {
        Some(b) => b.clone(),
        None => return, // No bundled runtime installed — nothing to do.
    };

    let host = std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "127.0.0.1:11434".to_string());
    let host_hostport = host.trim_start_matches("http://").trim_start_matches("https://");
    let addr: SocketAddr = host_hostport
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:11434".parse().expect("valid default socket addr"));

    // If a daemon is already up, don't start another.
    if TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok() {
        println!("Assistant: Ollama already running on {host_hostport}");
        return;
    }

    let models = vendor.join("models");
    match Command::new(&bin)
        .arg("serve")
        .env("OLLAMA_HOST", host_hostport)
        .env("OLLAMA_MODELS", &models)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(_) => println!(
            "Assistant: started bundled Ollama ({}) — models: {}",
            bin.display(),
            models.display()
        ),
        Err(e) => eprintln!("Assistant: could not start bundled Ollama: {e}"),
    }
}
