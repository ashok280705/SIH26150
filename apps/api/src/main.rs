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

    let config = forensic_api::AppConfig::from_env_or_cwd();
    let db_pool = forensic_api::db::connection::init_pool(&config.database_url).await?;
    seed_demo_case_if_empty(&db_pool, &config).await;
    let state = AppState::new_with_config(db_pool, config);
    let app = app_router(state);

    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let bind_addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    println!("DVR/NVR Forensic Analysis API listening on http://{bind_addr}");

    axum::serve(listener, app).await?;
    Ok(())
}

/// Automatically seeds a demonstration case and links available sample evidence when the database is fresh.
async fn seed_demo_case_if_empty(pool: &sqlx::SqlitePool, config: &forensic_api::AppConfig) {
    use chrono::Utc;
    use forensic_api::db::repositories;
    use forensic_core::{Evidence, EvidenceId, ExaminerId, ImageFormat, SourceState};
    use std::path::PathBuf;

    match repositories::cases::get_all_cases(pool).await {
        Ok(cases) if cases.is_empty() => {
            println!("Database is empty: seeding demonstration case and evidence...");
            let examiner = ExaminerId("Shubham Sarwar".to_string());
            match repositories::cases::create_case(
                pool,
                "Dahua DVR/NVR",
                "Forensic demonstration case with DHFS 4.1 evidence image",
                &examiner,
            )
            .await
            {
                Ok(case) => {
                    println!("Created demo case: '{}' ({})", case.name, case.id.0);

                    let candidate_paths = [
                        PathBuf::from("evidence_samples/dahua_dhfs_sample.raw"),
                        PathBuf::from("/app/evidence_samples/dahua_dhfs_sample.raw"),
                        config.evidence_samples_dir.join("dahua_dhfs_sample.raw"),
                        PathBuf::from("dahua_dhfs_sample.raw"),
                    ];

                    let mut found_path = None;
                    for p in &candidate_paths {
                        if p.exists() {
                            found_path = Some(p.clone());
                            break;
                        }
                    }

                    if let Some(path) = found_path {
                        let capacity =
                            std::fs::metadata(&path).map(|m| m.len()).unwrap_or(19204691);
                        let evidence = Evidence {
                            id: EvidenceId::new(),
                            case_id: case.id,
                            source_device: "Dahua Surveillance System".to_string(),
                            acquisition_time: Utc::now(),
                            capacity,
                            image_format: ImageFormat::Raw,
                            responsible_examiner: examiner,
                            acquisition_tool: Some("dd".to_string()),
                            acquisition_tool_version: Some("8.32".to_string()),
                            source_state: SourceState::ReadOnly,
                            acquisition_id: None,
                            path: path.to_string_lossy().to_string(),
                            registered_at: Utc::now(),
                            examiner_timezone: None,
                        };

                        match repositories::evidence::create_evidence(pool, &evidence).await {
                            Ok(_) => {
                                println!(
                                    "Registered sample evidence: '{}' ({}) -> {}",
                                    evidence.source_device,
                                    evidence.id.0,
                                    path.display()
                                );
                            }
                            Err(e) => eprintln!("Failed to register sample evidence: {e}"),
                        }
                    } else {
                        println!("Note: dahua_dhfs_sample.raw not found; created empty demo case.");
                    }
                }
                Err(e) => eprintln!("Failed to create demo case: {e}"),
            }
        }
        Ok(_) => {}
        Err(e) => eprintln!("Failed to check existing cases for seeding: {e}"),
    }
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

    let bin_name = if cfg!(windows) {
        "ollama.exe"
    } else {
        "ollama"
    };
    let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let vendor = root.join("vendor").join("ollama");

    // Look for the binary at vendor/ollama/bin/<name> or vendor/ollama/<name>.
    let candidates = [vendor.join("bin").join(bin_name), vendor.join(bin_name)];
    let bin = match candidates.iter().find(|p| p.exists()) {
        Some(b) => b.clone(),
        None => return, // No bundled runtime installed — nothing to do.
    };

    let host = std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "127.0.0.1:11434".to_string());
    let host_hostport = host
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let addr: SocketAddr = host_hostport.parse().unwrap_or_else(|_| {
        "127.0.0.1:11434"
            .parse()
            .expect("valid default socket addr")
    });

    // If a daemon is already up, don't start another.
    if TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok() {
        println!("Assistant: Ollama already running on {host_hostport}");
        return;
    }

    let models = vendor.join("models");
    let mut cmd = Command::new(&bin);
    cmd.arg("serve")
        .env("OLLAMA_HOST", host_hostport)
        .env("OLLAMA_MODELS", &models)
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    match cmd.spawn() {
        Ok(_) => println!(
            "Assistant: started bundled Ollama ({}) — models: {}",
            bin.display(),
            models.display()
        ),
        Err(e) => eprintln!("Assistant: could not start bundled Ollama: {e}"),
    }
}
