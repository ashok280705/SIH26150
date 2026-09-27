#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::Arc;
use tauri::{WebviewUrl, WebviewWindowBuilder};
use tokio::sync::oneshot;

fn get_desktop_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(app_data) = std::env::var("APPDATA") {
            return PathBuf::from(app_data).join("VidForge");
        }
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("data")
}

fn main() {
    tracing_subscriber::fmt::init();

    let runtime = tokio::runtime::Runtime::new().expect("Failed to initialize Tokio runtime");

    // Initialize desktop database and application state
    let data_dir = get_desktop_data_dir();
    let config = forensic_api::AppConfig::for_desktop(&data_dir);

    let (port, shutdown_tx) = runtime.block_on(async {
        let db_pool = forensic_api::db::connection::init_pool(&config.database_url)
            .await
            .expect("Failed to initialize desktop database pool");

        let state = forensic_api::AppState::new_with_config(db_pool, config);
        let app = forensic_api::app_router(state);

        // Bind strictly to loopback on a dynamic port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind desktop Axum listener to 127.0.0.1:0");

        let port = listener
            .local_addr()
            .expect("Failed to query assigned port")
            .port();

        tracing::info!("Embedded forensic API listening on http://127.0.0.1:{port}");

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        // Spawn embedded server
        tokio::spawn(async move {
            let server = axum::serve(listener, app);
            let graceful = server.with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
                tracing::info!("Embedded forensic API server shutting down gracefully");
            });
            if let Err(e) = graceful.await {
                tracing::error!("Embedded Axum server error: {e}");
            }
        });

        (port, shutdown_tx)
    });

    let shutdown_tx_arc = Arc::new(std::sync::Mutex::new(Some(shutdown_tx)));
    let shutdown_for_exit = shutdown_tx_arc.clone();

    tauri::Builder::default()
        .setup(move |app| {
            // Inject runtime API configuration script into window
            let init_script = format!(
                "window.__VIDFORGE_API_BASE__ = 'http://127.0.0.1:{port}/api';"
            );

            let win_builder = WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::App("index.html".into()),
            )
            .title("VIDFORGE Forensic Workstation")
            .inner_size(1440.0, 900.0)
            .initialization_script(&init_script);

            let _window = win_builder.build()?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("Error while building VidForge desktop application")
        .run(move |_app_handle, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                if let Ok(mut guard) = shutdown_for_exit.lock() {
                    if let Some(tx) = guard.take() {
                        let _ = tx.send(());
                    }
                }
            }
        });
}
