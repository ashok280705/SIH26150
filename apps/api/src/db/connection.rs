use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::path::Path;

pub async fn init_pool(db_url: &str) -> Result<SqlitePool, sqlx::Error> {
    // If the URL is just a file path (e.g., "sqlite:data.db"), we might need to create it
    if db_url.starts_with("sqlite:") {
        let path_str = &db_url["sqlite:".len()..];
        if path_str != ":memory:" {
            let path = Path::new(path_str);
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            if !path.exists() {
                let _ = std::fs::File::create(path);
            }
        }
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(db_url)
        .await?;

    // Enable WAL mode and Foreign Keys
    sqlx::query("PRAGMA journal_mode = WAL;")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA foreign_keys = ON;")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA synchronous = NORMAL;")
        .execute(&pool)
        .await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}
