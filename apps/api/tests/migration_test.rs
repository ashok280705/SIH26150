use sqlx::sqlite::SqlitePoolOptions;
use std::fs;

#[tokio::test]
async fn test_migrations() {
    let db_path = "sqlite:test_mig.db";
    let _ = fs::remove_file("test_mig.db");
    let _ = fs::File::create("test_mig.db").unwrap();

    let pool = SqlitePoolOptions::new()
        .connect(db_path)
        .await
        .unwrap();

    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    println!("Migrations successful!");
    
    let _ = fs::remove_file("test_mig.db");
}
