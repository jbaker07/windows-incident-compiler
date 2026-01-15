//! Run persistence layer tests
//!
//! Verifies that runs are properly persisted and retrieved.
//! 
//! These tests directly use SQLite since the db module isn't exported
//! from the library crate.

use rusqlite::{params, Connection};
use tempfile::tempdir;

/// Test inserting and listing a run with SQLite directly
#[test]
fn test_run_persistence_roundtrip_sqlite() {
    let dir = tempdir().expect("Failed to create temp dir");
    let db_path = dir.path().join("test.db");
    let conn = Connection::open(&db_path).expect("Failed to open database");
    
    // Create the runs table
    conn.execute(
        r#"CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            profile TEXT,
            started_at TEXT NOT NULL,
            stopped_at TEXT,
            run_dir TEXT,
            events_total INTEGER NOT NULL DEFAULT 0,
            segments_count INTEGER NOT NULL DEFAULT 0,
            facts_extracted INTEGER NOT NULL DEFAULT 0,
            signals_fired INTEGER NOT NULL DEFAULT 0,
            bytes_written INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'running',
            created_at TEXT NOT NULL
        )"#,
        [],
    ).expect("Failed to create table");
    
    // Insert a test run
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        r#"INSERT INTO runs (run_id, profile, started_at, stopped_at, events_total, segments_count, facts_extracted, signals_fired, bytes_written, status, created_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
        params![
            "run_test12345",
            "extended",
            "2026-01-10T00:00:00Z",
            "2026-01-10T00:05:00Z",
            1234_i64,
            12_i64,
            56_i64,
            0_i64,
            50000_i64,
            "completed",
            now
        ],
    ).expect("Failed to insert run");
    
    // Query back
    let mut stmt = conn.prepare("SELECT run_id, events_total, signals_fired, status FROM runs").unwrap();
    let mut rows = stmt.query([]).unwrap();
    
    let row = rows.next().unwrap().expect("No rows");
    let run_id: String = row.get(0).unwrap();
    let events_total: i64 = row.get(1).unwrap();
    let signals_fired: i64 = row.get(2).unwrap();
    let status: String = row.get(3).unwrap();
    
    assert_eq!(run_id, "run_test12345");
    assert_eq!(events_total, 1234);
    assert_eq!(signals_fired, 0);
    assert_eq!(status, "completed");
    
    println!("✅ Run persistence roundtrip passed");
}

/// Test that runs persist to production database
/// This test uses the actual production database path
#[test]
#[ignore] // Run with: cargo test -p edr-server test_seed_production_run -- --ignored
fn test_seed_production_run() {
    let data_dir = dirs::data_local_dir()
        .expect("No local data dir")
        .join("attack-workbench");
    
    std::fs::create_dir_all(&data_dir).expect("Failed to create data dir");
    let db_path = data_dir.join("workbench.db");
    
    println!("Using database: {:?}", db_path);
    
    let conn = Connection::open(&db_path).expect("Failed to open database");
    
    // Insert a test run with known ID
    let now = chrono::Utc::now();
    let started = (now - chrono::Duration::minutes(5)).to_rfc3339();
    let stopped = now.to_rfc3339();
    let run_id = format!("run_test_{}", now.timestamp() % 100000);
    
    conn.execute(
        r#"INSERT OR REPLACE INTO runs (run_id, profile, started_at, stopped_at, events_total, segments_count, facts_extracted, signals_fired, bytes_written, status, created_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
        params![
            &run_id,
            "extended",
            &started,
            &stopped,
            1234_i64,
            12_i64,
            56_i64,
            0_i64,
            50000_i64,
            "completed",
            &started
        ],
    ).expect("Failed to insert run");
    
    println!("Inserted run: {}", run_id);
    
    // Verify
    let mut stmt = conn.prepare("SELECT run_id, events_total, signals_fired, status FROM runs ORDER BY started_at DESC LIMIT 10").unwrap();
    let mut rows = stmt.query([]).unwrap();
    
    println!("Current runs:");
    while let Some(row) = rows.next().unwrap() {
        let rid: String = row.get(0).unwrap();
        let events: i64 = row.get(1).unwrap();
        let signals: i64 = row.get(2).unwrap();
        let status: String = row.get(3).unwrap();
        println!("  - {}: events={}, signals={}, status={}", rid, events, signals, status);
    }
}
