// Database persistence layer using SQLite

use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;
use workbench::Document;

/// Signal record stored in the database
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredSignal {
    pub signal_id: String,
    pub signal_type: String,
    pub severity: String,
    pub host: String,
    pub ts: i64,
    pub ts_start: i64,
    pub ts_end: i64,
    pub proc_key: Option<String>,
    pub file_key: Option<String>,
    pub identity_key: Option<String>,
    pub metadata: serde_json::Value,
    pub evidence_ptrs: Vec<serde_json::Value>,
    pub dropped_evidence_count: usize,
}

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_schema()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS signals (
                signal_id TEXT PRIMARY KEY,
                signal_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                host TEXT NOT NULL,
                ts INTEGER NOT NULL,
                ts_start INTEGER NOT NULL,
                ts_end INTEGER NOT NULL,
                proc_key TEXT,
                file_key TEXT,
                identity_key TEXT,
                metadata TEXT NOT NULL,
                evidence_ptrs TEXT NOT NULL,
                dropped_evidence_count INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_documents_updated 
                ON documents(updated_at DESC);
            
            CREATE INDEX IF NOT EXISTS idx_signals_ts 
                ON signals(ts DESC);
                
            CREATE INDEX IF NOT EXISTS idx_signals_host 
                ON signals(host);
                
            CREATE INDEX IF NOT EXISTS idx_signals_type 
                ON signals(signal_type);
                
            CREATE INDEX IF NOT EXISTS idx_signals_severity 
                ON signals(severity);
        "#,
        )?;
        Ok(())
    }

    // Document operations

    pub fn save_document(&self, doc: &Document) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let data = serde_json::to_string(doc).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO documents (id, data, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params![doc.id, data, doc.created_at.to_rfc3339(), doc.updated_at.to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_document(&self, id: &str) -> Result<Option<Document>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT data FROM documents WHERE id = ?1")?;
        let mut rows = stmt.query(params![id])?;

        if let Some(row) = rows.next()? {
            let data: String = row.get(0)?;
            let doc: Document = serde_json::from_str(&data).unwrap();
            Ok(Some(doc))
        } else {
            Ok(None)
        }
    }

    pub fn list_documents(&self) -> Result<Vec<Document>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT data FROM documents ORDER BY updated_at DESC")?;
        let mut rows = stmt.query([])?;

        let mut docs = Vec::new();
        while let Some(row) = rows.next()? {
            let data: String = row.get(0)?;
            if let Ok(doc) = serde_json::from_str(&data) {
                docs.push(doc);
            }
        }
        Ok(docs)
    }

    pub fn delete_document(&self, id: &str) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let count = conn.execute("DELETE FROM documents WHERE id = ?1", params![id])?;
        Ok(count > 0)
    }

    // Signal operations

    /// Store a batch of signals (upsert)
    pub fn save_signals(&self, signals: &[StoredSignal]) -> Result<usize, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut count = 0;
        for signal in signals {
            let metadata = serde_json::to_string(&signal.metadata).unwrap_or_default();
            let evidence = serde_json::to_string(&signal.evidence_ptrs).unwrap_or_default();
            let created_at = chrono::Utc::now().to_rfc3339();

            conn.execute(
                r#"INSERT OR REPLACE INTO signals 
                   (signal_id, signal_type, severity, host, ts, ts_start, ts_end,
                    proc_key, file_key, identity_key, metadata, evidence_ptrs, 
                    dropped_evidence_count, created_at)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"#,
                params![
                    signal.signal_id,
                    signal.signal_type,
                    signal.severity,
                    signal.host,
                    signal.ts,
                    signal.ts_start,
                    signal.ts_end,
                    signal.proc_key,
                    signal.file_key,
                    signal.identity_key,
                    metadata,
                    evidence,
                    signal.dropped_evidence_count,
                    created_at
                ],
            )?;
            count += 1;
        }
        Ok(count)
    }

    /// Get signal by ID
    pub fn get_signal(&self, signal_id: &str) -> Result<Option<StoredSignal>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT signal_id, signal_type, severity, host, ts, ts_start, ts_end, 
                    proc_key, file_key, identity_key, metadata, evidence_ptrs, dropped_evidence_count
             FROM signals WHERE signal_id = ?1"
        )?;

        let mut rows = stmt.query(params![signal_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Self::row_to_signal(row)?))
        } else {
            Ok(None)
        }
    }

    /// List recent signals with optional filters
    pub fn list_signals(
        &self,
        host: Option<&str>,
        signal_type: Option<&str>,
        severity: Option<&str>,
        limit: usize,
    ) -> Result<Vec<StoredSignal>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        let mut sql = String::from(
            "SELECT signal_id, signal_type, severity, host, ts, ts_start, ts_end,
                    proc_key, file_key, identity_key, metadata, evidence_ptrs, dropped_evidence_count
             FROM signals WHERE 1=1"
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(h) = host {
            sql.push_str(" AND host = ?");
            params_vec.push(Box::new(h.to_string()));
        }
        if let Some(t) = signal_type {
            sql.push_str(" AND signal_type = ?");
            params_vec.push(Box::new(t.to_string()));
        }
        if let Some(s) = severity {
            sql.push_str(" AND severity = ?");
            params_vec.push(Box::new(s.to_string()));
        }

        sql.push_str(" ORDER BY ts DESC LIMIT ?");
        params_vec.push(Box::new(limit as i64));

        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(params_refs.as_slice())?;

        let mut signals = Vec::new();
        while let Some(row) = rows.next()? {
            signals.push(Self::row_to_signal(row)?);
        }
        Ok(signals)
    }

    /// Get signal statistics
    pub fn signal_stats(&self) -> Result<SignalStats, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        let total: i64 = conn.query_row("SELECT COUNT(*) FROM signals", [], |r| r.get(0))?;

        let mut by_severity = std::collections::HashMap::new();
        let mut stmt = conn.prepare("SELECT severity, COUNT(*) FROM signals GROUP BY severity")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let sev: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            by_severity.insert(sev, count);
        }

        let mut by_host = std::collections::HashMap::new();
        let mut stmt = conn.prepare(
            "SELECT host, COUNT(*) FROM signals GROUP BY host ORDER BY COUNT(*) DESC LIMIT 10",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let host: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            by_host.insert(host, count);
        }

        let mut by_type = std::collections::HashMap::new();
        let mut stmt = conn.prepare("SELECT signal_type, COUNT(*) FROM signals GROUP BY signal_type ORDER BY COUNT(*) DESC LIMIT 20")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let sig_type: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            by_type.insert(sig_type, count);
        }

        Ok(SignalStats {
            total,
            by_severity,
            by_host,
            by_type,
        })
    }

    /// Count signals received within the last N seconds
    pub fn count_recent_signals(&self, seconds: i64) -> Result<i64, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let cutoff = chrono::Utc::now().timestamp() - seconds;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM signals WHERE created_at >= ?1",
            params![cutoff],
            |r| r.get(0),
        )?;
        Ok(count)
    }

    /// Health check - verify database is accessible
    pub fn health_check(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT 1", [], |_| Ok(()))?;
        Ok(())
    }

    /// Get stream stats for diagnostics
    pub fn get_stream_stats(
        &self,
    ) -> Result<std::collections::HashMap<String, crate::diagnostics::StreamStats>, rusqlite::Error>
    {
        use crate::diagnostics::StreamStats;

        let conn = self.conn.lock().unwrap();

        // Map signal_type to stream_id
        let mut stats: std::collections::HashMap<String, StreamStats> =
            std::collections::HashMap::new();

        let mut stmt = conn
            .prepare("SELECT signal_type, COUNT(*), MAX(ts) FROM signals GROUP BY signal_type")?;

        let rows = stmt.query_map([], |row| {
            let signal_type: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            let max_ts: i64 = row.get(2)?;
            Ok((signal_type, count, max_ts))
        })?;

        for row in rows {
            if let Ok((signal_type, count, max_ts)) = row {
                // Map signal types to stream IDs
                let stream_id = match signal_type.as_str() {
                    "ProcessInjection" | "SuspiciousExec" | "ProcessHollowing" => "process_exec",
                    "FileModification" | "SuspiciousWrite" => "file_write",
                    "NetworkConnection" | "C2Communication" => "network_connect",
                    "DnsQuery" => "dns_query",
                    "RegistryModification" => "registry_write",
                    _ => "unknown",
                };

                let entry = stats
                    .entry(stream_id.to_string())
                    .or_insert_with(StreamStats::default);
                entry.event_count += count as u64;

                // Convert timestamp to DateTime
                let ts = chrono::DateTime::from_timestamp(max_ts, 0)
                    .map(|dt| dt.with_timezone(&chrono::Utc));
                if let Some(ts) = ts {
                    if entry.last_seen_ts.map(|prev| ts > prev).unwrap_or(true) {
                        entry.last_seen_ts = Some(ts);
                    }
                }
            }
        }

        Ok(stats)
    }

    fn row_to_signal(row: &rusqlite::Row) -> Result<StoredSignal, rusqlite::Error> {
        let metadata_str: String = row.get(10)?;
        let evidence_str: String = row.get(11)?;

        Ok(StoredSignal {
            signal_id: row.get(0)?,
            signal_type: row.get(1)?,
            severity: row.get(2)?,
            host: row.get(3)?,
            ts: row.get(4)?,
            ts_start: row.get(5)?,
            ts_end: row.get(6)?,
            proc_key: row.get(7)?,
            file_key: row.get(8)?,
            identity_key: row.get(9)?,
            metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
            evidence_ptrs: serde_json::from_str(&evidence_str).unwrap_or_default(),
            dropped_evidence_count: row.get(12)?,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SignalStats {
    pub total: i64,
    pub by_severity: std::collections::HashMap<String, i64>,
    pub by_host: std::collections::HashMap<String, i64>,
    pub by_type: std::collections::HashMap<String, i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_document_crud() {
        let db = Database::open_in_memory().unwrap();

        // Create
        let doc = Document::new("Test Doc", "Tester");
        db.save_document(&doc).unwrap();

        // Read
        let loaded = db.get_document(&doc.id).unwrap().unwrap();
        assert_eq!(loaded.title, "Test Doc");

        // List
        let docs = db.list_documents().unwrap();
        assert_eq!(docs.len(), 1);

        // Delete
        let deleted = db.delete_document(&doc.id).unwrap();
        assert!(deleted);

        let docs = db.list_documents().unwrap();
        assert_eq!(docs.len(), 0);
    }

    #[test]
    fn test_signal_storage() {
        let db = Database::open_in_memory().unwrap();

        let signals = vec![
            StoredSignal {
                signal_id: "sig_001".to_string(),
                signal_type: "ProcessInjection".to_string(),
                severity: "critical".to_string(),
                host: "HOST1".to_string(),
                ts: 1000,
                ts_start: 900,
                ts_end: 1000,
                proc_key: Some("proc_123".to_string()),
                file_key: None,
                identity_key: Some("SYSTEM".to_string()),
                metadata: serde_json::json!({"technique": "T1055"}),
                evidence_ptrs: vec![serde_json::json!({"stream_id": "s1", "segment_id": 0})],
                dropped_evidence_count: 0,
            },
            StoredSignal {
                signal_id: "sig_002".to_string(),
                signal_type: "SuspiciousExec".to_string(),
                severity: "high".to_string(),
                host: "HOST2".to_string(),
                ts: 2000,
                ts_start: 2000,
                ts_end: 2000,
                proc_key: None,
                file_key: Some("file_abc".to_string()),
                identity_key: None,
                metadata: serde_json::json!({}),
                evidence_ptrs: vec![],
                dropped_evidence_count: 0,
            },
        ];

        // Save
        let count = db.save_signals(&signals).unwrap();
        assert_eq!(count, 2);

        // Get by ID
        let sig = db.get_signal("sig_001").unwrap().unwrap();
        assert_eq!(sig.signal_type, "ProcessInjection");
        assert_eq!(sig.severity, "critical");

        // List all
        let all = db.list_signals(None, None, None, 100).unwrap();
        assert_eq!(all.len(), 2);

        // Filter by host
        let host1 = db.list_signals(Some("HOST1"), None, None, 100).unwrap();
        assert_eq!(host1.len(), 1);

        // Filter by severity
        let critical = db.list_signals(None, None, Some("critical"), 100).unwrap();
        assert_eq!(critical.len(), 1);

        // Stats
        let stats = db.signal_stats().unwrap();
        assert_eq!(stats.total, 2);
        assert_eq!(*stats.by_severity.get("critical").unwrap_or(&0), 1);
    }
}
