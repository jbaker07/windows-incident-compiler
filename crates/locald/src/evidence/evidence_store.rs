//! Evidence Store: Persist and retrieve canonical event records
//!
//! Stores canonical events keyed by EvidencePtr for fast deref.
//! Maintains both DB-backed storage and segment file references.
//!
//! Ship Hardening: All segment paths are validated to prevent directory traversal.

use super::evidence_ptr::EvidencePtr;
use super::path_safety::{validate_path_within_root, validate_segment_id, PathValidationError};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// Stored record with canonical event data and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRecord {
    /// The evidence pointer
    pub ptr: EvidencePtr,

    /// Canonical event JSON (serialized CanonicalEvent)
    pub canonical_json: String,

    /// Raw record bytes (optional, may be large)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_bytes: Option<Vec<u8>>,

    /// Ingestion timestamp
    pub ingested_at: i64,

    /// Whether this record came from DB or segment fallback
    pub source: RecordSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordSource {
    Database,
    SegmentFile,
    Cache,
}

/// Evidence storage backend
pub struct EvidenceStore {
    /// SQLite connection for persistent storage
    db: Connection,

    /// In-memory cache for hot records
    cache: Arc<RwLock<HashMap<String, StoredRecord>>>,

    /// Segment file directory
    segment_dir: PathBuf,

    /// Cache size limit
    cache_limit: usize,
}

impl EvidenceStore {
    /// Open or create evidence store
    pub fn open(db_path: &str, segment_dir: PathBuf) -> Result<Self, rusqlite::Error> {
        let db = Connection::open(db_path)?;
        Self::init_schema(&db)?;

        Ok(Self {
            db,
            cache: Arc::new(RwLock::new(HashMap::new())),
            segment_dir,
            cache_limit: 10000,
        })
    }

    /// Open in-memory store (for testing)
    pub fn open_memory() -> Result<Self, rusqlite::Error> {
        let db = Connection::open_in_memory()?;
        Self::init_schema(&db)?;

        Ok(Self {
            db,
            cache: Arc::new(RwLock::new(HashMap::new())),
            segment_dir: PathBuf::from("/tmp/segments"),
            cache_limit: 10000,
        })
    }

    fn init_schema(db: &Connection) -> Result<(), rusqlite::Error> {
        db.execute_batch(r#"
            CREATE TABLE IF NOT EXISTS canonical_events (
                ptr_key TEXT PRIMARY KEY,
                stream_id TEXT NOT NULL,
                segment_id TEXT NOT NULL,
                record_index INTEGER NOT NULL,
                sha256 TEXT,
                ts INTEGER,
                canonical_json TEXT NOT NULL,
                ingested_at INTEGER NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_canonical_stream ON canonical_events(stream_id, segment_id);
            CREATE INDEX IF NOT EXISTS idx_canonical_ts ON canonical_events(ts);
            
            CREATE TABLE IF NOT EXISTS segment_metadata (
                segment_id TEXT PRIMARY KEY,
                stream_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                start_index INTEGER NOT NULL,
                end_index INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                rotated_at INTEGER,
                deleted_at INTEGER
            );
        "#)?;
        Ok(())
    }

    /// Store a canonical event record
    pub fn store(
        &mut self,
        ptr: &EvidencePtr,
        canonical_json: &str,
    ) -> Result<(), rusqlite::Error> {
        let ptr_key = ptr.canonical_key();
        let now = chrono::Utc::now().timestamp_millis();

        self.db.execute(
            r#"INSERT OR REPLACE INTO canonical_events 
               (ptr_key, stream_id, segment_id, record_index, sha256, ts, canonical_json, ingested_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
            params![
                ptr_key,
                ptr.stream_id,
                ptr.segment_id,
                ptr.record_index as i64,
                ptr.sha256,
                ptr.ts,
                canonical_json,
                now,
            ],
        )?;

        // Update cache
        let record = StoredRecord {
            ptr: ptr.clone(),
            canonical_json: canonical_json.to_string(),
            raw_bytes: None,
            ingested_at: now,
            source: RecordSource::Database,
        };

        let mut cache = self.cache.write().unwrap();
        if cache.len() >= self.cache_limit {
            // Simple eviction: remove a random entry
            if let Some(key) = cache.keys().next().cloned() {
                cache.remove(&key);
            }
        }
        cache.insert(ptr_key, record);

        Ok(())
    }

    /// Store multiple records in a batch
    pub fn store_batch(
        &mut self,
        records: &[(EvidencePtr, String)],
    ) -> Result<(), rusqlite::Error> {
        let tx = self.db.transaction()?;
        let now = chrono::Utc::now().timestamp_millis();

        for (ptr, canonical_json) in records {
            let ptr_key = ptr.canonical_key();
            tx.execute(
                r#"INSERT OR REPLACE INTO canonical_events 
                   (ptr_key, stream_id, segment_id, record_index, sha256, ts, canonical_json, ingested_at)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
                params![
                    ptr_key,
                    ptr.stream_id,
                    ptr.segment_id,
                    ptr.record_index as i64,
                    ptr.sha256,
                    ptr.ts,
                    canonical_json,
                    now,
                ],
            )?;
        }

        tx.commit()
    }

    /// Retrieve record by evidence pointer (DB lookup)
    pub fn get(&self, ptr: &EvidencePtr) -> Option<StoredRecord> {
        let ptr_key = ptr.canonical_key();

        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(record) = cache.get(&ptr_key) {
                return Some(StoredRecord {
                    source: RecordSource::Cache,
                    ..record.clone()
                });
            }
        }

        // DB lookup
        let mut stmt = self
            .db
            .prepare("SELECT canonical_json, ingested_at FROM canonical_events WHERE ptr_key = ?1")
            .ok()?;

        stmt.query_row([&ptr_key], |row| {
            Ok(StoredRecord {
                ptr: ptr.clone(),
                canonical_json: row.get(0)?,
                raw_bytes: None,
                ingested_at: row.get(1)?,
                source: RecordSource::Database,
            })
        })
        .ok()
    }

    /// Check if segment exists and is available
    pub fn segment_available(&self, segment_id: &str) -> bool {
        let mut stmt = match self
            .db
            .prepare("SELECT deleted_at FROM segment_metadata WHERE segment_id = ?1")
        {
            Ok(s) => s,
            Err(_) => return false,
        };

        match stmt.query_row([segment_id], |row| {
            let deleted_at: Option<i64> = row.get(0)?;
            Ok(deleted_at.is_none())
        }) {
            Ok(available) => available,
            Err(_) => {
                // Not in metadata, check file system
                let path = self.segment_dir.join(segment_id);
                path.exists()
            }
        }
    }

    /// Register segment metadata
    pub fn register_segment(
        &mut self,
        segment_id: &str,
        stream_id: &str,
        file_path: &str,
        start_index: u64,
        end_index: u64,
    ) -> Result<(), rusqlite::Error> {
        let now = chrono::Utc::now().timestamp_millis();

        self.db.execute(
            r#"INSERT OR REPLACE INTO segment_metadata 
               (segment_id, stream_id, file_path, start_index, end_index, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
            params![
                segment_id,
                stream_id,
                file_path,
                start_index as i64,
                end_index as i64,
                now
            ],
        )?;
        Ok(())
    }

    /// Mark segment as rotated/deleted
    pub fn mark_segment_deleted(&mut self, segment_id: &str) -> Result<(), rusqlite::Error> {
        let now = chrono::Utc::now().timestamp_millis();

        self.db.execute(
            "UPDATE segment_metadata SET deleted_at = ?1 WHERE segment_id = ?2",
            params![now, segment_id],
        )?;
        Ok(())
    }

    /// Get segment file path with path safety validation
    ///
    /// Ship Hardening: Validates that the path stays within telemetry root
    /// Returns None if segment not found or path validation fails
    pub fn get_segment_path(&self, segment_id: &str) -> Option<PathBuf> {
        // Validate segment_id format first
        if validate_segment_id(segment_id).is_err() {
            log::warn!("Invalid segment_id format: {}", segment_id);
            return None;
        }

        let mut stmt = self.db.prepare(
            "SELECT file_path FROM segment_metadata WHERE segment_id = ?1 AND deleted_at IS NULL"
        ).ok()?;

        let path: String = stmt.query_row([segment_id], |row| row.get(0)).ok()?;
        let path_buf = PathBuf::from(&path);

        // Validate path stays within segment_dir (telemetry root)
        match validate_path_within_root(&self.segment_dir, &path_buf) {
            Ok(canonical_path) => Some(canonical_path),
            Err(e) => {
                log::error!("Path validation failed for segment {}: {}", segment_id, e);
                None
            }
        }
    }

    /// Get segment file path by joining with segment_dir (safe fallback)
    ///
    /// Ship Hardening: Always validates that path stays within telemetry root
    pub fn get_segment_path_safe(&self, segment_id: &str) -> Result<PathBuf, PathValidationError> {
        // Validate segment_id format
        validate_segment_id(segment_id)?;

        // Build path within segment_dir
        let path = self.segment_dir.join(segment_id);

        // Validate final path stays within bounds
        validate_path_within_root(&self.segment_dir, &path)
    }

    /// Query records by time range
    pub fn query_by_time(&self, start_ts: i64, end_ts: i64, limit: usize) -> Vec<StoredRecord> {
        let mut stmt = match self.db.prepare(
            r#"SELECT ptr_key, stream_id, segment_id, record_index, sha256, ts, canonical_json, ingested_at
               FROM canonical_events 
               WHERE ts >= ?1 AND ts <= ?2
               ORDER BY ts, stream_id, record_index
               LIMIT ?3"#
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let iter = match stmt.query_map(params![start_ts, end_ts, limit as i64], |row| {
            Ok(StoredRecord {
                ptr: EvidencePtr {
                    stream_id: row.get(1)?,
                    segment_id: row.get(2)?,
                    record_index: row.get::<_, i64>(3)? as u64,
                    sha256: row.get(4)?,
                    ts: row.get(5)?,
                },
                canonical_json: row.get(6)?,
                raw_bytes: None,
                ingested_at: row.get(7)?,
                source: RecordSource::Database,
            })
        }) {
            Ok(i) => i,
            Err(_) => return Vec::new(),
        };

        iter.filter_map(|r| r.ok()).collect()
    }

    /// Query records by stream
    pub fn query_by_stream(&self, stream_id: &str, limit: usize) -> Vec<StoredRecord> {
        let mut stmt = match self.db.prepare(
            r#"SELECT ptr_key, segment_id, record_index, sha256, ts, canonical_json, ingested_at
               FROM canonical_events 
               WHERE stream_id = ?1
               ORDER BY segment_id, record_index
               LIMIT ?2"#,
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let iter = match stmt.query_map(params![stream_id, limit as i64], |row| {
            Ok(StoredRecord {
                ptr: EvidencePtr {
                    stream_id: stream_id.to_string(),
                    segment_id: row.get(0)?,
                    record_index: row.get::<_, i64>(1)? as u64,
                    sha256: row.get(2)?,
                    ts: row.get(3)?,
                },
                canonical_json: row.get(4)?,
                raw_bytes: None,
                ingested_at: row.get(5)?,
                source: RecordSource::Database,
            })
        }) {
            Ok(i) => i,
            Err(_) => return Vec::new(),
        };

        iter.filter_map(|r| r.ok()).collect()
    }

    /// Count records in store
    pub fn count(&self) -> u64 {
        let mut stmt = match self.db.prepare("SELECT COUNT(*) FROM canonical_events") {
            Ok(s) => s,
            Err(_) => return 0,
        };

        stmt.query_row([], |row| row.get(0)).unwrap_or(0)
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_retrieve() {
        let mut store = EvidenceStore::open_memory().unwrap();

        let ptr = EvidencePtr::minimal("stream-a", "seg-001", 42);
        let json = r#"{"event_type":"process_start","pid":1234}"#;

        store.store(&ptr, json).unwrap();

        let record = store.get(&ptr).unwrap();
        assert_eq!(record.canonical_json, json);
    }

    #[test]
    fn test_batch_store() {
        let mut store = EvidenceStore::open_memory().unwrap();

        let records: Vec<(EvidencePtr, String)> = (0..100)
            .map(|i| {
                (
                    EvidencePtr::minimal("stream-a", "seg-001", i),
                    format!(r#"{{"index":{}}}"#, i),
                )
            })
            .collect();

        store.store_batch(&records).unwrap();

        assert_eq!(store.count(), 100);
    }

    #[test]
    fn test_query_by_time() {
        let mut store = EvidenceStore::open_memory().unwrap();

        for i in 0..10 {
            let ptr = EvidencePtr::new("stream-a", "seg-001", i, None, Some(1000 + i as i64 * 100));
            store
                .store(&ptr, &format!(r#"{{"ts":{}}}"#, 1000 + i * 100))
                .unwrap();
        }

        let records = store.query_by_time(1200, 1600, 100);
        assert_eq!(records.len(), 5); // ts 1200, 1300, 1400, 1500, 1600
    }
}
