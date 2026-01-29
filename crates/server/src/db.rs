// Database persistence layer using SQLite

use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use workbench::Document;

/// Signal record stored in the database
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredSignal {
    pub signal_id: String,
    pub run_id: String,
    pub signal_type: String,
    pub severity: String,
    pub host: String,
    pub ts: i64,
    pub ts_start: i64,
    pub ts_end: i64,
    pub proc_key: Option<String>,
    pub file_key: Option<String>,
    pub identity_key: Option<String>,
    /// Detector that produced this signal (e.g., "playbook:ransomware_v2")
    pub detector_id: String,
    /// Detector version (e.g., "1.2.0")
    pub detector_version: String,
    /// Data source/sensor that provided evidence (e.g., "etw:kernel", "sysmon")
    pub source_sensor: String,
    pub metadata: serde_json::Value,
    pub evidence_ptrs: Vec<serde_json::Value>,
    pub dropped_evidence_count: usize,
}

/// Run record stored in the database
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RunRecord {
    pub run_id: String,
    pub name: Option<String>,  // User-assigned name for the run
    pub profile: Option<String>,
    pub started_at: String,
    pub stopped_at: Option<String>,
    pub run_dir: Option<String>,
    pub events_total: u64,
    pub segments_count: u32,
    pub facts_extracted: u64,
    pub signals_fired: u64,
    pub bytes_written: u64,
    pub status: String,  // "running", "stopping", "stopped"
    // Baseline fields (Pro/Team foundation)
    #[serde(default)]
    pub baseline_scope: Option<String>,  // "host" | "install" | null
    #[serde(default)]
    pub baseline_enabled: bool,  // true if this run is marked as baseline
    #[serde(default)]
    pub baseline_set_at: Option<String>,  // ISO timestamp when marked as baseline
    // Chain stack for Investigate tab (INVESTIGATE_CHAINS-1)
    #[serde(default)]
    pub chain_ids: Option<Vec<String>>,  // Persisted chain IDs for this run
}

/// Metrics from a run (used for finalization)
#[derive(Debug, Clone, Default)]
pub struct RunMetrics {
    pub events_total: u64,
    pub segments_count: u32,
    pub facts_extracted: u64,
    pub signals_fired: u64,
    pub bytes_written: u64,
}

pub struct Database {
    conn: Mutex<Connection>,
    data_dir: PathBuf,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        // Derive data_dir from the database path (workbench.db is in data_dir)
        let data_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        let db = Self {
            conn: Mutex::new(conn),
            data_dir,
        };
        db.init_schema()?;
        Ok(db)
    }

    #[allow(dead_code)]
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Mutex::new(conn),
            data_dir: PathBuf::from("."),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        
        // Step 1: Create main tables (without indices that depend on columns that might need migration)
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
                run_id TEXT NOT NULL DEFAULT 'unknown',
                signal_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                host TEXT NOT NULL,
                ts INTEGER NOT NULL,
                ts_start INTEGER NOT NULL,
                ts_end INTEGER NOT NULL,
                proc_key TEXT,
                file_key TEXT,
                identity_key TEXT,
                detector_id TEXT NOT NULL DEFAULT 'unknown',
                detector_version TEXT NOT NULL DEFAULT '0.0.0',
                source_sensor TEXT NOT NULL DEFAULT 'unknown',
                metadata TEXT NOT NULL,
                evidence_ptrs TEXT NOT NULL,
                dropped_evidence_count INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            "#,
        )?;
        
        // Step 2: Run migrations BEFORE creating indices on new columns
        self.migrate_signals_table(&conn)?;
        self.migrate_runs_table(&conn)?;
        
        // Step 3: Create indices and remaining tables (after migration ensures columns exist)
        conn.execute_batch(
            r#"
            CREATE INDEX IF NOT EXISTS idx_signals_run_id ON signals(run_id);
            CREATE INDEX IF NOT EXISTS idx_signals_ts ON signals(ts);
            
            -- Runs table (persisted run records)
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                name TEXT,
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
                baseline_scope TEXT,
                baseline_enabled INTEGER NOT NULL DEFAULT 0,
                baseline_set_at TEXT,
                chain_ids TEXT,
                created_at TEXT NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_runs_started_at ON runs(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
            
            -- Narratives table (evidence-cited explanations)
            CREATE TABLE IF NOT EXISTS narratives (
                narrative_id TEXT PRIMARY KEY,
                signal_id TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                narrative_json TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                FOREIGN KEY (signal_id) REFERENCES signals(signal_id)
            );
            
            -- Mission specs table (for mission mode)
            CREATE TABLE IF NOT EXISTS mission_specs (
                mission_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                objective TEXT NOT NULL,
                spec_json TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            
            -- User actions on narratives (pin/hide/verify)
            CREATE TABLE IF NOT EXISTS narrative_actions (
                action_id TEXT PRIMARY KEY,
                narrative_id TEXT NOT NULL,
                sentence_id TEXT,
                evidence_ptr_json TEXT,
                action_type TEXT NOT NULL,
                notes TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (narrative_id) REFERENCES narratives(narrative_id)
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
                
            CREATE INDEX IF NOT EXISTS idx_narratives_signal 
                ON narratives(signal_id);
                
            CREATE INDEX IF NOT EXISTS idx_mission_specs_active 
                ON mission_specs(is_active);
        "#,
        )?;
        
        Ok(())
    }
    
    /// Migrate existing signals table to add new columns if missing
    fn migrate_signals_table(&self, conn: &std::sync::MutexGuard<'_, Connection>) -> Result<(), rusqlite::Error> {
        // Check which columns exist
        let mut stmt = conn.prepare("PRAGMA table_info(signals)")?;
        let mut rows = stmt.query([])?;
        
        let mut existing_columns: std::collections::HashSet<String> = std::collections::HashSet::new();
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            existing_columns.insert(name);
        }
        
        // Migrations for new columns with safe defaults
        let migrations = [
            ("run_id", "ALTER TABLE signals ADD COLUMN run_id TEXT NOT NULL DEFAULT 'unknown'"),
            ("detector_id", "ALTER TABLE signals ADD COLUMN detector_id TEXT NOT NULL DEFAULT 'unknown'"),
            ("detector_version", "ALTER TABLE signals ADD COLUMN detector_version TEXT NOT NULL DEFAULT '0.0.0'"),
            ("source_sensor", "ALTER TABLE signals ADD COLUMN source_sensor TEXT NOT NULL DEFAULT 'unknown'"),
        ];
        
        for (column, sql) in migrations {
            if !existing_columns.contains(column) {
                tracing::info!("Migrating signals table: adding column '{}'", column);
                if let Err(e) = conn.execute(sql, []) {
                    // Column might already exist from a partial migration
                    if !e.to_string().contains("duplicate column") {
                        tracing::warn!("Migration warning for '{}': {}", column, e);
                    }
                }
            }
        }
        
        // Ensure index exists
        let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_signals_run_id ON signals(run_id)", []);
        
        Ok(())
    }

    /// Migrate existing runs table to add new columns if missing
    fn migrate_runs_table(&self, conn: &std::sync::MutexGuard<'_, Connection>) -> Result<(), rusqlite::Error> {
        // Check if runs table exists first
        let table_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='runs'",
                [],
                |row| row.get::<_, i32>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        
        if !table_exists {
            return Ok(());
        }
        
        // Check which columns exist
        let mut stmt = conn.prepare("PRAGMA table_info(runs)")?;
        let mut rows = stmt.query([])?;
        
        let mut existing_columns: std::collections::HashSet<String> = std::collections::HashSet::new();
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            existing_columns.insert(name);
        }
        
        // Add name column if missing
        if !existing_columns.contains("name") {
            tracing::info!("Migrating runs table: adding column 'name'");
            if let Err(e) = conn.execute("ALTER TABLE runs ADD COLUMN name TEXT", []) {
                if !e.to_string().contains("duplicate column") {
                    tracing::warn!("Migration warning for 'name': {}", e);
                }
            }
        }
        
        // Add baseline columns (Pro/Team foundation)
        if !existing_columns.contains("baseline_scope") {
            tracing::info!("Migrating runs table: adding baseline columns");
            if let Err(e) = conn.execute("ALTER TABLE runs ADD COLUMN baseline_scope TEXT", []) {
                if !e.to_string().contains("duplicate column") {
                    tracing::warn!("Migration warning for 'baseline_scope': {}", e);
                }
            }
        }
        if !existing_columns.contains("baseline_enabled") {
            if let Err(e) = conn.execute("ALTER TABLE runs ADD COLUMN baseline_enabled INTEGER NOT NULL DEFAULT 0", []) {
                if !e.to_string().contains("duplicate column") {
                    tracing::warn!("Migration warning for 'baseline_enabled': {}", e);
                }
            }
        }
        if !existing_columns.contains("baseline_set_at") {
            if let Err(e) = conn.execute("ALTER TABLE runs ADD COLUMN baseline_set_at TEXT", []) {
                if !e.to_string().contains("duplicate column") {
                    tracing::warn!("Migration warning for 'baseline_set_at': {}", e);
                }
            }
        }
        
        // Add chain_ids column (INVESTIGATE_CHAINS-1)
        if !existing_columns.contains("chain_ids") {
            tracing::info!("Migrating runs table: adding column 'chain_ids'");
            if let Err(e) = conn.execute("ALTER TABLE runs ADD COLUMN chain_ids TEXT", []) {
                if !e.to_string().contains("duplicate column") {
                    tracing::warn!("Migration warning for 'chain_ids': {}", e);
                }
            }
        }
        
        tracing::debug!("runs table baseline columns OK (baseline_scope, baseline_enabled, baseline_set_at)");
        tracing::debug!("runs table chain_ids column OK");
        
        // Safe orphan reconciliation: only abandon runs that are truly dead
        // NOT the aggressive "abandon all running" which creates false positives
        tracing::info!("DB startup: running orphan reconciliation...");
        if let Err(e) = self.reconcile_orphan_runs(&conn) {
            tracing::error!("Orphan reconciliation failed: {}", e);
        }
        tracing::info!("DB startup: orphan reconciliation complete");
        
        Ok(())
    }
    
    /// Safe orphan reconciliation: only abandon runs that are truly dead/stale
    /// 
    /// For each run with status="running":
    /// 1) If run_meta.json has PIDs: check if PIDs are alive
    /// 2) Else: check run_dir activity (segments/, checkpoint) within last 120s
    /// 3) Only mark as abandoned if truly dead AND stale beyond threshold
    fn reconcile_orphan_runs(&self, _conn: &std::sync::MutexGuard<'_, Connection>) -> Result<(), rusqlite::Error> {
        // Scan filesystem for runs (run_meta.json is the source of truth for status)
        let runs_dir = self.data_dir.join("runs");
        if !runs_dir.exists() {
            tracing::debug!("Orphan reconciliation: runs directory does not exist");
            return Ok(());
        }
        
        let entries = match std::fs::read_dir(&runs_dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Orphan reconciliation: failed to read runs directory: {}", e);
                return Ok(());
            }
        };
        
        let mut running_count = 0;
        let mut abandoned_count = 0;
        let mut kept_running = 0;
        
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            
            let run_dir = entry.path();
            let meta_path = run_dir.join("run_meta.json");
            
            // Read run_meta.json
            let meta_content = match std::fs::read_to_string(&meta_path) {
                Ok(c) => c,
                Err(_) => continue, // No run_meta.json, skip
            };
            
            let meta: serde_json::Value = match serde_json::from_str(&meta_content) {
                Ok(m) => m,
                Err(_) => continue, // Invalid JSON, skip
            };
            
            // Only process runs with status="running"
            let status = meta.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if status != "running" {
                continue;
            }
            
            running_count += 1;
            let run_id = entry.file_name().to_string_lossy().to_string();
            let run_dir_str = run_dir.display().to_string();
            
            // Check if this run is still alive
            let (should_abandon, reason) = check_run_status(&run_dir_str);
            
            if should_abandon {
                tracing::info!(
                    "Orphan reconciliation: Marking run '{}' as abandoned (reason: {})", 
                    run_id, reason
                );
                
                // Update run_meta.json with status and reason
                update_run_meta_status(&run_dir_str, "abandoned", &reason, Some("interrupted"));
                abandoned_count += 1;
            } else {
                tracing::debug!(
                    "Orphan reconciliation: Keeping run '{}' as 'running' (reason: {})",
                    run_id, reason
                );
                kept_running += 1;
            }
        }
        
        if running_count > 0 {
            tracing::info!(
                "Orphan reconciliation: found {} runs in 'running' state, {} abandoned, {} kept running",
                running_count, abandoned_count, kept_running
            );
        } else {
            tracing::debug!("Orphan reconciliation: no runs in 'running' state");
        }
        
        Ok(())
    }
}

/// Check if a run is still active or should be abandoned
/// Returns (should_abandon: bool, reason: String)
fn check_run_status(run_dir: &str) -> (bool, String) {
    use std::path::Path;
    
    let path = Path::new(run_dir);
    if !path.exists() {
        return (true, "RUN_DIR_MISSING".to_string());
    }
    
    // 1) Check for PIDs in run_meta.json and verify they're alive
    let meta_path = path.join("run_meta.json");
    if meta_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&meta_path) {
            if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&content) {
                // Check capture_pid
                if let Some(pid) = meta.get("capture_pid").and_then(|v| v.as_u64()) {
                    if is_pid_alive(pid as u32) {
                        return (false, format!("CAPTURE_PID_{}_ALIVE", pid));
                    }
                }
                // Check locald_pid
                if let Some(pid) = meta.get("locald_pid").and_then(|v| v.as_u64()) {
                    if is_pid_alive(pid as u32) {
                        return (false, format!("LOCALD_PID_{}_ALIVE", pid));
                    }
                }
                // Check supervisor_pid (if we add it)
                if let Some(pid) = meta.get("supervisor_pid").and_then(|v| v.as_u64()) {
                    if is_pid_alive(pid as u32) {
                        return (false, format!("SUPERVISOR_PID_{}_ALIVE", pid));
                    }
                }
            }
        }
    }
    
    // 2) No live PIDs found - check file activity threshold (120 seconds)
    let stale_threshold_secs = 120;
    if !is_run_dir_stale_secs(run_dir, stale_threshold_secs) {
        return (false, format!("RECENT_ACTIVITY_WITHIN_{}s", stale_threshold_secs));
    }
    
    // 3) Run has no live PIDs and no recent activity - it's dead
    (true, "PROCESS_DIED_NO_ACTIVITY".to_string())
}

/// Check if a process with given PID is alive
#[cfg(windows)]
fn is_pid_alive(pid: u32) -> bool {
    use std::ptr::null_mut;
    
    // OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
    let handle = unsafe {
        winapi::um::processthreadsapi::OpenProcess(0x1000, 0, pid)
    };
    
    if handle.is_null() {
        return false;
    }
    
    // Check if process is still running
    let mut exit_code: u32 = 0;
    let result = unsafe {
        winapi::um::processthreadsapi::GetExitCodeProcess(handle, &mut exit_code)
    };
    
    unsafe { winapi::um::handleapi::CloseHandle(handle) };
    
    // STILL_ACTIVE = 259
    result != 0 && exit_code == 259
}

#[cfg(not(windows))]
fn is_pid_alive(pid: u32) -> bool {
    // On Unix, send signal 0 to check if process exists
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// Update run_meta.json with status, reason, and optional compile_status
fn update_run_meta_status(run_dir: &str, status: &str, reason: &str, compile_status: Option<&str>) {
    use std::path::Path;
    
    let meta_path = Path::new(run_dir).join("run_meta.json");
    if !meta_path.exists() {
        tracing::debug!("No run_meta.json to update at {:?}", meta_path);
        return;
    }
    
    // Read existing meta
    let content = match std::fs::read_to_string(&meta_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to read run_meta.json: {}", e);
            return;
        }
    };
    
    // Parse as JSON and update
    let mut meta: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Failed to parse run_meta.json: {}", e);
            return;
        }
    };
    
    if let Some(obj) = meta.as_object_mut() {
        obj.insert("status".to_string(), serde_json::Value::String(status.to_string()));
        obj.insert("abandoned_reason".to_string(), serde_json::Value::String(reason.to_string()));
        obj.insert("stopped_at".to_string(), serde_json::Value::String(chrono::Utc::now().to_rfc3339()));
        
        // S6 FIX: Persist compile_status in run_meta.json
        if let Some(cs) = compile_status {
            obj.insert("compile_status".to_string(), serde_json::Value::String(cs.to_string()));
        }
    }
    
    // Write back
    if let Err(e) = std::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap_or_default()) {
        tracing::warn!("Failed to write updated run_meta.json: {}", e);
    } else {
        tracing::debug!("Updated run_meta.json: status={}, reason={}, compile_status={:?}", status, reason, compile_status);
    }
}

/// Check if a run directory is stale (no recent file activity within threshold seconds)
fn is_run_dir_stale_secs(run_dir: &str, threshold_secs: u64) -> bool {
    use std::path::Path;
    use std::time::{Duration, SystemTime};
    
    let path = Path::new(run_dir);
    if !path.exists() {
        return true;
    }
    
    let stale_threshold = Duration::from_secs(threshold_secs);
    let now = SystemTime::now();
    
    // Check key files that would be updated during an active run
    let key_files = [
        "workbench.db",
        "run_meta.json",
        "checkpoint.json",
        "locald_checkpoint.json",
    ];
    
    for filename in &key_files {
        let file_path = path.join(filename);
        if let Ok(metadata) = std::fs::metadata(&file_path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(elapsed) = now.duration_since(modified) {
                    if elapsed < stale_threshold {
                        return false; // Recent activity found
                    }
                }
            }
        }
    }
    
    // Check segments directory for recent files
    let segments_dir = path.join("segments");
    if segments_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&segments_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(elapsed) = now.duration_since(modified) {
                            if elapsed < stale_threshold {
                                return false; // Recent segment activity
                            }
                        }
                    }
                }
            }
        }
    }
    
    true // No recent activity
}

/// Check if a run directory appears stale (no recent file activity)
/// Returns true if the directory doesn't exist OR has no files modified in last 5 minutes
#[allow(dead_code)]
fn is_run_dir_stale(run_dir: &str) -> bool {
    is_run_dir_stale_secs(run_dir, 5 * 60)
}

impl Database {
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
                   (signal_id, run_id, signal_type, severity, host, ts, ts_start, ts_end,
                    proc_key, file_key, identity_key, detector_id, detector_version,
                    source_sensor, metadata, evidence_ptrs, dropped_evidence_count, created_at)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)"#,
                params![
                    signal.signal_id,
                    signal.run_id,
                    signal.signal_type,
                    signal.severity,
                    signal.host,
                    signal.ts,
                    signal.ts_start,
                    signal.ts_end,
                    signal.proc_key,
                    signal.file_key,
                    signal.identity_key,
                    signal.detector_id,
                    signal.detector_version,
                    signal.source_sensor,
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
            "SELECT signal_id, run_id, signal_type, severity, host, ts, ts_start, ts_end, 
                    proc_key, file_key, identity_key, detector_id, detector_version, source_sensor,
                    metadata, evidence_ptrs, dropped_evidence_count
             FROM signals WHERE signal_id = ?1"
        )?;

        let mut rows = stmt.query(params![signal_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Self::row_to_signal(row)?))
        } else {
            Ok(None)
        }
    }

    /// Get signal explanation by signal ID
    pub fn get_signal_explanation(
        &self,
        signal_id: &str,
    ) -> Result<Option<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        // First ensure the table exists (for backwards compatibility)
        let _ = conn.execute(
            "CREATE TABLE IF NOT EXISTS signal_explanations (
                signal_id TEXT PRIMARY KEY,
                explanation_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
            [],
        );

        let mut stmt =
            conn.prepare("SELECT explanation_json FROM signal_explanations WHERE signal_id = ?1")?;

        let mut rows = stmt.query(params![signal_id])?;
        if let Some(row) = rows.next()? {
            let json_str: String = row.get(0)?;
            match serde_json::from_str(&json_str) {
                Ok(json) => Ok(Some(json)),
                Err(e) => {
                    tracing::warn!("Failed to parse explanation JSON for {}: {}", signal_id, e);
                    Ok(Some(serde_json::json!({
                        "error": "Failed to parse stored explanation",
                        "raw": json_str
                    })))
                }
            }
        } else {
            Ok(None)
        }
    }

    /// List recent signals with optional filters
    pub fn list_signals(
        &self,
        run_id: Option<&str>,
        host: Option<&str>,
        signal_type: Option<&str>,
        severity: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredSignal>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        let mut sql = String::from(
            "SELECT signal_id, run_id, signal_type, severity, host, ts, ts_start, ts_end,
                    proc_key, file_key, identity_key, detector_id, detector_version, source_sensor,
                    metadata, evidence_ptrs, dropped_evidence_count
             FROM signals WHERE 1=1"
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(r) = run_id {
            sql.push_str(" AND run_id = ?");
            params_vec.push(Box::new(r.to_string()));
        }
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

        sql.push_str(" ORDER BY ts DESC LIMIT ? OFFSET ?");
        params_vec.push(Box::new(limit as i64));
        params_vec.push(Box::new(offset as i64));

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

    // ==========================================================================
    // Run Record Operations
    // ==========================================================================

    /// Insert a new run record (called when a run starts)
    pub fn insert_run(&self, run: &RunRecord) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        
        // Serialize chain_ids as JSON if present
        let chain_ids_json = run.chain_ids.as_ref().map(|ids| serde_json::to_string(ids).unwrap_or_default());
        
        conn.execute(
            r#"INSERT OR REPLACE INTO runs 
               (run_id, name, profile, started_at, stopped_at, run_dir, 
                events_total, segments_count, facts_extracted, signals_fired, bytes_written,
                status, baseline_scope, baseline_enabled, baseline_set_at, chain_ids, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)"#,
            params![
                run.run_id,
                run.name,
                run.profile,
                run.started_at,
                run.stopped_at,
                run.run_dir,
                run.events_total as i64,
                run.segments_count as i64,
                run.facts_extracted as i64,
                run.signals_fired as i64,
                run.bytes_written as i64,
                run.status,
                run.baseline_scope,
                if run.baseline_enabled { 1 } else { 0 },
                run.baseline_set_at,
                chain_ids_json,
                now
            ],
        )?;
        Ok(())
    }

    /// Update run record on stop (with final metrics)
    pub fn finalize_run(&self, run_id: &str, stopped_at: &str, metrics: &RunMetrics) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            r#"UPDATE runs SET 
                stopped_at = ?2,
                events_total = ?3,
                segments_count = ?4,
                facts_extracted = ?5,
                signals_fired = ?6,
                bytes_written = ?7,
                status = 'stopped'
               WHERE run_id = ?1"#,
            params![
                run_id,
                stopped_at,
                metrics.events_total as i64,
                metrics.segments_count as i64,
                metrics.facts_extracted as i64,
                metrics.signals_fired as i64,
                metrics.bytes_written as i64,
            ],
        )?;
        Ok(())
    }

    /// List all runs (newest first)
    pub fn list_runs(&self, limit: usize) -> Result<Vec<RunRecord>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT run_id, name, profile, started_at, stopped_at, run_dir,
                      events_total, segments_count, facts_extracted, signals_fired, bytes_written,
                      status, baseline_scope, baseline_enabled, baseline_set_at, chain_ids
               FROM runs 
               ORDER BY started_at DESC 
               LIMIT ?1"#
        )?;
        
        let mut rows = stmt.query(params![limit as i64])?;
        let mut runs = Vec::new();
        
        while let Some(row) = rows.next()? {
            // Deserialize chain_ids from JSON string
            let chain_ids_json: Option<String> = row.get(15)?;
            let chain_ids: Option<Vec<String>> = chain_ids_json.and_then(|s| serde_json::from_str(&s).ok());
            
            runs.push(RunRecord {
                run_id: row.get(0)?,
                name: row.get(1)?,
                profile: row.get(2)?,
                started_at: row.get(3)?,
                stopped_at: row.get(4)?,
                run_dir: row.get(5)?,
                events_total: row.get::<_, i64>(6)? as u64,
                segments_count: row.get::<_, i64>(7)? as u32,
                facts_extracted: row.get::<_, i64>(8)? as u64,
                signals_fired: row.get::<_, i64>(9)? as u64,
                bytes_written: row.get::<_, i64>(10)? as u64,
                status: row.get(11)?,
                baseline_scope: row.get(12)?,
                baseline_enabled: row.get::<_, i64>(13).unwrap_or(0) != 0,
                baseline_set_at: row.get(14)?,
                chain_ids,
            });
        }
        Ok(runs)
    }

    /// Get a single run by ID
    pub fn get_run(&self, run_id: &str) -> Result<Option<RunRecord>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT run_id, name, profile, started_at, stopped_at, run_dir,
                      events_total, segments_count, facts_extracted, signals_fired, bytes_written,
                      status, baseline_scope, baseline_enabled, baseline_set_at, chain_ids
               FROM runs WHERE run_id = ?1"#
        )?;
        
        let mut rows = stmt.query(params![run_id])?;
        if let Some(row) = rows.next()? {
            // Deserialize chain_ids from JSON string
            let chain_ids_json: Option<String> = row.get(15)?;
            let chain_ids: Option<Vec<String>> = chain_ids_json.and_then(|s| serde_json::from_str(&s).ok());
            
            Ok(Some(RunRecord {
                run_id: row.get(0)?,
                name: row.get(1)?,
                profile: row.get(2)?,
                started_at: row.get(3)?,
                stopped_at: row.get(4)?,
                run_dir: row.get(5)?,
                events_total: row.get::<_, i64>(6)? as u64,
                segments_count: row.get::<_, i64>(7)? as u32,
                facts_extracted: row.get::<_, i64>(8)? as u64,
                signals_fired: row.get::<_, i64>(9)? as u64,
                bytes_written: row.get::<_, i64>(10)? as u64,
                status: row.get(11)?,
                baseline_scope: row.get(12)?,
                baseline_enabled: row.get::<_, i64>(13).unwrap_or(0) != 0,
                baseline_set_at: row.get(14)?,
                chain_ids,
            }))
        } else {
            Ok(None)
        }
    }

    /// Set a run as baseline (transactional: clears other defaults for same scope)
    pub fn set_baseline(&self, run_id: &str, scope: &str, set_as_default: bool) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        
        // If setting as default, first clear existing defaults for this scope
        if set_as_default {
            conn.execute(
                "UPDATE runs SET baseline_enabled = 0 WHERE baseline_scope = ?1 AND baseline_enabled = 1",
                params![scope],
            )?;
        }
        
        // Set this run as baseline
        let rows_affected = conn.execute(
            "UPDATE runs SET baseline_scope = ?2, baseline_enabled = ?3, baseline_set_at = ?4 WHERE run_id = ?1",
            params![run_id, scope, if set_as_default { 1 } else { 0 }, now],
        )?;
        
        Ok(rows_affected > 0)
    }

    /// Get the default baseline for a scope
    pub fn get_default_baseline(&self, scope: &str) -> Result<Option<RunRecord>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT run_id, name, profile, started_at, stopped_at, run_dir,
                      events_total, segments_count, facts_extracted, signals_fired, bytes_written,
                      status, baseline_scope, baseline_enabled, baseline_set_at
               FROM runs WHERE baseline_scope = ?1 AND baseline_enabled = 1 LIMIT 1"#
        )?;
        
        let mut rows = stmt.query(params![scope])?;
        if let Some(row) = rows.next()? {
            Ok(Some(RunRecord {
                run_id: row.get(0)?,
                name: row.get(1)?,
                profile: row.get(2)?,
                started_at: row.get(3)?,
                stopped_at: row.get(4)?,
                run_dir: row.get(5)?,
                events_total: row.get::<_, i64>(6)? as u64,
                segments_count: row.get::<_, i64>(7)? as u32,
                facts_extracted: row.get::<_, i64>(8)? as u64,
                signals_fired: row.get::<_, i64>(9)? as u64,
                bytes_written: row.get::<_, i64>(10)? as u64,
                status: row.get(11)?,
                baseline_scope: row.get(12)?,
                baseline_enabled: row.get::<_, i64>(13).unwrap_or(0) != 0,
                baseline_set_at: row.get(14)?,
                chain_ids: None,
            }))
        } else {
            Ok(None)
        }
    }

    /// List all baseline runs
    pub fn list_baselines(&self) -> Result<Vec<RunRecord>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT run_id, name, profile, started_at, stopped_at, run_dir,
                      events_total, segments_count, facts_extracted, signals_fired, bytes_written,
                      status, baseline_scope, baseline_enabled, baseline_set_at
               FROM runs WHERE baseline_scope IS NOT NULL ORDER BY baseline_set_at DESC"#
        )?;
        
        let mut baselines = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            baselines.push(RunRecord {
                run_id: row.get(0)?,
                name: row.get(1)?,
                profile: row.get(2)?,
                started_at: row.get(3)?,
                stopped_at: row.get(4)?,
                run_dir: row.get(5)?,
                events_total: row.get::<_, i64>(6)? as u64,
                segments_count: row.get::<_, i64>(7)? as u32,
                facts_extracted: row.get::<_, i64>(8)? as u64,
                signals_fired: row.get::<_, i64>(9)? as u64,
                bytes_written: row.get::<_, i64>(10)? as u64,
                status: row.get(11)?,
                baseline_scope: row.get(12)?,
                baseline_enabled: row.get::<_, i64>(13).unwrap_or(0) != 0,
                baseline_set_at: row.get(14)?,
                chain_ids: None,
            });
        }
        Ok(baselines)
    }

    /// Remove baseline marking from a run
    pub fn unset_baseline(&self, run_id: &str) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let rows_affected = conn.execute(
            "UPDATE runs SET baseline_scope = NULL, baseline_enabled = 0, baseline_set_at = NULL WHERE run_id = ?1",
            params![run_id],
        )?;
        Ok(rows_affected > 0)
    }

    /// Rename a run (set user-friendly name)
    pub fn rename_run(&self, run_id: &str, name: Option<&str>) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let rows_affected = conn.execute(
            "UPDATE runs SET name = ?2 WHERE run_id = ?1",
            params![run_id, name],
        )?;
        Ok(rows_affected > 0)
    }

    /// Backfill run_dir for a run (used when resolving legacy runs with NULL run_dir)
    pub fn backfill_run_dir(&self, run_id: &str, run_dir: &str) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        // Only update if run_dir is currently NULL
        let rows_affected = conn.execute(
            "UPDATE runs SET run_dir = ?2 WHERE run_id = ?1 AND run_dir IS NULL",
            params![run_id, run_dir],
        )?;
        Ok(rows_affected > 0)
    }

    /// Delete a run record
    pub fn delete_run(&self, run_id: &str) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let rows_affected = conn.execute(
            "DELETE FROM runs WHERE run_id = ?1",
            params![run_id],
        )?;
        Ok(rows_affected > 0)
    }

    // ==========================================================================
    // Narrative Operations
    // ==========================================================================

    /// Save a narrative document
    pub fn save_narrative(
        &self,
        narrative_json: &serde_json::Value,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        let narrative_id = narrative_json
            .get("narrative_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let signal_id = narrative_json
            .get("signal_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let version = narrative_json
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as i64;
        let input_hash = narrative_json
            .get("input_hash")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let json_str = serde_json::to_string(narrative_json).unwrap_or_default();
        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            r#"INSERT OR REPLACE INTO narratives 
               (narrative_id, signal_id, version, narrative_json, input_hash, generated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
            params![narrative_id, signal_id, version, json_str, input_hash, now],
        )?;
        Ok(())
    }

    /// Get narrative by signal ID (latest version)
    pub fn get_narrative(
        &self,
        signal_id: &str,
    ) -> Result<Option<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT narrative_json FROM narratives WHERE signal_id = ?1 ORDER BY version DESC LIMIT 1"
        )?;

        let mut rows = stmt.query(params![signal_id])?;
        if let Some(row) = rows.next()? {
            let json_str: String = row.get(0)?;
            match serde_json::from_str(&json_str) {
                Ok(json) => Ok(Some(json)),
                Err(e) => {
                    tracing::warn!("Failed to parse narrative JSON for {}: {}", signal_id, e);
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Get narrative by ID
    pub fn get_narrative_by_id(
        &self,
        narrative_id: &str,
    ) -> Result<Option<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT narrative_json FROM narratives WHERE narrative_id = ?1")?;

        let mut rows = stmt.query(params![narrative_id])?;
        if let Some(row) = rows.next()? {
            let json_str: String = row.get(0)?;
            match serde_json::from_str(&json_str) {
                Ok(json) => Ok(Some(json)),
                Err(_) => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    // ==========================================================================
    // Mission Spec Operations
    // ==========================================================================

    /// Save a mission spec
    pub fn save_mission_spec(&self, spec: &serde_json::Value) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        let mission_id = spec
            .get("mission_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let name = spec
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let objective = spec
            .get("objective")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let json_str = serde_json::to_string(spec).unwrap_or_default();
        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            r#"INSERT OR REPLACE INTO mission_specs 
               (mission_id, name, objective, spec_json, is_active, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)"#,
            params![mission_id, name, objective, json_str, now],
        )?;
        Ok(())
    }

    /// Get active mission spec (if any)
    pub fn get_active_mission_spec(&self) -> Result<Option<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT spec_json FROM mission_specs WHERE is_active = 1 LIMIT 1")?;

        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let json_str: String = row.get(0)?;
            match serde_json::from_str(&json_str) {
                Ok(json) => Ok(Some(json)),
                Err(_) => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    /// Set active mission spec
    pub fn set_active_mission(&self, mission_id: &str) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        // Deactivate all
        conn.execute("UPDATE mission_specs SET is_active = 0", [])?;

        // Activate the specified one
        let count = conn.execute(
            "UPDATE mission_specs SET is_active = 1, updated_at = ?1 WHERE mission_id = ?2",
            params![chrono::Utc::now().to_rfc3339(), mission_id],
        )?;

        Ok(count > 0)
    }

    /// Clear active mission (switch to discovery mode)
    pub fn clear_active_mission(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE mission_specs SET is_active = 0", [])?;
        Ok(())
    }

    /// List all mission specs
    pub fn list_mission_specs(&self) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT spec_json FROM mission_specs ORDER BY updated_at DESC")?;

        let mut rows = stmt.query([])?;
        let mut specs = Vec::new();
        while let Some(row) = rows.next()? {
            let json_str: String = row.get(0)?;
            if let Ok(json) = serde_json::from_str(&json_str) {
                specs.push(json);
            }
        }
        Ok(specs)
    }

    /// Get mission spec by ID
    pub fn get_mission_spec(
        &self,
        mission_id: &str,
    ) -> Result<Option<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT spec_json FROM mission_specs WHERE mission_id = ?1")?;

        let mut rows = stmt.query(params![mission_id])?;
        if let Some(row) = rows.next()? {
            let json_str: String = row.get(0)?;
            match serde_json::from_str(&json_str) {
                Ok(json) => Ok(Some(json)),
                Err(_) => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    /// Delete mission spec
    pub fn delete_mission_spec(&self, mission_id: &str) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let count = conn.execute(
            "DELETE FROM mission_specs WHERE mission_id = ?1",
            params![mission_id],
        )?;
        Ok(count > 0)
    }

    // ==========================================================================
    // Narrative Action Operations
    // ==========================================================================

    /// Save a user action on a narrative
    pub fn save_narrative_action(
        &self,
        narrative_id: &str,
        sentence_id: Option<&str>,
        evidence_ptr: Option<&serde_json::Value>,
        action_type: &str,
        notes: Option<&str>,
    ) -> Result<String, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        let action_id = format!("act_{}", uuid::Uuid::new_v4());
        let evidence_json = evidence_ptr.map(|p| serde_json::to_string(p).unwrap_or_default());
        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            r#"INSERT INTO narrative_actions 
               (action_id, narrative_id, sentence_id, evidence_ptr_json, action_type, notes, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            params![action_id, narrative_id, sentence_id, evidence_json, action_type, notes, now],
        )?;

        Ok(action_id)
    }

    /// Get actions for a narrative
    pub fn get_narrative_actions(
        &self,
        narrative_id: &str,
    ) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT action_id, sentence_id, evidence_ptr_json, action_type, notes, created_at 
               FROM narrative_actions WHERE narrative_id = ?1 ORDER BY created_at"#,
        )?;

        let mut rows = stmt.query(params![narrative_id])?;
        let mut actions = Vec::new();
        while let Some(row) = rows.next()? {
            let action_id: String = row.get(0)?;
            let sentence_id: Option<String> = row.get(1)?;
            let evidence_json: Option<String> = row.get(2)?;
            let action_type: String = row.get(3)?;
            let notes: Option<String> = row.get(4)?;
            let created_at: String = row.get(5)?;

            let evidence_ptr: Option<serde_json::Value> =
                evidence_json.and_then(|j| serde_json::from_str(&j).ok());

            actions.push(serde_json::json!({
                "action_id": action_id,
                "sentence_id": sentence_id,
                "evidence_ptr": evidence_ptr,
                "action_type": action_type,
                "notes": notes,
                "created_at": created_at,
            }));
        }
        Ok(actions)
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
}

/// Stats for a single event stream
#[derive(Debug, Clone, Default)]
pub struct StreamStats {
    pub last_seen_ts: Option<chrono::DateTime<chrono::Utc>>,
    pub event_count: u64,
}

impl Database {
    /// Get stream stats for diagnostics
    pub fn get_stream_stats(
        &self,
    ) -> Result<std::collections::HashMap<String, StreamStats>, rusqlite::Error>
    {
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

        for (signal_type, count, max_ts) in rows.flatten() {
            // Map signal types to stream IDs
            let stream_id = match signal_type.as_str() {
                "ProcessInjection" | "SuspiciousExec" | "ProcessHollowing" => "process_exec",
                "FileModification" | "SuspiciousWrite" => "file_write",
                "NetworkConnection" | "C2Communication" => "network_connect",
                "DnsQuery" => "dns_query",
                "RegistryModification" => "registry_write",
                _ => "unknown",
            };

            let entry = stats.entry(stream_id.to_string()).or_default();
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

        Ok(stats)
    }

    fn row_to_signal(row: &rusqlite::Row) -> Result<StoredSignal, rusqlite::Error> {
        let metadata_str: String = row.get(14)?;
        let evidence_str: String = row.get(15)?;

        Ok(StoredSignal {
            signal_id: row.get(0)?,
            run_id: row.get(1)?,
            signal_type: row.get(2)?,
            severity: row.get(3)?,
            host: row.get(4)?,
            ts: row.get(5)?,
            ts_start: row.get(6)?,
            ts_end: row.get(7)?,
            proc_key: row.get(8)?,
            file_key: row.get(9)?,
            identity_key: row.get(10)?,
            detector_id: row.get(11)?,
            detector_version: row.get(12)?,
            source_sensor: row.get(13)?,
            metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
            evidence_ptrs: serde_json::from_str(&evidence_str).unwrap_or_default(),
            dropped_evidence_count: row.get(16)?,
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
                run_id: "run_20241201_100000".to_string(),
                signal_type: "ProcessInjection".to_string(),
                severity: "critical".to_string(),
                host: "HOST1".to_string(),
                ts: 1000,
                ts_start: 900,
                ts_end: 1000,
                proc_key: Some("proc_123".to_string()),
                file_key: None,
                identity_key: Some("SYSTEM".to_string()),
                detector_id: "playbook:process_injection_v1".to_string(),
                detector_version: "1.0.0".to_string(),
                source_sensor: "etw:kernel".to_string(),
                metadata: serde_json::json!({"technique": "T1055"}),
                evidence_ptrs: vec![serde_json::json!({"stream_id": "s1", "segment_id": 0})],
                dropped_evidence_count: 0,
            },
            StoredSignal {
                signal_id: "sig_002".to_string(),
                run_id: "run_20241201_100000".to_string(),
                signal_type: "SuspiciousExec".to_string(),
                severity: "high".to_string(),
                host: "HOST2".to_string(),
                ts: 2000,
                ts_start: 2000,
                ts_end: 2000,
                proc_key: None,
                file_key: Some("file_abc".to_string()),
                identity_key: None,
                detector_id: "playbook:suspicious_exec_v1".to_string(),
                detector_version: "1.0.0".to_string(),
                source_sensor: "sysmon".to_string(),
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
        assert_eq!(sig.run_id, "run_20241201_100000");
        assert_eq!(sig.detector_id, "playbook:process_injection_v1");

        // List all
        let all = db.list_signals(None, None, None, None, 100, 0).unwrap();
        assert_eq!(all.len(), 2);

        // Filter by host
        let host1 = db.list_signals(None, Some("HOST1"), None, None, 100, 0).unwrap();
        assert_eq!(host1.len(), 1);

        // Filter by severity
        let critical = db.list_signals(None, None, None, Some("critical"), 100, 0).unwrap();
        assert_eq!(critical.len(), 1);
        
        // Filter by run_id
        let run_signals = db.list_signals(Some("run_20241201_100000"), None, None, None, 100, 0).unwrap();
        assert_eq!(run_signals.len(), 2);

        // Stats
        let stats = db.signal_stats().unwrap();
        assert_eq!(stats.total, 2);
        assert_eq!(*stats.by_severity.get("critical").unwrap_or(&0), 1);
    }
}
