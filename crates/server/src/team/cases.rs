//! Team Cases Service
//!
//! Handles case CRUD operations, notes, tags, and metadata.

use crate::services::types::{CaseMeta, CaseNote};
use std::path::{Path, PathBuf};

use super::store::{safe_case_path_join, CASE_STORE_SCHEMA_VERSION};

// ============================================================================
// Case ID Generation
// ============================================================================

/// Generate a unique case ID (ULID-based)
pub fn generate_case_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Encode timestamp as base32
    let ts_part = encode_base32_crockford(timestamp);

    // Add random suffix
    let random_part: String = (0..10)
        .map(|_| {
            let idx = rand_u8() as usize % 32;
            BASE32_ALPHABET.chars().nth(idx).unwrap_or('0')
        })
        .collect();

    format!("{}{}", ts_part, random_part)
}

const BASE32_ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn encode_base32_crockford(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }

    let mut chars = Vec::new();
    let alphabet: Vec<char> = BASE32_ALPHABET.chars().collect();

    while n > 0 {
        chars.push(alphabet[(n % 32) as usize]);
        n /= 32;
    }

    chars.reverse();
    chars.into_iter().collect()
}

fn rand_u8() -> u8 {
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    SystemTime::now().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    (hasher.finish() & 0xFF) as u8
}

// ============================================================================
// Case Directory Operations
// ============================================================================

/// Get case directory path (without validation)
pub fn get_case_dir(store_dir: &Path, case_id: &str) -> Option<PathBuf> {
    let cases_dir = store_dir.join("cases");
    safe_case_path_join(&cases_dir, case_id)
}

/// List all cases in store
pub fn list_cases(store_dir: &Path) -> Result<Vec<CaseMeta>, String> {
    let cases_dir = store_dir.join("cases");
    if !cases_dir.exists() {
        return Ok(vec![]);
    }

    let mut cases = Vec::new();

    for entry in std::fs::read_dir(&cases_dir).map_err(|e| format!("Failed to read cases dir: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry.path();

        if path.is_dir() {
            if let Some(case_id) = path.file_name().and_then(|n| n.to_str()) {
                if let Ok(meta) = read_case_meta(&path) {
                    cases.push(meta);
                } else {
                    // Minimal entry for cases without meta
                    cases.push(CaseMeta {
                        case_id: case_id.to_string(),
                        name: case_id.to_string(),
                        created_at: String::new(),
                        created_by: String::new(),
                        modified_at: String::new(),
                        status: "unknown".to_string(),
                        description: None,
                        tags: vec![],
                        source_runs: vec![],
                        signals_count: 0,
                    });
                }
            }
        }
    }

    // Sort by modified_at descending
    cases.sort_by(|a, b| b.modified_at.cmp(&a.modified_at));

    Ok(cases)
}

/// Read case metadata
pub fn read_case_meta(case_dir: &Path) -> Result<CaseMeta, String> {
    let meta_path = case_dir.join("case.json");
    let contents =
        std::fs::read_to_string(&meta_path).map_err(|e| format!("Failed to read case.json: {}", e))?;

    serde_json::from_str(&contents).map_err(|e| format!("Failed to parse case.json: {}", e))
}

/// Write case metadata
pub fn write_case_meta(case_dir: &Path, meta: &CaseMeta) -> Result<(), String> {
    let meta_path = case_dir.join("case.json");
    let contents =
        serde_json::to_string_pretty(meta).map_err(|e| format!("Failed to serialize case meta: {}", e))?;

    std::fs::write(&meta_path, contents).map_err(|e| format!("Failed to write case.json: {}", e))?;

    Ok(())
}

/// Create a new case
pub fn create_case(
    store_dir: &Path,
    name: &str,
    description: Option<String>,
    tags: Vec<String>,
    install_id: &str,
) -> Result<CaseMeta, String> {
    let case_id = generate_case_id();
    let cases_dir = store_dir.join("cases");

    let case_dir = safe_case_path_join(&cases_dir, &case_id)
        .ok_or_else(|| "Invalid case ID generated".to_string())?;

    std::fs::create_dir_all(&case_dir).map_err(|e| format!("Failed to create case directory: {}", e))?;

    // Create subdirectories
    std::fs::create_dir_all(case_dir.join("runs"))
        .map_err(|e| format!("Failed to create runs dir: {}", e))?;
    std::fs::create_dir_all(case_dir.join("attachments"))
        .map_err(|e| format!("Failed to create attachments dir: {}", e))?;
    std::fs::create_dir_all(case_dir.join("notes"))
        .map_err(|e| format!("Failed to create notes dir: {}", e))?;

    let now = chrono::Utc::now().to_rfc3339();

    let meta = CaseMeta {
        case_id: case_id.clone(),
        name: name.to_string(),
        created_at: now.clone(),
        created_by: install_id.to_string(),
        modified_at: now,
        status: "active".to_string(),
        description,
        tags,
        source_runs: vec![],
        signals_count: 0,
    };

    write_case_meta(&case_dir, &meta)?;

    // Write schema version
    let version_path = case_dir.join("version.json");
    let version_info = serde_json::json!({
        "schema_version": CASE_STORE_SCHEMA_VERSION,
        "created_at": &meta.created_at
    });
    std::fs::write(&version_path, serde_json::to_string_pretty(&version_info).unwrap())
        .map_err(|e| format!("Failed to write version.json: {}", e))?;

    Ok(meta)
}

/// Update case metadata
pub fn update_case(
    store_dir: &Path,
    case_id: &str,
    name: Option<String>,
    description: Option<String>,
    status: Option<String>,
    tags: Option<Vec<String>>,
) -> Result<CaseMeta, String> {
    let case_dir = get_case_dir(store_dir, case_id).ok_or_else(|| "Invalid case ID".to_string())?;

    if !case_dir.exists() {
        return Err("Case not found".to_string());
    }

    let mut meta = read_case_meta(&case_dir)?;

    if let Some(n) = name {
        meta.name = n;
    }
    if let Some(d) = description {
        meta.description = Some(d);
    }
    if let Some(s) = status {
        meta.status = s;
    }
    if let Some(t) = tags {
        meta.tags = t;
    }

    meta.modified_at = chrono::Utc::now().to_rfc3339();

    write_case_meta(&case_dir, &meta)?;

    Ok(meta)
}

/// Delete a case (moves to archive)
pub fn delete_case(store_dir: &Path, case_id: &str) -> Result<(), String> {
    let case_dir = get_case_dir(store_dir, case_id).ok_or_else(|| "Invalid case ID".to_string())?;

    if !case_dir.exists() {
        return Err("Case not found".to_string());
    }

    // Move to archive
    let archive_dir = store_dir.join("archive");
    std::fs::create_dir_all(&archive_dir).map_err(|e| format!("Failed to create archive dir: {}", e))?;

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let archive_name = format!("{}_{}", case_id, timestamp);
    let archive_path = archive_dir.join(&archive_name);

    std::fs::rename(&case_dir, &archive_path).map_err(|e| format!("Failed to archive case: {}", e))?;

    Ok(())
}

// ============================================================================
// Case Notes
// ============================================================================

/// Generate note ID
pub fn generate_note_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    format!("note_{:016x}", timestamp)
}

/// List notes for a case
pub fn list_notes(case_dir: &Path) -> Result<Vec<CaseNote>, String> {
    let notes_dir = case_dir.join("notes");
    if !notes_dir.exists() {
        return Ok(vec![]);
    }

    let mut notes = Vec::new();

    for entry in std::fs::read_dir(&notes_dir).map_err(|e| format!("Failed to read notes dir: {}", e))? {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry.path();

        if path.extension().map(|e| e == "json").unwrap_or(false) {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(note) = serde_json::from_str::<CaseNote>(&contents) {
                    notes.push(note);
                }
            }
        }
    }

    // Sort by created_at ascending
    notes.sort_by(|a, b| a.created_at.cmp(&b.created_at));

    Ok(notes)
}

/// Add a note to a case
pub fn add_note(
    case_dir: &Path,
    content: &str,
    author: &str,
    signal_id: Option<&str>,
) -> Result<CaseNote, String> {
    let notes_dir = case_dir.join("notes");
    std::fs::create_dir_all(&notes_dir).map_err(|e| format!("Failed to create notes dir: {}", e))?;

    let note_id = generate_note_id();
    let now = chrono::Utc::now().to_rfc3339();

    let note = CaseNote {
        note_id: note_id.clone(),
        created_at: now.clone(),
        modified_at: now,
        author: author.to_string(),
        content: content.to_string(),
        signal_id: signal_id.map(|s| s.to_string()),
    };

    let note_path = notes_dir.join(format!("{}.json", note_id));
    let contents =
        serde_json::to_string_pretty(&note).map_err(|e| format!("Failed to serialize note: {}", e))?;

    std::fs::write(&note_path, contents).map_err(|e| format!("Failed to write note: {}", e))?;

    Ok(note)
}

/// Update a note
pub fn update_note(case_dir: &Path, note_id: &str, content: &str) -> Result<CaseNote, String> {
    let notes_dir = case_dir.join("notes");
    let note_path = notes_dir.join(format!("{}.json", note_id));

    if !note_path.exists() {
        return Err("Note not found".to_string());
    }

    let contents = std::fs::read_to_string(&note_path).map_err(|e| format!("Failed to read note: {}", e))?;

    let mut note: CaseNote =
        serde_json::from_str(&contents).map_err(|e| format!("Failed to parse note: {}", e))?;

    note.content = content.to_string();
    note.modified_at = chrono::Utc::now().to_rfc3339();

    let updated =
        serde_json::to_string_pretty(&note).map_err(|e| format!("Failed to serialize note: {}", e))?;

    std::fs::write(&note_path, updated).map_err(|e| format!("Failed to write note: {}", e))?;

    Ok(note)
}

/// Delete a note
pub fn delete_note(case_dir: &Path, note_id: &str) -> Result<(), String> {
    let notes_dir = case_dir.join("notes");
    let note_path = notes_dir.join(format!("{}.json", note_id));

    if !note_path.exists() {
        return Err("Note not found".to_string());
    }

    std::fs::remove_file(&note_path).map_err(|e| format!("Failed to delete note: {}", e))?;

    Ok(())
}

// ============================================================================
// Case Tags
// ============================================================================

/// Add tags to a case (deduplicates)
pub fn add_tags(case_dir: &Path, new_tags: &[String]) -> Result<Vec<String>, String> {
    let mut meta = read_case_meta(case_dir)?;

    for tag in new_tags {
        let normalized = tag.trim().to_lowercase();
        if !normalized.is_empty() && !meta.tags.contains(&normalized) {
            meta.tags.push(normalized);
        }
    }

    meta.modified_at = chrono::Utc::now().to_rfc3339();
    write_case_meta(case_dir, &meta)?;

    Ok(meta.tags)
}

/// Remove tags from a case
pub fn remove_tags(case_dir: &Path, tags_to_remove: &[String]) -> Result<Vec<String>, String> {
    let mut meta = read_case_meta(case_dir)?;

    let remove_set: std::collections::HashSet<_> =
        tags_to_remove.iter().map(|t| t.trim().to_lowercase()).collect();

    meta.tags.retain(|t| !remove_set.contains(t));

    meta.modified_at = chrono::Utc::now().to_rfc3339();
    write_case_meta(case_dir, &meta)?;

    Ok(meta.tags)
}

// ============================================================================
// Case Source Runs
// ============================================================================

/// Add a source run reference to a case
pub fn add_source_run(case_dir: &Path, run_id: &str) -> Result<(), String> {
    let mut meta = read_case_meta(case_dir)?;

    if !meta.source_runs.iter().any(|r: &String| r == run_id) {
        meta.source_runs.push(run_id.to_string());
        meta.modified_at = chrono::Utc::now().to_rfc3339();
        write_case_meta(case_dir, &meta)?;
    }

    Ok(())
}

/// Get signals count from case database
pub fn get_case_signals_count(case_dir: &Path) -> usize {
    let db_path = case_dir.join("signals.db");
    if !db_path.exists() {
        return 0;
    }

    if let Ok(conn) = rusqlite::Connection::open(&db_path) {
        if let Ok(count) = conn.query_row("SELECT COUNT(*) FROM signals", [], |row| row.get::<_, i64>(0)) {
            return count as usize;
        }
    }

    0
}

/// Update signals count in case meta
pub fn update_signals_count(case_dir: &Path) -> Result<usize, String> {
    let count = get_case_signals_count(case_dir);

    let mut meta = read_case_meta(case_dir)?;
    meta.signals_count = count;
    meta.modified_at = chrono::Utc::now().to_rfc3339();
    write_case_meta(case_dir, &meta)?;

    Ok(count)
}
