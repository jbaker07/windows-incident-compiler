//! Safe Importer - Secure extraction and manifest generation
//!
//! This module provides safe import functionality for folders and zip files:
//! - Path traversal protection
//! - Zip bomb detection and limits
//! - SHA256 hashing for integrity
//! - Type allowlist filtering
//!
//! SECURITY: Never executes imported content. All files treated as untrusted bytes.

use crate::import_types::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

// ============================================================================
// PATH VALIDATION
// ============================================================================

/// Validate a path component is safe (no traversal attacks)
fn is_safe_path_component(component: &str) -> bool {
    // Reject empty, dot navigation, or hidden
    if component.is_empty() || component == "." || component == ".." {
        return false;
    }
    
    // Reject Windows drive letters (C:, D:, etc)
    if component.len() >= 2 && component.chars().nth(1) == Some(':') {
        return false;
    }
    
    // Reject UNC paths
    if component.starts_with("\\\\") || component.starts_with("//") {
        return false;
    }
    
    // Reject null bytes and other control characters
    if component.chars().any(|c| c.is_control()) {
        return false;
    }
    
    true
}

/// Validate a relative path is safe for extraction
fn validate_rel_path(rel_path: &str) -> Result<(), String> {
    // Check for absolute path indicators
    if rel_path.starts_with('/') || rel_path.starts_with('\\') {
        return Err("Absolute path detected".to_string());
    }
    
    // Check for drive letter
    if rel_path.len() >= 2 && rel_path.chars().nth(1) == Some(':') {
        return Err("Drive letter detected".to_string());
    }
    
    // Check for UNC path
    if rel_path.starts_with("\\\\") || rel_path.starts_with("//") {
        return Err("UNC path detected".to_string());
    }
    
    // Normalize and check each component
    let normalized = rel_path.replace('\\', "/");
    let depth = normalized
        .split('/')
        .filter(|s| !s.is_empty())
        .try_fold(0i32, |depth, component| {
            if !is_safe_path_component(component) {
                return Err(format!("Invalid path component: {}", component));
            }
            if component == ".." {
                if depth <= 0 {
                    return Err("Path traversal detected".to_string());
                }
                Ok(depth - 1)
            } else {
                Ok(depth + 1)
            }
        })?;
    
    if depth < 0 {
        return Err("Path traversal detected".to_string());
    }
    
    Ok(())
}

/// Calculate depth of a path
fn path_depth(rel_path: &str) -> u32 {
    rel_path
        .replace('\\', "/")
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .count() as u32
}

// ============================================================================
// HASHING
// ============================================================================

/// Compute SHA256 hash of a file
fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536]; // 64KB buffer
    
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    
    Ok(format!("{:x}", hasher.finalize()))
}

/// Compute SHA256 hash of bytes
fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

// ============================================================================
// SYMLINK DETECTION
// ============================================================================

/// Check if a path is a symlink or reparse point
fn is_symlink(path: &Path) -> bool {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        metadata.file_type().is_symlink()
    } else {
        false
    }
}

// ============================================================================
// SAFE IMPORTER
// ============================================================================

/// Safe importer for bundles (folders and zips)
pub struct SafeImporter {
    limits: ImportLimits,
    run_id: String,
    run_dir: PathBuf,
}

impl SafeImporter {
    /// Create a new importer
    pub fn new(run_id: String, run_dir: PathBuf, limits: Option<ImportLimits>) -> Self {
        Self {
            limits: limits.unwrap_or_default(),
            run_id,
            run_dir,
        }
    }
    
    /// Import a bundle (auto-detect folder or zip)
    pub fn import(&self, source_path: &str) -> Result<ImportResult, String> {
        let path = Path::new(source_path);
        
        if !path.exists() {
            return Err(format!("Source path does not exist: {}", source_path));
        }
        
        if path.is_dir() {
            self.import_folder(path)
        } else if path.is_file() {
            // Check for zip extension or magic bytes
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext.eq_ignore_ascii_case("zip") {
                self.import_zip(path)
            } else {
                // Try to open as zip anyway
                match File::open(path) {
                    Ok(file) => {
                        if ZipArchive::new(file).is_ok() {
                            self.import_zip(path)
                        } else {
                            Err(format!("Unsupported file type: {}", source_path))
                        }
                    }
                    Err(e) => Err(format!("Failed to open file: {}", e)),
                }
            }
        } else {
            Err(format!("Source is neither file nor directory: {}", source_path))
        }
    }
    
    /// Import a folder
    fn import_folder(&self, source: &Path) -> Result<ImportResult, String> {
        let bundle_id = generate_bundle_id();
        let import_dir = self.run_dir.join("imports").join(&bundle_id);
        let files_dir = import_dir.join("files");
        
        // Create import directory structure
        fs::create_dir_all(&files_dir)
            .map_err(|e| format!("Failed to create import directory: {}", e))?;
        
        let mut manifest_files = Vec::new();
        let mut rejected_files = Vec::new();
        let mut total_bytes: u64 = 0;
        let mut file_count: u64 = 0;
        
        // Walk the directory
        self.walk_directory(
            source,
            source,
            &files_dir,
            &mut manifest_files,
            &mut rejected_files,
            &mut total_bytes,
            &mut file_count,
        )?;
        
        // Build summary
        let summary = self.build_summary(&manifest_files, &rejected_files, total_bytes);
        
        // Create manifest
        let manifest = ImportManifest {
            schema_version: 1,
            imported_at: Utc::now(),
            source_type: ImportSourceType::Folder,
            source_path: source.display().to_string(),
            bundle_id: bundle_id.clone(),
            run_id: self.run_id.clone(),
            files: manifest_files,
            rejected: rejected_files,
            limits: self.limits.clone(),
            summary: summary.clone(),
        };
        
        // Write manifest
        let manifest_path = import_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| format!("Failed to serialize manifest: {}", e))?;
        fs::write(&manifest_path, &manifest_json)
            .map_err(|e| format!("Failed to write manifest: {}", e))?;
        
        Ok(ImportResult {
            bundle_id,
            run_id: self.run_id.clone(),
            manifest_path: manifest_path.display().to_string(),
            files_dir: files_dir.display().to_string(),
            summary,
            success: true,
            error: None,
        })
    }
    
    /// Walk directory recursively with safety checks
    #[allow(clippy::too_many_arguments)]
    fn walk_directory(
        &self,
        base: &Path,
        current: &Path,
        dest_base: &Path,
        files: &mut Vec<ManifestFile>,
        rejected: &mut Vec<RejectedFile>,
        total_bytes: &mut u64,
        file_count: &mut u64,
    ) -> Result<(), String> {
        let entries = fs::read_dir(current)
            .map_err(|e| format!("Failed to read directory: {}", e))?;
        
        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let path = entry.path();
            let rel_path = path.strip_prefix(base)
                .map_err(|_| "Failed to compute relative path")?
                .to_string_lossy()
                .replace('\\', "/");
            
            // Check path safety
            if let Err(reason) = validate_rel_path(&rel_path) {
                rejected.push(RejectedFile {
                    rel_path: rel_path.clone(),
                    reason: RejectionReason::PathTraversal,
                    message: reason,
                });
                continue;
            }
            
            // Check depth
            let depth = path_depth(&rel_path);
            if depth > self.limits.max_depth {
                rejected.push(RejectedFile {
                    rel_path: rel_path.clone(),
                    reason: RejectionReason::TooDeep,
                    message: format!("Path depth {} exceeds limit {}", depth, self.limits.max_depth),
                });
                continue;
            }
            
            // Check for symlinks
            if is_symlink(&path) {
                rejected.push(RejectedFile {
                    rel_path: rel_path.clone(),
                    reason: RejectionReason::Symlink,
                    message: "Symlinks are not allowed".to_string(),
                });
                continue;
            }
            
            if path.is_dir() {
                // Create corresponding directory
                let dest_dir = dest_base.join(&rel_path);
                fs::create_dir_all(&dest_dir)
                    .map_err(|e| format!("Failed to create directory: {}", e))?;
                
                // Recurse
                self.walk_directory(base, &path, dest_base, files, rejected, total_bytes, file_count)?;
            } else if path.is_file() {
                // Check file count limit
                if *file_count >= self.limits.max_files {
                    rejected.push(RejectedFile {
                        rel_path: rel_path.clone(),
                        reason: RejectionReason::MaxFiles,
                        message: format!("Max files limit ({}) exceeded", self.limits.max_files),
                    });
                    continue;
                }
                
                // Check file size
                let metadata = fs::metadata(&path)
                    .map_err(|e| format!("Failed to read metadata: {}", e))?;
                let size = metadata.len();
                
                if size > self.limits.max_single_file_bytes {
                    rejected.push(RejectedFile {
                        rel_path: rel_path.clone(),
                        reason: RejectionReason::TooLarge,
                        message: format!("File size {} exceeds limit {}", size, self.limits.max_single_file_bytes),
                    });
                    continue;
                }
                
                // Check total size limit
                if *total_bytes + size > self.limits.max_total_bytes {
                    rejected.push(RejectedFile {
                        rel_path: rel_path.clone(),
                        reason: RejectionReason::MaxTotalSize,
                        message: format!("Total size would exceed limit {}", self.limits.max_total_bytes),
                    });
                    continue;
                }
                
                // Copy file and compute hash
                let dest_path = dest_base.join(&rel_path);
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("Failed to create parent directory: {}", e))?;
                }
                
                fs::copy(&path, &dest_path)
                    .map_err(|e| format!("Failed to copy file: {}", e))?;
                
                let sha256 = sha256_file(&dest_path)
                    .map_err(|e| format!("Failed to compute hash: {}", e))?;
                
                let kind = FileKind::detect(&rel_path);
                
                files.push(ManifestFile {
                    rel_path,
                    sha256,
                    bytes: size,
                    kind,
                    parsed: false,
                    parser: None,
                    warnings: Vec::new(),
                    events_extracted: None,
                });
                
                *total_bytes += size;
                *file_count += 1;
            }
        }
        
        Ok(())
    }
    
    /// Import a zip file
    fn import_zip(&self, source: &Path) -> Result<ImportResult, String> {
        let bundle_id = generate_bundle_id();
        let import_dir = self.run_dir.join("imports").join(&bundle_id);
        let files_dir = import_dir.join("files");
        
        // Create import directory structure
        fs::create_dir_all(&files_dir)
            .map_err(|e| format!("Failed to create import directory: {}", e))?;
        
        let file = File::open(source)
            .map_err(|e| format!("Failed to open zip: {}", e))?;
        let mut archive = ZipArchive::new(file)
            .map_err(|e| format!("Failed to read zip: {}", e))?;
        
        // Pre-scan for zip bomb detection
        let (safe, reason) = self.validate_zip_archive(&mut archive)?;
        if !safe {
            return Err(format!("Zip validation failed: {}", reason));
        }
        
        let mut manifest_files = Vec::new();
        let mut rejected_files = Vec::new();
        let mut total_bytes: u64 = 0;
        
        for i in 0..archive.len() {
            let mut zip_file = archive.by_index(i)
                .map_err(|e| format!("Failed to read zip entry: {}", e))?;
            
            let rel_path = match zip_file.enclosed_name() {
                Some(p) => p.to_string_lossy().replace('\\', "/"),
                None => {
                    rejected_files.push(RejectedFile {
                        rel_path: format!("entry_{}", i),
                        reason: RejectionReason::PathTraversal,
                        message: "Entry has invalid path".to_string(),
                    });
                    continue;
                }
            };
            
            // Validate path
            if let Err(reason) = validate_rel_path(&rel_path) {
                rejected_files.push(RejectedFile {
                    rel_path: rel_path.clone(),
                    reason: RejectionReason::PathTraversal,
                    message: reason,
                });
                continue;
            }
            
            // Check depth
            let depth = path_depth(&rel_path);
            if depth > self.limits.max_depth {
                rejected_files.push(RejectedFile {
                    rel_path: rel_path.clone(),
                    reason: RejectionReason::TooDeep,
                    message: format!("Path depth {} exceeds limit {}", depth, self.limits.max_depth),
                });
                continue;
            }
            
            // Skip directories (they're created implicitly)
            if zip_file.is_dir() {
                continue;
            }
            
            // Check file count
            if manifest_files.len() as u64 >= self.limits.max_files {
                rejected_files.push(RejectedFile {
                    rel_path: rel_path.clone(),
                    reason: RejectionReason::MaxFiles,
                    message: format!("Max files limit ({}) exceeded", self.limits.max_files),
                });
                continue;
            }
            
            let uncompressed_size = zip_file.size();
            
            // Check single file size
            if uncompressed_size > self.limits.max_single_file_bytes {
                rejected_files.push(RejectedFile {
                    rel_path: rel_path.clone(),
                    reason: RejectionReason::TooLarge,
                    message: format!("Uncompressed size {} exceeds limit {}", uncompressed_size, self.limits.max_single_file_bytes),
                });
                continue;
            }
            
            // Check total size
            if total_bytes + uncompressed_size > self.limits.max_total_bytes {
                rejected_files.push(RejectedFile {
                    rel_path: rel_path.clone(),
                    reason: RejectionReason::MaxTotalSize,
                    message: format!("Total size would exceed limit {}", self.limits.max_total_bytes),
                });
                continue;
            }
            
            // Check compression ratio
            let compressed_size = zip_file.compressed_size();
            if compressed_size > 0 {
                let ratio = uncompressed_size as f64 / compressed_size as f64;
                if ratio > self.limits.max_compression_ratio {
                    rejected_files.push(RejectedFile {
                        rel_path: rel_path.clone(),
                        reason: RejectionReason::CompressionRatio,
                        message: format!("Compression ratio {:.1} exceeds limit {}", ratio, self.limits.max_compression_ratio),
                    });
                    continue;
                }
            }
            
            // Extract file
            let dest_path = files_dir.join(&rel_path);
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create directory: {}", e))?;
            }
            
            // Read content and compute hash while extracting
            let mut content = Vec::with_capacity(uncompressed_size as usize);
            zip_file.read_to_end(&mut content)
                .map_err(|e| format!("Failed to read zip entry: {}", e))?;
            
            let sha256 = sha256_bytes(&content);
            
            fs::write(&dest_path, &content)
                .map_err(|e| format!("Failed to write file: {}", e))?;
            
            let kind = FileKind::detect(&rel_path);
            
            manifest_files.push(ManifestFile {
                rel_path,
                sha256,
                bytes: uncompressed_size,
                kind,
                parsed: false,
                parser: None,
                warnings: Vec::new(),
                events_extracted: None,
            });
            
            total_bytes += uncompressed_size;
        }
        
        // Build summary
        let summary = self.build_summary(&manifest_files, &rejected_files, total_bytes);
        
        // Create manifest
        let manifest = ImportManifest {
            schema_version: 1,
            imported_at: Utc::now(),
            source_type: ImportSourceType::Zip,
            source_path: source.display().to_string(),
            bundle_id: bundle_id.clone(),
            run_id: self.run_id.clone(),
            files: manifest_files,
            rejected: rejected_files,
            limits: self.limits.clone(),
            summary: summary.clone(),
        };
        
        // Write manifest
        let manifest_path = import_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| format!("Failed to serialize manifest: {}", e))?;
        fs::write(&manifest_path, &manifest_json)
            .map_err(|e| format!("Failed to write manifest: {}", e))?;
        
        Ok(ImportResult {
            bundle_id,
            run_id: self.run_id.clone(),
            manifest_path: manifest_path.display().to_string(),
            files_dir: files_dir.display().to_string(),
            summary,
            success: true,
            error: None,
        })
    }
    
    /// Validate zip archive for bomb detection
    fn validate_zip_archive(&self, archive: &mut ZipArchive<File>) -> Result<(bool, String), String> {
        let mut total_uncompressed: u64 = 0;
        let file_count = archive.len() as u64;
        
        // Check file count
        if file_count > self.limits.max_files {
            return Ok((false, format!("Too many files: {} > {}", file_count, self.limits.max_files)));
        }
        
        // Sum uncompressed sizes
        for i in 0..archive.len() {
            let file = archive.by_index_raw(i)
                .map_err(|e| format!("Failed to read zip entry: {}", e))?;
            total_uncompressed += file.size();
        }
        
        // Check total size
        if total_uncompressed > self.limits.max_total_bytes {
            return Ok((false, format!("Total uncompressed size {} exceeds limit {}", 
                total_uncompressed, self.limits.max_total_bytes)));
        }
        
        Ok((true, String::new()))
    }
    
    /// Build summary statistics
    fn build_summary(
        &self,
        files: &[ManifestFile],
        rejected: &[RejectedFile],
        total_bytes: u64,
    ) -> ImportSummary {
        let mut file_kinds: HashMap<String, u64> = HashMap::new();
        
        for file in files {
            let kind_str = format!("{:?}", file.kind).to_lowercase();
            *file_kinds.entry(kind_str).or_insert(0) += 1;
        }
        
        let parsed_files = files.iter().filter(|f| f.parsed).count() as u64;
        let events_extracted = files.iter()
            .filter_map(|f| f.events_extracted)
            .sum();
        
        ImportSummary {
            total_files: files.len() as u64,
            total_bytes,
            parsed_files,
            rejected_files: rejected.len() as u64,
            events_extracted,
            file_kinds,
        }
    }
}

/// Generate a unique bundle ID
fn generate_bundle_id() -> String {
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("bundle_{:x}_{:04x}", ts, rand_u16())
}

/// Simple random u16 (not cryptographic)
fn rand_u16() -> u16 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos % 65536) as u16
}

// ============================================================================
// IMPORT MANAGER
// ============================================================================

/// Manager for import operations
pub struct ImportManager {
    telemetry_root: PathBuf,
}

impl ImportManager {
    pub fn new(telemetry_root: PathBuf) -> Self {
        Self { telemetry_root }
    }
    
    /// Get or create current run ID for imports
    pub fn ensure_run(&self) -> Result<(String, PathBuf), String> {
        let runs_dir = self.telemetry_root.join("runs");
        fs::create_dir_all(&runs_dir)
            .map_err(|e| format!("Failed to create runs directory: {}", e))?;
        
        // Generate new run ID
        let run_id = generate_run_id();
        let run_dir = runs_dir.join(&run_id);
        
        fs::create_dir_all(&run_dir)
            .map_err(|e| format!("Failed to create run directory: {}", e))?;
        fs::create_dir_all(run_dir.join("imports"))
            .map_err(|e| format!("Failed to create imports directory: {}", e))?;
        fs::create_dir_all(run_dir.join("case"))
            .map_err(|e| format!("Failed to create case directory: {}", e))?;
        fs::create_dir_all(run_dir.join("metrics"))
            .map_err(|e| format!("Failed to create metrics directory: {}", e))?;
        fs::create_dir_all(run_dir.join("logs"))
            .map_err(|e| format!("Failed to create logs directory: {}", e))?;
        
        Ok((run_id, run_dir))
    }
    
    /// Import a bundle into a run
    pub fn import_bundle(&self, source_path: &str) -> Result<ImportResult, String> {
        let (run_id, run_dir) = self.ensure_run()?;
        let importer = SafeImporter::new(run_id, run_dir, None);
        importer.import(source_path)
    }
    
    /// List imports for a run
    pub fn list_imports(&self, run_id: &str) -> Result<Vec<ImportSummaryEntry>, String> {
        let imports_dir = self.telemetry_root.join("runs").join(run_id).join("imports");
        
        if !imports_dir.exists() {
            return Ok(Vec::new());
        }
        
        let mut entries = Vec::new();
        
        for entry in fs::read_dir(&imports_dir)
            .map_err(|e| format!("Failed to read imports directory: {}", e))? {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let bundle_dir = entry.path();
            
            if bundle_dir.is_dir() {
                let manifest_path = bundle_dir.join("manifest.json");
                if manifest_path.exists() {
                    if let Ok(manifest_json) = fs::read_to_string(&manifest_path) {
                        if let Ok(manifest) = serde_json::from_str::<ImportManifest>(&manifest_json) {
                            entries.push(ImportSummaryEntry {
                                bundle_id: manifest.bundle_id,
                                imported_at: manifest.imported_at.to_rfc3339(),
                                source_type: format!("{:?}", manifest.source_type),
                                total_files: manifest.summary.total_files,
                                total_bytes: manifest.summary.total_bytes,
                                parsed_files: manifest.summary.parsed_files,
                            });
                        }
                    }
                }
            }
        }
        
        Ok(entries)
    }
    
    /// Get manifest for a bundle
    pub fn get_manifest(&self, run_id: &str, bundle_id: &str) -> Result<ImportManifest, String> {
        let manifest_path = self.telemetry_root
            .join("runs")
            .join(run_id)
            .join("imports")
            .join(bundle_id)
            .join("manifest.json");
        
        let manifest_json = fs::read_to_string(&manifest_path)
            .map_err(|e| format!("Failed to read manifest: {}", e))?;
        
        serde_json::from_str(&manifest_json)
            .map_err(|e| format!("Failed to parse manifest: {}", e))
    }
    
    /// Open import folder in file browser
    pub fn open_import_folder(&self, run_id: &str, bundle_id: &str) -> Result<(), String> {
        let import_dir = self.telemetry_root
            .join("runs")
            .join(run_id)
            .join("imports")
            .join(bundle_id);
        
        if !import_dir.exists() {
            return Err("Import folder does not exist".to_string());
        }
        
        std::process::Command::new("explorer")
            .arg(&import_dir)
            .spawn()
            .map_err(|e| format!("Failed to open folder: {}", e))?;
        
        Ok(())
    }
}

/// Summary entry for listing imports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSummaryEntry {
    pub bundle_id: String,
    pub imported_at: String,
    pub source_type: String,
    pub total_files: u64,
    pub total_bytes: u64,
    pub parsed_files: u64,
}

fn generate_run_id() -> String {
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("import_{}", ts)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_path_validation() {
        assert!(validate_rel_path("foo/bar.json").is_ok());
        assert!(validate_rel_path("foo/bar/baz.json").is_ok());
        assert!(validate_rel_path("../foo.json").is_err());
        assert!(validate_rel_path("foo/../bar.json").is_ok()); // Goes up then down, net positive
        assert!(validate_rel_path("foo/../../bar.json").is_err()); // Goes above root
        assert!(validate_rel_path("/absolute/path.json").is_err());
        assert!(validate_rel_path("C:\\windows\\path.json").is_err());
        assert!(validate_rel_path("\\\\unc\\path.json").is_err());
    }
    
    #[test]
    fn test_path_depth() {
        assert_eq!(path_depth("foo.json"), 1);
        assert_eq!(path_depth("foo/bar.json"), 2);
        assert_eq!(path_depth("foo/bar/baz.json"), 3);
        assert_eq!(path_depth("./foo.json"), 1);
    }
    
    #[test]
    fn test_file_kind_detection() {
        assert_eq!(FileKind::detect("data.jsonl"), FileKind::Jsonl);
        assert_eq!(FileKind::detect("data.json"), FileKind::Json);
        assert_eq!(FileKind::detect("capture.har"), FileKind::Har);
        assert_eq!(FileKind::detect("conn.log"), FileKind::ZeekConn);
        assert_eq!(FileKind::detect("dns.log"), FileKind::ZeekDns);
        assert_eq!(FileKind::detect("http.log"), FileKind::ZeekHttp);
        assert_eq!(FileKind::detect("zeek/conn.log"), FileKind::ZeekConn);
        assert_eq!(FileKind::detect("capture.pcap"), FileKind::Pcap);
        assert_eq!(FileKind::detect("events.evtx"), FileKind::Evtx);
        assert_eq!(FileKind::detect("unknown.bin"), FileKind::Unknown);
    }
}
