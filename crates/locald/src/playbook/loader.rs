//! Finds the playbook directory, applies the desktop selection, and loads files.
//!
//! Directory, first match wins:
//!
//! 1. `EDR_PLAYBOOKS_DIR` (set by the desktop supervisor)
//! 2. `EDR_PLAYBOOK_DIR` (older name, kept as an alias)
//! 3. `<telemetry root>/playbooks/windows` (where the scripts copy playbooks)
//! 4. `playbooks/windows` next to the executable
//! 5. `playbooks/windows` under the current directory (running from the repo)
//!
//! A directory named by an environment variable is used even if it does not
//! exist, so a wrong setting shows up as a load error instead of silently
//! falling back to another set of playbooks.
//!
//! Selection: `EDR_SELECTED_PLAYBOOKS` is a comma separated list of playbook ids
//! (the file name without `.yaml`, which is what the desktop picker sends). When
//! it is unset or empty every enabled playbook loads.

use super::schema::{parse_playbook, Playbook};
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub const ENV_PLAYBOOKS_DIR: &str = "EDR_PLAYBOOKS_DIR";
pub const ENV_PLAYBOOK_DIR_ALIAS: &str = "EDR_PLAYBOOK_DIR";
pub const ENV_SELECTED_PLAYBOOKS: &str = "EDR_SELECTED_PLAYBOOKS";

/// Name of the status file edr-locald writes into the telemetry root after
/// loading, so the desktop app can show what actually loaded.
pub const STATUS_FILE_NAME: &str = "playbooks_loaded.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Macos,
    Linux,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::Macos
        } else {
            Platform::Linux
        }
    }

    /// Playbook directory for this platform, relative to a root.
    pub fn playbook_dir(&self) -> &'static str {
        match self {
            Platform::Windows => "playbooks/windows",
            Platform::Macos => "playbooks/macos",
            Platform::Linux => "playbooks/linux",
        }
    }
}

/// Where the playbook directory came from, for the startup log and status file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedDir {
    pub path: PathBuf,
    pub source: String,
}

/// Resolve the Windows playbook directory. The edr-locald engine always runs the
/// Windows set because the fact extractor and the playbooks are Windows specific.
pub fn resolve_playbook_dir(telemetry_root: &Path) -> Option<ResolvedDir> {
    resolve_playbook_dir_with(telemetry_root, |name| std::env::var(name).ok())
}

/// Same as `resolve_playbook_dir` with the environment passed in, for tests.
pub fn resolve_playbook_dir_with(
    telemetry_root: &Path,
    env: impl Fn(&str) -> Option<String>,
) -> Option<ResolvedDir> {
    for name in [ENV_PLAYBOOKS_DIR, ENV_PLAYBOOK_DIR_ALIAS] {
        if let Some(value) = env(name).filter(|v| !v.trim().is_empty()) {
            return Some(ResolvedDir {
                path: PathBuf::from(value.trim()),
                source: name.to_string(),
            });
        }
    }

    let rel = Platform::Windows.playbook_dir();
    let mut candidates = vec![(telemetry_root.join(rel), "telemetry root")];
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    {
        candidates.push((exe_dir.join(rel), "executable directory"));
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push((cwd.join(rel), "current directory"));
    }
    candidates
        .into_iter()
        .find(|(p, _)| p.is_dir())
        .map(|(path, source)| ResolvedDir {
            path,
            source: source.to_string(),
        })
}

/// Parse `EDR_SELECTED_PLAYBOOKS`. None means "load all".
pub fn selected_from_env() -> Option<Vec<String>> {
    parse_selection(std::env::var(ENV_SELECTED_PLAYBOOKS).ok().as_deref())
}

pub fn parse_selection(value: Option<&str>) -> Option<Vec<String>> {
    let list: Vec<String> = value?
        .split(',')
        .map(|s| {
            let s = s.trim();
            s.strip_suffix(".yaml")
                .or_else(|| s.strip_suffix(".yml"))
                .unwrap_or(s)
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect();
    if list.is_empty() {
        None
    } else {
        Some(list)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadError {
    pub file: String,
    pub error: String,
}

/// Result of loading a directory. `playbooks` are ready for the engine.
#[derive(Debug, Default)]
pub struct LoadReport {
    pub dir: Option<ResolvedDir>,
    pub playbooks: Vec<Playbook>,
    pub files_found: usize,
    pub disabled: Vec<String>,
    pub not_selected: Vec<String>,
    pub unknown_selected: Vec<String>,
    pub errors: Vec<LoadError>,
    pub selected: Option<Vec<String>>,
}

impl LoadReport {
    pub fn loaded_ids(&self) -> Vec<String> {
        self.playbooks.iter().map(|p| p.id.clone()).collect()
    }

    pub fn rule_count(&self) -> usize {
        self.playbooks.iter().map(|p| p.rules.len()).sum()
    }

    /// JSON written to `STATUS_FILE_NAME`.
    pub fn status_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "dir": self.dir.as_ref().map(|d| d.path.display().to_string()),
            "dir_source": self.dir.as_ref().map(|d| d.source.clone()),
            "files_found": self.files_found,
            "selected": self.selected,
            "loaded": self.loaded_ids(),
            "count": self.playbooks.len(),
            "rules": self.rule_count(),
            "disabled": self.disabled,
            "unknown_selected": self.unknown_selected,
            "errors": self.errors,
        })
    }
}

/// Load every `.yaml` / `.yml` file directly inside `dir`, keeping only the
/// selected ids when a selection is given. Files are read in name order so the
/// result is deterministic.
pub fn load_dir(dir: &Path, selected: Option<&[String]>) -> LoadReport {
    let mut report = LoadReport {
        selected: selected.map(|s| s.to_vec()),
        ..Default::default()
    };

    let mut paths: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e == "yaml" || e == "yml")
            })
            .collect(),
        Err(e) => {
            report.errors.push(LoadError {
                file: dir.display().to_string(),
                error: format!("cannot read playbook directory: {}", e),
            });
            return report;
        }
    };
    paths.sort();
    report.files_found = paths.len();

    let wanted: Option<HashSet<&str>> = selected.map(|s| s.iter().map(String::as_str).collect());
    let mut ids = HashSet::new();

    for path in paths {
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        if let Some(w) = &wanted {
            if !w.contains(stem.as_str()) {
                report.not_selected.push(stem);
                continue;
            }
        }

        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                report.errors.push(LoadError {
                    file: file_name,
                    error: format!("cannot read file: {}", e),
                });
                continue;
            }
        };
        match parse_playbook(&text, Some(&path)) {
            Ok(pb) if !pb.enabled => report.disabled.push(pb.id),
            Ok(pb) => {
                if !ids.insert(pb.id.clone()) {
                    report.errors.push(LoadError {
                        file: file_name,
                        error: format!("duplicate playbook id '{}'", pb.id),
                    });
                    continue;
                }
                report.playbooks.push(pb);
            }
            Err(e) => report.errors.push(LoadError {
                file: file_name,
                error: e,
            }),
        }
    }

    if let Some(sel) = selected {
        let present: HashSet<String> = report
            .playbooks
            .iter()
            .map(|p| p.id.clone())
            .chain(report.disabled.iter().cloned())
            .collect();
        let failed: HashSet<String> = report
            .errors
            .iter()
            .map(|e| {
                Path::new(&e.file)
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default()
            })
            .collect();
        report.unknown_selected = sel
            .iter()
            .filter(|s| !present.contains(*s) && !failed.contains(*s))
            .cloned()
            .collect();
    }
    report
}

/// Resolve the directory from the environment, read the selection from the
/// environment, and load. This is what edr-locald calls at startup.
pub fn load_from_env(telemetry_root: &Path) -> LoadReport {
    let selected = selected_from_env();
    match resolve_playbook_dir(telemetry_root) {
        Some(dir) => {
            let mut report = load_dir(&dir.path, selected.as_deref());
            report.dir = Some(dir);
            report
        }
        None => LoadReport {
            selected,
            errors: vec![LoadError {
                file: String::new(),
                error: format!(
                    "no playbook directory found. Set {} or copy playbooks to {}",
                    ENV_PLAYBOOKS_DIR,
                    telemetry_root
                        .join(Platform::Windows.playbook_dir())
                        .display()
                ),
            }],
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_playbook_dirs() {
        assert_eq!(Platform::Windows.playbook_dir(), "playbooks/windows");
        assert_eq!(Platform::Macos.playbook_dir(), "playbooks/macos");
        assert_eq!(Platform::Linux.playbook_dir(), "playbooks/linux");
    }

    #[test]
    fn test_parse_selection() {
        assert_eq!(parse_selection(None), None);
        assert_eq!(parse_selection(Some("")), None);
        assert_eq!(parse_selection(Some(" , ")), None);
        assert_eq!(
            parse_selection(Some("signal_a, signal_b.yaml,signal_c.yml")),
            Some(vec![
                "signal_a".to_string(),
                "signal_b".to_string(),
                "signal_c".to_string()
            ])
        );
    }

    #[test]
    fn test_env_dir_wins_and_alias_works() {
        let root = Path::new("/nonexistent-root");
        let primary = resolve_playbook_dir_with(root, |n| match n {
            ENV_PLAYBOOKS_DIR => Some("/a".to_string()),
            ENV_PLAYBOOK_DIR_ALIAS => Some("/b".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(primary.path, PathBuf::from("/a"));
        assert_eq!(primary.source, ENV_PLAYBOOKS_DIR);

        let alias = resolve_playbook_dir_with(root, |n| match n {
            ENV_PLAYBOOK_DIR_ALIAS => Some("/b".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(alias.path, PathBuf::from("/b"));
        assert_eq!(alias.source, ENV_PLAYBOOK_DIR_ALIAS);
    }

    #[test]
    fn test_telemetry_root_dir_is_used() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("playbooks").join("windows");
        std::fs::create_dir_all(&dir).unwrap();
        let resolved = resolve_playbook_dir_with(tmp.path(), |_| None).unwrap();
        assert_eq!(resolved.path, dir);
        assert_eq!(resolved.source, "telemetry root");
    }

    #[test]
    fn test_missing_dir_is_an_error() {
        let report = load_dir(Path::new("/nonexistent/playbooks"), None);
        assert!(report.playbooks.is_empty());
        assert_eq!(report.errors.len(), 1);
    }
}
