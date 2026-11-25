//! Endpoints behind the web dashboard (ui/index.html and ui/graph.html).
//!
//! Every response is computed from data the pipeline writes:
//!
//! * the `signals` and `signal_explanations` tables edr-locald writes to
//!   workbench.db
//! * the segment files listed in index.json (written by the capture agent)
//! * the manifest.json files the desktop importer writes for imported cases
//!
//! Nothing is invented. Where a value is derived the derivation is stated:
//! `risk` is the signal severity mapped onto 0..1 (LOW 0.3, MEDIUM 0.55,
//! HIGH 0.8, CRITICAL 1.0), and an incident is every signal from one host in
//! one clock hour.

use crate::db::StoredSignal;
use crate::SharedState;
use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use futures_util::stream::{self, Stream, StreamExt};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

/// How often the streams look for new signals.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// How many existing signals a new stream client receives first.
const BACKLOG: i64 = 200;
/// How many recent signals the snapshots (hits, incidents, graph) consider.
const SNAPSHOT_LIMIT: usize = 1000;

// ============================================================================
// Derivations (pure, unit tested)
// ============================================================================

/// Signal severity mapped onto 0..1. The dashboard shows it as "risk".
pub fn severity_weight(severity: &str) -> f64 {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => 1.0,
        "HIGH" => 0.8,
        "MEDIUM" => 0.55,
        "LOW" => 0.3,
        _ => 0.0,
    }
}

/// Playbook details from a signal's metadata, falling back to signal_type.
#[derive(Debug, Clone, PartialEq)]
pub struct PlaybookInfo {
    pub id: String,
    pub title: String,
    pub rule: String,
    pub techniques: Vec<String>,
    pub tactics: Vec<String>,
}

pub fn playbook_info(signal: &StoredSignal) -> PlaybookInfo {
    let meta = &signal.metadata;
    let text = |key: &str| meta.get(key).and_then(|v| v.as_str()).map(str::to_string);
    let list = |key: &str| -> Vec<String> {
        meta.get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let id = text("playbook_id").unwrap_or_else(|| {
        signal
            .signal_type
            .strip_prefix("playbook:")
            .unwrap_or(&signal.signal_type)
            .to_string()
    });
    PlaybookInfo {
        title: text("playbook_title").unwrap_or_else(|| id.clone()),
        rule: text("rule").unwrap_or_default(),
        techniques: list("mitre_techniques"),
        tactics: list("mitre_tactics"),
        id,
    }
}

/// Signal times are milliseconds. The dashboard lists take seconds.
fn millis_to_secs(ms: i64) -> i64 {
    if ms > 2_000_000_000 {
        ms / 1000
    } else {
        ms
    }
}

/// One signal in the shape the "Alerts (live)" table reads.
pub fn signal_to_alert(signal: &StoredSignal, summary: Option<&str>) -> Value {
    let pb = playbook_info(signal);
    let findings: Vec<Value> = if pb.techniques.is_empty() {
        vec![json!({ "source": pb.id, "rule": pb.rule })]
    } else {
        pb.techniques
            .iter()
            .map(|t| json!({ "source": pb.id, "rule": pb.rule, "label": t }))
            .collect()
    };
    json!({
        "id": signal.signal_id,
        "ts": signal.ts_start,
        "host": signal.host,
        "severity": signal.severity.to_lowercase(),
        "risk": severity_weight(&signal.severity),
        "title": pb.title,
        "playbook_id": pb.id,
        "rule": pb.rule,
        "technique": pb.techniques.first(),
        "tactics": pb.tactics,
        "event": { "category": format!("{}: {}", pb.title, pb.rule) },
        "findings": findings,
        "explanation": summary.map(|s| json!({ "summary": s })),
    })
}

/// One signal in the shape the playbook hits lists read.
pub fn signal_to_hit(signal: &StoredSignal) -> Value {
    let pb = playbook_info(signal);
    json!({
        "ts": millis_to_secs(signal.ts_start),
        "signal_id": signal.signal_id,
        "playbook_id": pb.id,
        "playbook_name": pb.title,
        "severity": signal.severity,
        "tags": pb.techniques,
        "rationale": [pb.rule, signal.host.clone()],
    })
}

/// Group signals into incidents: every signal from one host in one clock hour.
/// Sorted by most recent activity first.
pub fn rollup_incidents(signals: &[StoredSignal]) -> Vec<Value> {
    #[derive(Default)]
    struct Acc {
        host: String,
        first_ts: i64,
        last_ts: i64,
        count: u64,
        risk_max: f64,
        severity_max: String,
        playbooks: BTreeSet<String>,
        techniques: BTreeMap<String, u64>,
        signal_ids: Vec<String>,
    }
    let mut groups: BTreeMap<(String, i64), Acc> = BTreeMap::new();
    for s in signals {
        let ts = millis_to_secs(s.ts_start);
        let bucket = ts.div_euclid(3600);
        let acc = groups.entry((s.host.clone(), bucket)).or_default();
        if acc.count == 0 {
            acc.host = s.host.clone();
            acc.first_ts = ts;
            acc.last_ts = ts;
        }
        acc.first_ts = acc.first_ts.min(ts);
        acc.last_ts = acc.last_ts.max(millis_to_secs(s.ts_end).max(ts));
        acc.count += 1;
        let w = severity_weight(&s.severity);
        if w >= acc.risk_max {
            acc.risk_max = w;
            acc.severity_max = s.severity.to_lowercase();
        }
        let pb = playbook_info(s);
        acc.playbooks.insert(pb.id);
        for t in pb.techniques {
            *acc.techniques.entry(t).or_default() += 1;
        }
        acc.signal_ids.push(s.signal_id.clone());
    }
    let mut out: Vec<Value> = groups
        .into_iter()
        .map(|((host, bucket), acc)| {
            let primary = acc
                .techniques
                .iter()
                .max_by_key(|(t, n)| (**n, std::cmp::Reverse((*t).clone())))
                .map(|(t, _)| t.clone());
            json!({
                "id": format!("inc_{}_{}", host, bucket),
                "host": host,
                "title": format!("{}: {} playbooks", acc.host, acc.playbooks.len()),
                "first_ts": acc.first_ts,
                "last_ts": acc.last_ts,
                "severity_max": acc.severity_max,
                "risk_max": acc.risk_max,
                "alerts_count": acc.count,
                "playbooks": acc.playbooks.into_iter().collect::<Vec<_>>(),
                "primary_technique": primary,
                "techniques": acc.techniques.keys().cloned().collect::<Vec<_>>(),
                "signal_ids": acc.signal_ids,
            })
        })
        .collect();
    out.sort_by_key(|v| std::cmp::Reverse(v["last_ts"].as_i64().unwrap_or(0)));
    out
}

/// Entity graph for ui/graph.html: host nodes, one node per signal, and the
/// entities each signal's explanation names (processes, files, users, network
/// endpoints, registry keys). Edges run host to signal and signal to entity.
pub fn build_graph(signals: &[(StoredSignal, Option<Value>)]) -> Value {
    let mut nodes: BTreeMap<String, Value> = BTreeMap::new();
    let mut edges: Vec<Value> = Vec::new();
    let mut edge_keys = BTreeSet::new();
    let mut add_edge = |edges: &mut Vec<Value>, source: &str, target: &str, rel: &str| {
        if edge_keys.insert((source.to_string(), target.to_string(), rel.to_string())) {
            edges.push(json!({ "source": source, "target": target, "rel": rel }));
        }
    };

    for (signal, explanation) in signals {
        let pb = playbook_info(signal);
        let host_id = format!("host:{}", signal.host);
        nodes
            .entry(host_id.clone())
            .or_insert_with(|| json!({ "id": host_id, "label": signal.host, "otype": "host" }));
        let sig_id = format!("signal:{}", signal.signal_id);
        nodes.insert(
            sig_id.clone(),
            json!({
                "id": sig_id,
                "label": format!("{} ({})", pb.title, signal.severity),
                "otype": "signal",
                "trust_score": 1.0 - severity_weight(&signal.severity),
                "details": { "playbook_id": pb.id, "rule": pb.rule, "techniques": pb.techniques },
            }),
        );
        add_edge(&mut edges, &host_id, &sig_id, "alert");

        let Some(entities) = explanation.as_ref().and_then(|e| e.get("entities")) else {
            continue;
        };
        for (field, otype) in [
            ("proc_keys", "process"),
            ("file_keys", "file"),
            ("identity_keys", "user"),
            ("net_keys", "ip"),
            ("registry_keys", "registry"),
        ] {
            let keys = entities
                .get(field)
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for key in keys.iter().filter_map(|k| k.as_str()) {
                // edr-locald uses "host:<name>" as the process key when an event
                // has no process identity. The host node already covers it.
                if key == host_id {
                    continue;
                }
                let node_id = format!("{}:{}", otype, key);
                nodes
                    .entry(node_id.clone())
                    .or_insert_with(|| json!({ "id": node_id, "label": key, "otype": otype }));
                add_edge(&mut edges, &sig_id, &node_id, "involves");
            }
        }
    }

    json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "nodes_count": nodes.len(),
        "edges_count": edges.len(),
        "nodes": nodes.into_values().collect::<Vec<_>>(),
        "edges": edges,
    })
}

/// Line count per segment file, keyed by path, with the size and mtime it was
/// counted at.
type LineCountCache = HashMap<PathBuf, (u64, Option<SystemTime>, u64)>;

/// Number of event records in the capture segments under `telemetry_root`.
/// Uses the segments listed in index.json, or every segments/*.jsonl file when
/// there is no index. Line counts are cached per file by size and mtime.
pub fn count_events(telemetry_root: &Path) -> (u64, u64) {
    static CACHE: OnceLock<Mutex<LineCountCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    let mut files: Vec<PathBuf> = Vec::new();
    if let Ok(text) = std::fs::read_to_string(telemetry_root.join("index.json")) {
        if let Ok(index) = serde_json::from_str::<Value>(&text) {
            for seg in index
                .get("segments")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
            {
                if let Some(rel) = seg
                    .get("rel_path")
                    .or_else(|| seg.get("path"))
                    .and_then(|v| v.as_str())
                {
                    files.push(telemetry_root.join(rel));
                }
            }
        }
    }
    if files.is_empty() {
        if let Ok(entries) = std::fs::read_dir(telemetry_root.join("segments")) {
            files = entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
                .collect();
        }
    }

    let mut events = 0u64;
    let mut segments = 0u64;
    let mut cache = cache.lock().unwrap();
    for path in files {
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        segments += 1;
        let len = meta.len();
        let mtime = meta.modified().ok();
        if let Some((l, m, n)) = cache.get(&path) {
            if *l == len && *m == mtime {
                events += n;
                continue;
            }
        }
        let n = std::fs::read(&path)
            .map(|bytes| {
                let lines = bytes.split(|b| *b == b'\n');
                lines
                    .filter(|l| l.iter().any(|b| !b.is_ascii_whitespace()))
                    .count() as u64
            })
            .unwrap_or(0);
        cache.insert(path, (len, mtime, n));
        events += n;
    }
    (events, segments)
}

/// Import case ids are folder names the desktop importer creates. Anything
/// else is rejected before it touches the file system.
pub fn is_valid_case_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        && !id.contains("..")
}

/// Folders that can hold `imports/<bundle_id>/manifest.json`: the telemetry
/// root itself, its `runs/*` folders, and, when the server runs inside one
/// run folder (as the desktop app starts it), the sibling run folders.
fn import_roots(telemetry_root: &Path) -> Vec<PathBuf> {
    let mut roots = vec![telemetry_root.join("imports")];
    let mut run_parents = vec![telemetry_root.join("runs")];
    if telemetry_root
        .parent()
        .and_then(|p| p.file_name())
        .is_some_and(|n| n == "runs")
    {
        if let Some(parent) = telemetry_root.parent() {
            run_parents.push(parent.to_path_buf());
        }
    }
    for parent in run_parents {
        if let Ok(entries) = std::fs::read_dir(&parent) {
            for e in entries.filter_map(Result::ok) {
                roots.push(e.path().join("imports"));
            }
        }
    }
    roots.sort();
    roots.dedup();
    roots
}

/// Every import manifest under the telemetry root, newest first.
pub fn find_import_cases(telemetry_root: &Path) -> Vec<Value> {
    let mut cases = Vec::new();
    let mut seen = BTreeSet::new();
    for root in import_roots(telemetry_root) {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in entries.filter_map(Result::ok) {
            let manifest_path = e.path().join("manifest.json");
            let Ok(text) = std::fs::read_to_string(&manifest_path) else {
                continue;
            };
            let Ok(manifest) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            let bundle_id = manifest
                .get("bundle_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| e.file_name().to_string_lossy().to_string());
            if !seen.insert(bundle_id.clone()) {
                continue;
            }
            cases.push(case_summary(&bundle_id, &manifest));
        }
    }
    cases.sort_by(|a, b| {
        b["imported_at"]
            .as_str()
            .unwrap_or("")
            .cmp(a["imported_at"].as_str().unwrap_or(""))
    });
    cases
}

fn case_summary(bundle_id: &str, manifest: &Value) -> Value {
    let summary = manifest.get("summary").cloned().unwrap_or(Value::Null);
    let num = |key: &str| summary.get(key).and_then(|v| v.as_u64()).unwrap_or(0);
    let source = manifest
        .get("source_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let name = source
        .rsplit(['/', '\\'])
        .find(|s| !s.is_empty())
        .unwrap_or(bundle_id);
    json!({
        "bundle_id": bundle_id,
        "name": name,
        "run_id": manifest.get("run_id"),
        "source_type": manifest.get("source_type"),
        "imported_at": manifest.get("imported_at"),
        "files_count": num("total_files"),
        "parsed_files": num("parsed_files"),
        "rejected_files": num("rejected_files"),
        "events_count": num("events_extracted"),
        "total_bytes": num("total_bytes"),
    })
}

/// The manifest for one import case.
pub fn find_import_manifest(telemetry_root: &Path, bundle_id: &str) -> Option<Value> {
    if !is_valid_case_id(bundle_id) {
        return None;
    }
    import_roots(telemetry_root).into_iter().find_map(|root| {
        let text = std::fs::read_to_string(root.join(bundle_id).join("manifest.json")).ok()?;
        serde_json::from_str(&text).ok()
    })
}

// ============================================================================
// Handlers
// ============================================================================

fn recent_signals(state: &SharedState) -> Vec<StoredSignal> {
    state
        .db
        .list_signals(None, None, None, SNAPSHOT_LIMIT)
        .unwrap_or_default()
}

/// GET /metrics: event and segment counts from the capture, signal count
/// from the database.
pub async fn metrics(State(state): State<SharedState>) -> impl IntoResponse {
    let root = state.data_dir.clone();
    let (events, segments) = tokio::task::spawn_blocking(move || count_events(&root))
        .await
        .unwrap_or((0, 0));
    let signals = state.db.signal_stats().map(|s| s.total).unwrap_or(0);
    Json(json!({
        "events_in": events,
        "segments_count": segments,
        "signals_count": signals,
    }))
}

/// GET /playbooks/hits: the most recent playbook signals, oldest first.
pub async fn playbook_hits(State(state): State<SharedState>) -> impl IntoResponse {
    let mut signals = recent_signals(&state);
    signals.truncate(200);
    signals.reverse();
    Json(signals.iter().map(signal_to_hit).collect::<Vec<_>>())
}

/// GET /graph/live: entity graph of recent signals.
pub async fn graph_live(State(state): State<SharedState>) -> impl IntoResponse {
    Json(current_graph(&state))
}

fn current_graph(state: &SharedState) -> Value {
    let signals = recent_signals(state);
    let with_explanations: Vec<(StoredSignal, Option<Value>)> = signals
        .into_iter()
        .take(300)
        .map(|s| {
            let e = state.db.get_signal_explanation(&s.signal_id).ok().flatten();
            (s, e)
        })
        .collect();
    build_graph(&with_explanations)
}

/// GET /api/import/cases: cases the desktop importer wrote to disk.
pub async fn list_import_cases(State(state): State<SharedState>) -> impl IntoResponse {
    Json(find_import_cases(&state.data_dir))
}

/// GET /api/import/cases/:id
pub async fn get_import_case(
    State(state): State<SharedState>,
    UrlPath(id): UrlPath<String>,
) -> Response {
    match find_import_manifest(&state.data_dir, &id) {
        Some(m) => Json(case_summary(&id, &m)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "case not found" })),
        )
            .into_response(),
    }
}

/// GET /api/import/cases/:id/manifest
pub async fn get_import_case_manifest(
    State(state): State<SharedState>,
    UrlPath(id): UrlPath<String>,
) -> Response {
    match find_import_manifest(&state.data_dir, &id) {
        Some(m) => Json(m).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "case not found" })),
        )
            .into_response(),
    }
}

// ============================================================================
// Server sent event streams
// ============================================================================

type EventStream = Sse<std::pin::Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>>>;

fn sse(events: impl Stream<Item = Vec<Value>> + Send + 'static) -> EventStream {
    let flat = events.flat_map(|batch| {
        stream::iter(
            batch
                .into_iter()
                .map(|v| Ok(Event::default().data(v.to_string()))),
        )
    });
    Sse::new(Box::pin(flat) as std::pin::Pin<Box<dyn Stream<Item = _> + Send>>)
        .keep_alive(KeepAlive::default())
}

/// Poll the signals table and hand each batch of new signals to `map`.
/// A new client first receives the last BACKLOG signals.
fn new_signal_batches<F>(state: SharedState, map: F) -> impl Stream<Item = Vec<Value>> + Send
where
    F: Fn(&SharedState, &StoredSignal) -> Value + Send + Sync + 'static,
{
    let start = state
        .db
        .max_signal_rowid()
        .unwrap_or(0)
        .saturating_sub(BACKLOG);
    stream::unfold(
        (state, start, true, map),
        |(state, cursor, first, map)| async move {
            if !first {
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            let batch = state
                .db
                .signals_after_rowid(cursor, 500)
                .unwrap_or_default();
            let next = batch.last().map(|(rowid, _)| *rowid).unwrap_or(cursor);
            let values = batch.iter().map(|(_, s)| map(&state, s)).collect();
            Some((values, (state, next, false, map)))
        },
    )
}

/// GET /alerts: every new signal as an alert row.
pub async fn alerts_stream(State(state): State<SharedState>) -> EventStream {
    sse(new_signal_batches(state, |state, s| {
        let summary = state
            .db
            .get_signal_explanation(&s.signal_id)
            .ok()
            .flatten()
            .and_then(|e| {
                e.get("summary")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            });
        signal_to_alert(s, summary.as_deref())
    }))
}

/// GET /playbooks/stream: every new signal as a playbook hit.
pub async fn playbooks_stream(State(state): State<SharedState>) -> EventStream {
    sse(new_signal_batches(state, |_, s| signal_to_hit(s)))
}

/// GET /incidents/stream: incidents (host and hour rollups) whenever their
/// signal count or last time changes.
pub async fn incidents_stream(State(state): State<SharedState>) -> EventStream {
    let sent: HashMap<String, (u64, i64)> = HashMap::new();
    let batches = stream::unfold((state, sent, true), |(state, mut sent, first)| async move {
        if !first {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        let incidents = rollup_incidents(&recent_signals(&state));
        let changed: Vec<Value> = incidents
            .into_iter()
            .filter(|inc| {
                let id = inc["id"].as_str().unwrap_or("").to_string();
                let stamp = (
                    inc["alerts_count"].as_u64().unwrap_or(0),
                    inc["last_ts"].as_i64().unwrap_or(0),
                );
                sent.insert(id, stamp) != Some(stamp)
            })
            .collect();
        Some((changed, (state, sent, false)))
    });
    sse(batches)
}

/// GET /graph/stream: the entity graph, sent again whenever new signals land.
pub async fn graph_stream(State(state): State<SharedState>) -> EventStream {
    let batches = stream::unfold((state, -1i64), |(state, last)| async move {
        if last >= 0 {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        let now = state.db.max_signal_rowid().unwrap_or(0);
        let out = if now != last {
            vec![current_graph(&state)]
        } else {
            Vec::new()
        };
        Some((out, (state, now)))
    });
    sse(batches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    fn signal(
        id: &str,
        host: &str,
        sev: &str,
        ts_ms: i64,
        playbook: &str,
        rule: &str,
        techs: &[&str],
    ) -> StoredSignal {
        StoredSignal {
            signal_id: id.to_string(),
            signal_type: format!("playbook:{}", playbook),
            severity: sev.to_string(),
            host: host.to_string(),
            ts: ts_ms,
            ts_start: ts_ms,
            ts_end: ts_ms,
            proc_key: None,
            file_key: None,
            identity_key: None,
            metadata: json!({
                "playbook_id": playbook,
                "playbook_title": format!("Title of {}", playbook),
                "rule": rule,
                "mitre_techniques": techs,
                "mitre_tactics": ["execution"],
            }),
            evidence_ptrs: vec![],
            dropped_evidence_count: 0,
        }
    }

    #[test]
    fn test_severity_weight() {
        assert_eq!(severity_weight("CRITICAL"), 1.0);
        assert_eq!(severity_weight("high"), 0.8);
        assert_eq!(severity_weight("MEDIUM"), 0.55);
        assert_eq!(severity_weight("LOW"), 0.3);
        assert_eq!(severity_weight("other"), 0.0);
    }

    #[test]
    fn test_playbook_info_falls_back_to_signal_type() {
        let mut s = signal(
            "s1",
            "WS01",
            "HIGH",
            0,
            "signal_a",
            "Rule A",
            &["T1059.001"],
        );
        s.metadata = json!({});
        let pb = playbook_info(&s);
        assert_eq!(pb.id, "signal_a");
        assert_eq!(pb.title, "signal_a");
        assert!(pb.techniques.is_empty());
    }

    #[test]
    fn test_signal_to_alert_uses_real_fields() {
        let s = signal(
            "s1",
            "WS01",
            "CRITICAL",
            1_700_000_000_000,
            "signal_wmic_abuse",
            "WMIC Shadow Copy Delete",
            &["T1490"],
        );
        let a = signal_to_alert(&s, Some("Rule matched"));
        assert_eq!(a["id"], "s1");
        assert_eq!(a["severity"], "critical");
        assert_eq!(a["risk"], 1.0);
        assert_eq!(a["technique"], "T1490");
        assert_eq!(a["findings"][0]["source"], "signal_wmic_abuse");
        assert_eq!(a["explanation"]["summary"], "Rule matched");
    }

    #[test]
    fn test_hits_use_seconds() {
        let s = signal(
            "s1",
            "WS01",
            "HIGH",
            1_700_000_000_000,
            "signal_a",
            "R",
            &[],
        );
        assert_eq!(signal_to_hit(&s)["ts"], 1_700_000_000);
    }

    #[test]
    fn test_rollup_groups_by_host_and_hour() {
        let base = 1_700_000_000_000i64 - (1_700_000_000_000i64 % 3_600_000);
        let signals = vec![
            signal(
                "a",
                "WS01",
                "MEDIUM",
                base + 1_000,
                "signal_a",
                "R1",
                &["T1059.001"],
            ),
            signal(
                "b",
                "WS01",
                "CRITICAL",
                base + 60_000,
                "signal_b",
                "R2",
                &["T1490", "T1059.001"],
            ),
            signal(
                "c",
                "WS02",
                "LOW",
                base + 2_000,
                "signal_a",
                "R1",
                &["T1059.001"],
            ),
            signal("d", "WS01", "HIGH", base + 3_700_000, "signal_a", "R1", &[]),
        ];
        let incs = rollup_incidents(&signals);
        assert_eq!(incs.len(), 3, "WS01 first hour, WS01 second hour, WS02");
        let first = incs
            .iter()
            .find(|i| i["host"] == "WS01" && i["alerts_count"] == 2)
            .unwrap();
        assert_eq!(first["severity_max"], "critical");
        assert_eq!(first["primary_technique"], "T1059.001");
        assert_eq!(first["playbooks"], json!(["signal_a", "signal_b"]));
        // Newest activity first
        assert_eq!(incs[0]["alerts_count"], 1);
        assert_eq!(incs[0]["host"], "WS01");
    }

    #[test]
    fn test_graph_links_signals_to_explanation_entities() {
        let s = signal("s1", "WS01", "HIGH", 0, "signal_a", "R", &[]);
        let explanation = json!({
            "entities": {
                "proc_keys": ["host:WS01", "proc_42"],
                "file_keys": ["C:\\Windows\\System32\\wbem\\WMIC.exe"],
                "identity_keys": ["alice"]
            }
        });
        let g = build_graph(&[(s, Some(explanation))]);
        let ids: Vec<&str> = g["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"host:WS01"));
        assert!(ids.contains(&"signal:s1"));
        assert!(ids.contains(&"process:proc_42"));
        assert!(ids.contains(&"user:alice"));
        assert!(!ids.contains(&"process:host:WS01"));
        assert_eq!(g["nodes_count"], 5);
        assert_eq!(g["edges_count"], 4);
    }

    #[test]
    fn test_count_events_from_index() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("segments")).unwrap();
        std::fs::write(
            tmp.path().join("segments/evtx_000000.jsonl"),
            "{}\n{}\n\n{}\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("segments/evtx_000001.jsonl"), "{}\n").unwrap();
        std::fs::write(
            tmp.path().join("index.json"),
            r#"{"segments":[{"rel_path":"segments/evtx_000000.jsonl"},{"rel_path":"segments/evtx_000001.jsonl"}]}"#,
        )
        .unwrap();
        assert_eq!(count_events(tmp.path()), (4, 2));
        // Appending is picked up through the size check
        std::fs::write(tmp.path().join("segments/evtx_000001.jsonl"), "{}\n{}\n").unwrap();
        assert_eq!(count_events(tmp.path()), (5, 2));
    }

    #[test]
    fn test_count_events_without_index() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("segments")).unwrap();
        std::fs::write(tmp.path().join("segments/1.jsonl"), "{}\n{}\n").unwrap();
        assert_eq!(count_events(tmp.path()), (2, 1));
    }

    #[test]
    fn test_import_cases_found_in_sibling_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let runs = tmp.path().join("runs");
        let live_run = runs.join("run_1");
        let import_run = runs.join("import_2").join("imports").join("bundle_abc");
        std::fs::create_dir_all(&live_run).unwrap();
        std::fs::create_dir_all(&import_run).unwrap();
        std::fs::write(
            import_run.join("manifest.json"),
            r#"{"bundle_id":"bundle_abc","run_id":"import_2","source_path":"/data/case.zip","imported_at":"2026-11-01T00:00:00Z","files":[{"rel_path":"a.json","bytes":10}],"summary":{"total_files":1,"parsed_files":1,"rejected_files":0,"events_extracted":7,"total_bytes":10}}"#,
        )
        .unwrap();

        // Server running inside one run folder, as the desktop app starts it
        let cases = find_import_cases(&live_run);
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0]["bundle_id"], "bundle_abc");
        assert_eq!(cases[0]["name"], "case.zip");
        assert_eq!(cases[0]["events_count"], 7);
        assert!(find_import_manifest(&live_run, "bundle_abc").is_some());
        // Server running at the telemetry root
        assert_eq!(find_import_cases(tmp.path()).len(), 1);
        // Path tricks are refused
        assert!(find_import_manifest(&live_run, "../import_2").is_none());
        assert!(!is_valid_case_id("a/b"));
        assert!(!is_valid_case_id(".."));
    }

    #[test]
    fn test_signal_cursor() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(db.max_signal_rowid().unwrap(), 0);
        db.save_signals(&[
            signal("s1", "WS01", "HIGH", 1, "signal_a", "R", &[]),
            signal("s2", "WS01", "LOW", 2, "signal_b", "R", &[]),
        ])
        .unwrap();
        let all = db.signals_after_rowid(0, 10).unwrap();
        assert_eq!(
            all.iter()
                .map(|(_, s)| s.signal_id.as_str())
                .collect::<Vec<_>>(),
            vec!["s1", "s2"]
        );
        let after_first = db.signals_after_rowid(all[0].0, 10).unwrap();
        assert_eq!(after_first.len(), 1);
        assert_eq!(after_first[0].1.signal_id, "s2");
        db.save_signal_explanation("s1", &json!({"summary": "x"}))
            .unwrap();
        assert_eq!(
            db.get_signal_explanation("s1").unwrap().unwrap()["summary"],
            "x"
        );
    }
}
