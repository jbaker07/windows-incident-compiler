//! Playbook file format, validation and compilation.
//!
//! A playbook file is parsed with serde into the `*Spec` types below, which
//! reject unknown keys so a misspelled key fails loudly. `compile` then checks
//! every rule and turns it into the `Playbook` and `Rule` types the engine runs,
//! with each regex compiled once.
//!
//! See the "Playbook format" section of `docs/playbooks_windows_coverage.md`
//! for the format as a playbook author sees it.

use super::fields::{VIEW_FIELDS, WINDOWS_FACT_TYPES};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// ATT&CK release the shipped playbooks are mapped to.
pub const ATTACK_VERSION: &str = "20.1";

/// ATT&CK v20.1 Enterprise tactics as (playbook name, tactic ID, display name).
pub const ATTACK_TACTICS: &[(&str, &str, &str)] = &[
    ("reconnaissance", "TA0043", "Reconnaissance"),
    ("resource_development", "TA0042", "Resource Development"),
    ("initial_access", "TA0001", "Initial Access"),
    ("execution", "TA0002", "Execution"),
    ("persistence", "TA0003", "Persistence"),
    ("privilege_escalation", "TA0004", "Privilege Escalation"),
    ("stealth", "TA0005", "Stealth"),
    ("defense_impairment", "TA0112", "Defense Impairment"),
    ("credential_access", "TA0006", "Credential Access"),
    ("discovery", "TA0007", "Discovery"),
    ("lateral_movement", "TA0008", "Lateral Movement"),
    ("collection", "TA0009", "Collection"),
    ("command_and_control", "TA0011", "Command and Control"),
    ("exfiltration", "TA0010", "Exfiltration"),
    ("impact", "TA0040", "Impact"),
];

/// Technique IDs that ATT&CK revoked before v20.1, with the ID that replaced
/// each one. A playbook that still lists one of these fails to load.
pub const RETIRED_TECHNIQUES: &[(&str, &str)] = &[
    ("T1070.001", "T1685.005"),
    ("T1084", "T1546.003"),
    ("T1089", "T1685"),
    ("T1562", "T1685"),
    ("T1562.001", "T1685"),
    ("T1562.002", "T1685.001"),
    ("T1562.004", "T1686"),
    ("T1562.006", "T1685"),
    ("T1574.002", "T1574.001"),
];

/// Default seconds a rule stays quiet for the same group after it fires.
pub const DEFAULT_COOLDOWN_SECONDS: u64 = 60;

/// Default window for count and sequence rules when none is given.
pub const DEFAULT_WINDOW_SECONDS: u64 = 60;

// ============================================================================
// File format (what serde reads)
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaybookSpec {
    pub id: String,
    pub title: String,
    pub family: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub cooldown_seconds: Option<u64>,
    /// Telemetry the playbook needs. Informational, shown in the docs.
    #[serde(default)]
    pub requires: Vec<String>,
    pub mitre: MitreSpec,
    pub rules: Vec<RuleSpec>,
    /// Analyst guidance. Parsed so the file stays valid, never executed.
    #[serde(default)]
    pub false_positives: Vec<String>,
    #[serde(default)]
    pub response: Option<serde_yaml::Value>,
    #[serde(default)]
    pub remediation: Option<serde_yaml::Value>,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MitreSpec {
    pub attack_version: String,
    pub tactics: Vec<String>,
    pub techniques: Vec<TechniqueRef>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TechniqueRef {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub name: String,
    #[serde(default)]
    pub severity: Option<String>,
    pub fact: String,
    #[serde(default, rename = "match")]
    pub all: Vec<ConditionSpec>,
    #[serde(default)]
    pub any: Vec<ConditionSpec>,
    #[serde(default)]
    pub exclude: Vec<ConditionSpec>,
    #[serde(default)]
    pub threshold: Option<u32>,
    #[serde(default)]
    pub distinct: Option<String>,
    #[serde(default)]
    pub window_seconds: Option<u64>,
    #[serde(default)]
    pub group_by: Option<String>,
    #[serde(default)]
    pub then: Option<StepSpec>,
    #[serde(default)]
    pub techniques: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepSpec {
    pub fact: String,
    #[serde(default, rename = "match")]
    pub all: Vec<ConditionSpec>,
    #[serde(default)]
    pub any: Vec<ConditionSpec>,
    #[serde(default)]
    pub exclude: Vec<ConditionSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionSpec {
    pub field: String,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub not_regex: Option<String>,
    #[serde(default)]
    pub equals: Option<serde_yaml::Value>,
    #[serde(default)]
    pub not_equals: Option<serde_yaml::Value>,
    #[serde(default, rename = "in")]
    pub one_of: Option<Vec<serde_yaml::Value>>,
    #[serde(default)]
    pub not_in: Option<Vec<serde_yaml::Value>>,
    #[serde(default)]
    pub exists: Option<bool>,
}

fn default_true() -> bool {
    true
}

// ============================================================================
// Compiled form (what the engine runs)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "LOW" => Some(Self::Low),
            "MEDIUM" => Some(Self::Medium),
            "HIGH" => Some(Self::High),
            "CRITICAL" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// How hits are grouped for counting, sequencing and cooldown. Every group is
/// also scoped to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupBy {
    Host,
    User,
    Process,
    Field(String),
}

impl GroupBy {
    pub fn describe(&self) -> String {
        match self {
            Self::Host => "host".to_string(),
            Self::User => "user".to_string(),
            Self::Process => "process".to_string(),
            Self::Field(f) => f.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Op {
    Regex(Regex),
    NotRegex(Regex),
    Equals(String),
    NotEquals(String),
    In(Vec<String>),
    NotIn(Vec<String>),
    Exists(bool),
}

#[derive(Debug, Clone)]
pub struct Condition {
    pub field: String,
    pub op: Op,
}

impl Condition {
    /// Plain text form used in explanations.
    pub fn describe(&self) -> String {
        match &self.op {
            Op::Regex(r) => format!("{} matches /{}/", self.field, r.as_str()),
            Op::NotRegex(r) => format!("{} does not match /{}/", self.field, r.as_str()),
            Op::Equals(v) => format!("{} equals {}", self.field, v),
            Op::NotEquals(v) => format!("{} is not {}", self.field, v),
            Op::In(vs) => format!("{} is one of [{}]", self.field, vs.join(", ")),
            Op::NotIn(vs) => format!("{} is none of [{}]", self.field, vs.join(", ")),
            Op::Exists(true) => format!("{} is present", self.field),
            Op::Exists(false) => format!("{} is absent", self.field),
        }
    }
}

/// One step of a rule: a fact type plus the conditions a fact must meet.
#[derive(Debug, Clone)]
pub struct Step {
    pub fact: String,
    pub all: Vec<Condition>,
    pub any: Vec<Condition>,
    pub exclude: Vec<Condition>,
}

impl Step {
    pub fn describe(&self) -> String {
        let mut parts = vec![format!("{} fact", self.fact)];
        if !self.all.is_empty() {
            let all: Vec<String> = self.all.iter().map(Condition::describe).collect();
            parts.push(format!("where {}", all.join(" and ")));
        }
        if !self.any.is_empty() {
            let any: Vec<String> = self.any.iter().map(Condition::describe).collect();
            parts.push(format!("and at least one of ({})", any.join(", ")));
        }
        if !self.exclude.is_empty() {
            let ex: Vec<String> = self.exclude.iter().map(Condition::describe).collect();
            parts.push(format!("unless ({})", ex.join(", ")));
        }
        parts.join(" ")
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub severity: Severity,
    pub first: Step,
    /// Second step for a sequence rule: `first` then `then` within the window.
    pub then: Option<Step>,
    pub threshold: u32,
    pub distinct: Option<String>,
    pub window_seconds: u64,
    pub group_by: GroupBy,
    /// Techniques this rule maps to. The rule list when given, otherwise all of
    /// the playbook techniques.
    pub techniques: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Playbook {
    pub id: String,
    pub title: String,
    pub family: String,
    pub version: String,
    pub description: String,
    pub enabled: bool,
    pub severity: Severity,
    pub cooldown_seconds: u64,
    pub requires: Vec<String>,
    pub attack_version: String,
    pub tactics: Vec<String>,
    pub techniques: Vec<TechniqueRef>,
    pub rules: Vec<Rule>,
    pub false_positives: Vec<String>,
    pub source_path: Option<PathBuf>,
}

impl Playbook {
    pub fn technique_ids(&self) -> Vec<String> {
        self.techniques.iter().map(|t| t.id.clone()).collect()
    }
}

// ============================================================================
// Parse and compile
// ============================================================================

/// Parse and validate one playbook file. `source` is used for the error text
/// and for the id check (the id must equal the file name without extension).
pub fn parse_playbook(text: &str, source: Option<&Path>) -> Result<Playbook, String> {
    let spec: PlaybookSpec =
        serde_yaml::from_str(text).map_err(|e| format!("YAML parse error: {}", e))?;
    compile(spec, source)
}

pub fn compile(spec: PlaybookSpec, source: Option<&Path>) -> Result<Playbook, String> {
    let id = spec.id.trim().to_string();
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(format!(
            "id '{}' must be lowercase letters, digits and underscores",
            spec.id
        ));
    }
    if let Some(stem) = source.and_then(|p| p.file_stem()).and_then(|s| s.to_str()) {
        if stem != id {
            return Err(format!(
                "id '{}' must equal the file name '{}' so the desktop picker and the engine agree",
                id, stem
            ));
        }
    }
    if spec.title.trim().is_empty() {
        return Err("title is empty".to_string());
    }
    if spec.family.trim().is_empty() {
        return Err("family is empty".to_string());
    }

    let severity = match &spec.severity {
        Some(s) => Severity::parse(s).ok_or_else(|| format!("unknown severity '{}'", s))?,
        None => Severity::Medium,
    };

    // ATT&CK block
    let mitre = &spec.mitre;
    if mitre.attack_version != ATTACK_VERSION {
        return Err(format!(
            "mitre.attack_version is '{}', expected '{}'",
            mitre.attack_version, ATTACK_VERSION
        ));
    }
    if mitre.tactics.is_empty() {
        return Err("mitre.tactics is empty".to_string());
    }
    let mut seen = HashSet::new();
    for tactic in &mitre.tactics {
        if !ATTACK_TACTICS.iter().any(|(name, _, _)| name == tactic) {
            return Err(format!("unknown ATT&CK tactic '{}'", tactic));
        }
        if !seen.insert(tactic.clone()) {
            return Err(format!("tactic '{}' listed twice", tactic));
        }
    }
    if mitre.techniques.is_empty() {
        return Err("mitre.techniques is empty".to_string());
    }
    let mut technique_ids = HashSet::new();
    for t in &mitre.techniques {
        if !is_technique_id(&t.id) {
            return Err(format!(
                "'{}' is not a technique ID like T1059 or T1059.001",
                t.id
            ));
        }
        if let Some((_, replacement)) = RETIRED_TECHNIQUES.iter().find(|(old, _)| *old == t.id) {
            return Err(format!(
                "technique {} was revoked by ATT&CK, use {}",
                t.id, replacement
            ));
        }
        if t.name.trim().is_empty() {
            return Err(format!("technique {} has no name", t.id));
        }
        if !technique_ids.insert(t.id.clone()) {
            return Err(format!("technique {} listed twice", t.id));
        }
    }

    // Rules
    if spec.rules.is_empty() {
        return Err("playbook has no rules".to_string());
    }
    let mut rule_names = HashSet::new();
    let mut rules = Vec::with_capacity(spec.rules.len());
    for rule_spec in spec.rules {
        let name = rule_spec.name.clone();
        if !rule_names.insert(name.clone()) {
            return Err(format!("rule name '{}' used twice", name));
        }
        let rule = compile_rule(rule_spec, severity, &technique_ids, &mitre.techniques)
            .map_err(|e| format!("rule '{}': {}", name, e))?;
        rules.push(rule);
    }

    Ok(Playbook {
        id,
        title: spec.title,
        family: spec.family,
        version: spec.version.unwrap_or_default(),
        description: spec.description.unwrap_or_default().trim().to_string(),
        enabled: spec.enabled,
        severity,
        cooldown_seconds: spec.cooldown_seconds.unwrap_or(DEFAULT_COOLDOWN_SECONDS),
        requires: spec.requires,
        attack_version: spec.mitre.attack_version,
        tactics: spec.mitre.tactics,
        techniques: spec.mitre.techniques,
        rules,
        false_positives: spec.false_positives,
        source_path: source.map(Path::to_path_buf),
    })
}

fn compile_rule(
    spec: RuleSpec,
    default_severity: Severity,
    technique_ids: &HashSet<String>,
    playbook_techniques: &[TechniqueRef],
) -> Result<Rule, String> {
    let severity = match &spec.severity {
        Some(s) => Severity::parse(s).ok_or_else(|| format!("unknown severity '{}'", s))?,
        None => default_severity,
    };

    let first = compile_step(&spec.fact, spec.all, spec.any, spec.exclude)?;
    let then = match spec.then {
        Some(step) => Some(compile_step(&step.fact, step.all, step.any, step.exclude)?),
        None => None,
    };

    let threshold = spec.threshold.unwrap_or(1);
    if threshold == 0 {
        return Err("threshold must be at least 1".to_string());
    }
    if then.is_some() && threshold > 1 {
        return Err("a sequence rule (then) cannot also have a threshold".to_string());
    }
    if let Some(field) = &spec.distinct {
        if threshold < 2 {
            return Err("distinct needs a threshold of 2 or more".to_string());
        }
        check_field_name(field)?;
    }
    let needs_window = threshold > 1 || then.is_some();
    let window_seconds = match spec.window_seconds {
        Some(0) => return Err("window_seconds must be greater than 0".to_string()),
        Some(w) => w,
        None if needs_window => {
            return Err("count and sequence rules need window_seconds".to_string())
        }
        None => DEFAULT_WINDOW_SECONDS,
    };

    let group_by = match spec.group_by.as_deref() {
        None | Some("host") => GroupBy::Host,
        Some("user") => GroupBy::User,
        Some("process") => GroupBy::Process,
        Some(field) => {
            check_field_name(field)?;
            GroupBy::Field(field.to_string())
        }
    };

    let techniques = if spec.techniques.is_empty() {
        playbook_techniques.iter().map(|t| t.id.clone()).collect()
    } else {
        for t in &spec.techniques {
            if !technique_ids.contains(t) {
                return Err(format!(
                    "technique {} is not in the playbook mitre.techniques list",
                    t
                ));
            }
        }
        spec.techniques
    };

    Ok(Rule {
        name: spec.name,
        severity,
        first,
        then,
        threshold,
        distinct: spec.distinct,
        window_seconds,
        group_by,
        techniques,
        tags: spec.tags,
    })
}

fn compile_step(
    fact: &str,
    all: Vec<ConditionSpec>,
    any: Vec<ConditionSpec>,
    exclude: Vec<ConditionSpec>,
) -> Result<Step, String> {
    if !WINDOWS_FACT_TYPES.contains(&fact) {
        return Err(format!(
            "fact type '{}' is not produced by the Windows fact extractor (known: {})",
            fact,
            WINDOWS_FACT_TYPES.join(", ")
        ));
    }
    if all.is_empty() && any.is_empty() {
        return Err("a step needs at least one match or any condition".to_string());
    }
    let compile_all = |specs: Vec<ConditionSpec>| -> Result<Vec<Condition>, String> {
        specs.into_iter().map(compile_condition).collect()
    };
    Ok(Step {
        fact: fact.to_string(),
        all: compile_all(all)?,
        any: compile_all(any)?,
        exclude: compile_all(exclude)?,
    })
}

fn compile_condition(spec: ConditionSpec) -> Result<Condition, String> {
    check_field_name(&spec.field)?;
    let mut ops = Vec::new();
    if let Some(r) = spec.regex {
        ops.push(Op::Regex(compile_regex(&r)?));
    }
    if let Some(r) = spec.not_regex {
        ops.push(Op::NotRegex(compile_regex(&r)?));
    }
    if let Some(v) = spec.equals {
        ops.push(Op::Equals(yaml_scalar(&v)?));
    }
    if let Some(v) = spec.not_equals {
        ops.push(Op::NotEquals(yaml_scalar(&v)?));
    }
    if let Some(vs) = spec.one_of {
        ops.push(Op::In(yaml_list(&vs)?));
    }
    if let Some(vs) = spec.not_in {
        ops.push(Op::NotIn(yaml_list(&vs)?));
    }
    if let Some(b) = spec.exists {
        ops.push(Op::Exists(b));
    }
    if ops.len() != 1 {
        return Err(format!(
            "condition on '{}' needs exactly one of regex, not_regex, equals, not_equals, in, not_in, exists",
            spec.field
        ));
    }
    Ok(Condition {
        field: spec.field,
        op: ops.remove(0),
    })
}

fn compile_regex(pattern: &str) -> Result<Regex, String> {
    Regex::new(pattern).map_err(|e| format!("bad regex '{}': {}", pattern, e))
}

fn yaml_scalar(v: &serde_yaml::Value) -> Result<String, String> {
    match v {
        serde_yaml::Value::String(s) => Ok(s.clone()),
        serde_yaml::Value::Number(n) => Ok(n.to_string()),
        serde_yaml::Value::Bool(b) => Ok(b.to_string()),
        other => Err(format!(
            "expected a string, number or boolean, got {:?}",
            other
        )),
    }
}

fn yaml_list(vs: &[serde_yaml::Value]) -> Result<Vec<String>, String> {
    if vs.is_empty() {
        return Err("an in or not_in list cannot be empty".to_string());
    }
    vs.iter().map(yaml_scalar).collect()
}

/// Lowercase names must be view fields. Anything else is taken as a raw Windows
/// event field name, which starts with an uppercase letter (CommandLine) or uses
/// the capture prefix (windows.event_id).
fn check_field_name(field: &str) -> Result<(), String> {
    let first = field.chars().next().ok_or("empty field name")?;
    if first.is_ascii_lowercase() && !field.starts_with("windows.") {
        if VIEW_FIELDS.contains(&field) {
            return Ok(());
        }
        return Err(format!(
            "unknown field '{}'. Use a view field ({}) or a raw Windows field name",
            field,
            VIEW_FIELDS.join(", ")
        ));
    }
    if field
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        Ok(())
    } else {
        Err(format!("field name '{}' has unexpected characters", field))
    }
}

fn is_technique_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    let base_ok =
        bytes.len() >= 5 && bytes[0] == b'T' && bytes[1..5].iter().all(u8::is_ascii_digit);
    match bytes.len() {
        5 => base_ok,
        9 => base_ok && bytes[5] == b'.' && bytes[6..9].iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
id: test_playbook
title: "Test"
family: execution
severity: HIGH
mitre:
  attack_version: "20.1"
  tactics: [execution]
  techniques:
    - { id: T1059.001, name: "PowerShell" }
rules:
  - name: "PowerShell run"
    fact: Exec
    match:
      - { field: image, equals: powershell.exe }
"#;

    #[test]
    fn test_minimal_playbook_compiles() {
        let pb = parse_playbook(MINIMAL, None).expect("minimal playbook should compile");
        assert_eq!(pb.id, "test_playbook");
        assert_eq!(pb.rules.len(), 1);
        assert_eq!(pb.rules[0].severity, Severity::High);
        assert_eq!(pb.rules[0].techniques, vec!["T1059.001".to_string()]);
    }

    #[test]
    fn test_unknown_key_is_rejected() {
        let text = MINIMAL.replace("    fact: Exec", "    fact: Exec\n    treshold: 3");
        let err = parse_playbook(&text, None).unwrap_err();
        assert!(err.contains("treshold"), "{}", err);
    }

    #[test]
    fn test_retired_technique_is_rejected() {
        let text = MINIMAL.replace(
            "T1059.001, name: \"PowerShell\"",
            "T1562.001, name: \"Old\"",
        );
        let err = parse_playbook(&text, None).unwrap_err();
        assert!(err.contains("T1685"), "{}", err);
    }

    #[test]
    fn test_unknown_tactic_is_rejected() {
        let text = MINIMAL.replace("tactics: [execution]", "tactics: [defense_evasion]");
        let err = parse_playbook(&text, None).unwrap_err();
        assert!(err.contains("defense_evasion"), "{}", err);
    }

    #[test]
    fn test_typo_in_field_name_is_rejected() {
        let text = MINIMAL.replace("field: image", "field: imgae");
        let err = parse_playbook(&text, None).unwrap_err();
        assert!(err.contains("imgae"), "{}", err);
    }

    #[test]
    fn test_bad_regex_is_rejected() {
        let text = MINIMAL.replace("equals: powershell.exe", "regex: \"(unclosed\"");
        let err = parse_playbook(&text, None).unwrap_err();
        assert!(err.contains("bad regex"), "{}", err);
    }

    #[test]
    fn test_count_rule_needs_window() {
        let text = MINIMAL.replace("    fact: Exec", "    fact: Exec\n    threshold: 3");
        let err = parse_playbook(&text, None).unwrap_err();
        assert!(err.contains("window_seconds"), "{}", err);
    }

    #[test]
    fn test_id_must_match_file_name() {
        let err = parse_playbook(MINIMAL, Some(Path::new("other_name.yaml"))).unwrap_err();
        assert!(err.contains("other_name"), "{}", err);
        assert!(parse_playbook(MINIMAL, Some(Path::new("dir/test_playbook.yaml"))).is_ok());
    }

    #[test]
    fn test_technique_id_format() {
        assert!(is_technique_id("T1059"));
        assert!(is_technique_id("T1059.001"));
        assert!(!is_technique_id("T159"));
        assert!(!is_technique_id("T1059.1"));
        assert!(!is_technique_id("TA0002"));
    }
}
