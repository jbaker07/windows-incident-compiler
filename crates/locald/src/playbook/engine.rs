//! Playbook engine: runs compiled YAML rules over facts.
//!
//! For every fact the engine looks up the rules that read that fact type, checks
//! their conditions against a `FactView`, and keeps a small amount of state per
//! (rule, group) so it can handle three rule shapes:
//!
//! * single event: one matching fact fires the rule
//! * count: `threshold` matching facts (or distinct values of one field) inside
//!   `window_seconds`
//! * sequence: a fact matching `first`, then a fact matching `then` for the same
//!   group inside `window_seconds`
//!
//! Time comes from the fact timestamps, not the wall clock, so replaying old
//! segments gives the same result as live capture. After a rule fires for a
//! group it stays quiet for that group for the playbook `cooldown_seconds`.

use super::fields::{fact_type_name, normalize_user, FactView};
use super::schema::{Condition, GroupBy, Op, Playbook, Rule, Step};
use crate::hypothesis::Fact;
use edr_core::Event;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};

/// A fact that took part in a match, with the rule step it satisfied (1 or 2).
#[derive(Debug, Clone)]
pub struct MatchedFact {
    pub step: u8,
    pub fact: Fact,
}

/// One rule firing. This is what edr-locald turns into a signal row.
#[derive(Debug, Clone)]
pub struct PlaybookMatch {
    pub signal_id: String,
    pub playbook_id: String,
    pub playbook_title: String,
    pub family: String,
    pub rule_name: String,
    pub severity: String,
    pub techniques: Vec<String>,
    pub tactics: Vec<String>,
    pub attack_version: String,
    pub group_by: String,
    pub group_key: String,
    pub host: String,
    pub tags: Vec<String>,
    pub first_ts_ms: i64,
    pub last_ts_ms: i64,
    pub facts: Vec<MatchedFact>,
}

#[derive(Debug, Clone)]
struct Hit {
    ts_ms: i64,
    distinct: Option<String>,
    fact: Fact,
}

#[derive(Debug, Default)]
struct RuleState {
    hits: VecDeque<Hit>,
    pending: VecDeque<Hit>,
    last_fire_ms: Option<i64>,
}

/// (playbook index, rule index, step number)
type RuleRef = (usize, usize, u8);

pub struct PlaybookEngine {
    playbooks: Vec<Playbook>,
    by_fact_type: HashMap<String, Vec<RuleRef>>,
    state: HashMap<(usize, usize, String), RuleState>,
    /// Facts processed since state was last pruned.
    since_prune: u32,
}

impl PlaybookEngine {
    pub fn new(playbooks: Vec<Playbook>) -> Self {
        let mut by_fact_type: HashMap<String, Vec<RuleRef>> = HashMap::new();
        for (pi, pb) in playbooks.iter().enumerate() {
            for (ri, rule) in pb.rules.iter().enumerate() {
                by_fact_type
                    .entry(rule.first.fact.clone())
                    .or_default()
                    .push((pi, ri, 1));
                if let Some(then) = &rule.then {
                    by_fact_type
                        .entry(then.fact.clone())
                        .or_default()
                        .push((pi, ri, 2));
                }
            }
        }
        Self {
            playbooks,
            by_fact_type,
            state: HashMap::new(),
            since_prune: 0,
        }
    }

    pub fn playbooks(&self) -> &[Playbook] {
        &self.playbooks
    }

    pub fn playbook(&self, id: &str) -> Option<&Playbook> {
        self.playbooks.iter().find(|p| p.id == id)
    }

    pub fn rule_count(&self) -> usize {
        self.playbooks.iter().map(|p| p.rules.len()).sum()
    }

    /// Evaluate the facts extracted from one event. Facts with the same fact_id
    /// (the extractor can emit the same fact twice when an event carries two
    /// routing tags) are evaluated once.
    pub fn process(&mut self, event: &Event, facts: &[Fact]) -> Vec<PlaybookMatch> {
        let mut matches = Vec::new();
        let mut seen_ids = HashSet::new();
        for fact in facts {
            if !seen_ids.insert(fact.fact_id.as_str()) {
                continue;
            }
            matches.extend(self.process_fact(event, fact));
        }
        matches
    }

    fn process_fact(&mut self, event: &Event, fact: &Fact) -> Vec<PlaybookMatch> {
        self.since_prune += 1;
        let ts_ms = fact.ts.timestamp_millis();
        if self.since_prune >= 1000 {
            self.since_prune = 0;
            self.prune(ts_ms);
        }

        let refs = match self.by_fact_type.get(fact_type_name(fact)) {
            Some(r) => r.clone(),
            None => return Vec::new(),
        };

        let view = FactView::new(fact, event);
        let mut out = Vec::new();
        for (pi, ri, step_no) in refs {
            let playbook = &self.playbooks[pi];
            let rule = &playbook.rules[ri];
            let step = if step_no == 1 {
                &rule.first
            } else {
                match &rule.then {
                    Some(s) => s,
                    None => continue,
                }
            };
            if !step_matches(step, &view) {
                continue;
            }

            let group_key = group_key(&rule.group_by, &view);
            let window_ms = (rule.window_seconds as i64) * 1000;
            let cooldown_ms = (playbook.cooldown_seconds as i64) * 1000;
            let state = self.state.entry((pi, ri, group_key.clone())).or_default();

            let fired: Option<Vec<MatchedFact>> = if rule.then.is_some() {
                if step_no == 1 {
                    state.pending.push_back(Hit {
                        ts_ms,
                        distinct: None,
                        fact: fact.clone(),
                    });
                    while state
                        .pending
                        .front()
                        .is_some_and(|h| ts_ms - h.ts_ms > window_ms)
                    {
                        state.pending.pop_front();
                    }
                    None
                } else {
                    // The most recent first step that happened at or before this
                    // fact and inside the window completes the sequence.
                    state
                        .pending
                        .retain(|h| h.ts_ms <= ts_ms && ts_ms - h.ts_ms <= window_ms);
                    match state.pending.back().cloned() {
                        Some(first) => {
                            state.pending.clear();
                            Some(vec![
                                MatchedFact {
                                    step: 1,
                                    fact: first.fact,
                                },
                                MatchedFact {
                                    step: 2,
                                    fact: fact.clone(),
                                },
                            ])
                        }
                        None => None,
                    }
                }
            } else {
                let distinct = match &rule.distinct {
                    Some(field) => match view.get(field) {
                        Some(v) => Some(v.to_lowercase()),
                        // A hit without the distinct field cannot count.
                        None => continue,
                    },
                    None => None,
                };
                state.hits.push_back(Hit {
                    ts_ms,
                    distinct,
                    fact: fact.clone(),
                });
                while state
                    .hits
                    .front()
                    .is_some_and(|h| ts_ms - h.ts_ms > window_ms)
                {
                    state.hits.pop_front();
                }
                let count = if rule.distinct.is_some() {
                    state
                        .hits
                        .iter()
                        .filter_map(|h| h.distinct.as_deref())
                        .collect::<HashSet<_>>()
                        .len()
                } else {
                    state.hits.len()
                };
                if count >= rule.threshold as usize {
                    let facts = state
                        .hits
                        .drain(..)
                        .map(|h| MatchedFact {
                            step: 1,
                            fact: h.fact,
                        })
                        .collect();
                    Some(facts)
                } else {
                    None
                }
            };

            let Some(facts) = fired else { continue };
            if let Some(last) = state.last_fire_ms {
                if ts_ms >= last && ts_ms - last < cooldown_ms {
                    continue;
                }
            }
            state.last_fire_ms = Some(ts_ms);
            out.push(build_match(playbook, rule, &group_key, facts));
        }
        out
    }

    /// Drop state that can no longer contribute to a match.
    fn prune(&mut self, now_ms: i64) {
        let playbooks = &self.playbooks;
        self.state.retain(|(pi, ri, _), st| {
            let pb = &playbooks[*pi];
            let rule = &pb.rules[*ri];
            let horizon = (rule.window_seconds.max(pb.cooldown_seconds) as i64) * 1000;
            let recent = |ts: i64| now_ms - ts <= horizon;
            st.hits.back().is_some_and(|h| recent(h.ts_ms))
                || st.pending.back().is_some_and(|h| recent(h.ts_ms))
                || st.last_fire_ms.is_some_and(recent)
        });
    }
}

fn step_matches(step: &Step, view: &FactView) -> bool {
    step.all.iter().all(|c| condition_matches(c, view))
        && (step.any.is_empty() || step.any.iter().any(|c| condition_matches(c, view)))
        && !step.exclude.iter().any(|c| condition_matches(c, view))
}

/// A condition on a missing field is false, except `exists: false`. That keeps
/// negative operators (not_regex, not_equals, not_in) from firing on events
/// that simply lack the field.
pub fn condition_matches(cond: &Condition, view: &FactView) -> bool {
    let value = view.get(&cond.field);
    match (&cond.op, value) {
        (Op::Exists(want), v) => v.is_some() == *want,
        (_, None) => false,
        (Op::Regex(re), Some(v)) => re.is_match(&v),
        (Op::NotRegex(re), Some(v)) => !re.is_match(&v),
        (Op::Equals(want), Some(v)) => v.eq_ignore_ascii_case(want),
        (Op::NotEquals(want), Some(v)) => !v.eq_ignore_ascii_case(want),
        (Op::In(list), Some(v)) => list.iter().any(|w| v.eq_ignore_ascii_case(w)),
        (Op::NotIn(list), Some(v)) => !list.iter().any(|w| v.eq_ignore_ascii_case(w)),
    }
}

fn group_key(group_by: &GroupBy, view: &FactView) -> String {
    let host = view.get("host").unwrap_or_default();
    let value = match group_by {
        GroupBy::Host => String::new(),
        GroupBy::User => view
            .get("user")
            .map(|u| normalize_user(&u))
            .unwrap_or_default(),
        GroupBy::Process => view.get("process").unwrap_or_default(),
        GroupBy::Field(f) => view.get(f).map(|v| v.to_lowercase()).unwrap_or_default(),
    };
    if value.is_empty() {
        host
    } else {
        format!("{}|{}", host, value)
    }
}

fn build_match(
    playbook: &Playbook,
    rule: &Rule,
    group_key: &str,
    facts: Vec<MatchedFact>,
) -> PlaybookMatch {
    let first_ts_ms = facts
        .iter()
        .map(|f| f.fact.ts.timestamp_millis())
        .min()
        .unwrap_or(0);
    let last_ts_ms = facts
        .iter()
        .map(|f| f.fact.ts.timestamp_millis())
        .max()
        .unwrap_or(0);
    let host = facts
        .first()
        .map(|f| f.fact.host_id.clone())
        .unwrap_or_default();

    let mut hasher = Sha256::new();
    hasher.update(playbook.id.as_bytes());
    hasher.update(b"\0");
    hasher.update(rule.name.as_bytes());
    hasher.update(b"\0");
    hasher.update(group_key.as_bytes());
    for f in &facts {
        hasher.update(b"\0");
        hasher.update(f.fact.fact_id.as_bytes());
    }
    let signal_id = format!("sig_{}", hex::encode(&hasher.finalize()[..16]));

    PlaybookMatch {
        signal_id,
        playbook_id: playbook.id.clone(),
        playbook_title: playbook.title.clone(),
        family: playbook.family.clone(),
        rule_name: rule.name.clone(),
        severity: rule.severity.as_str().to_string(),
        techniques: rule.techniques.clone(),
        tactics: playbook.tactics.clone(),
        attack_version: playbook.attack_version.clone(),
        group_by: rule.group_by.describe(),
        group_key: group_key.to_string(),
        host,
        tags: rule.tags.clone(),
        first_ts_ms,
        last_ts_ms,
        facts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::windows::extract_facts;
    use crate::playbook::schema::parse_playbook;
    use std::collections::BTreeMap;

    fn exec_event(ts_ms: i64, image: &str, cmdline: &str, user: &str) -> Event {
        let mut fields = BTreeMap::new();
        fields.insert("windows.event_id".into(), serde_json::json!(4688));
        fields.insert("windows.channel".into(), serde_json::json!("Security"));
        fields.insert("NewProcessName".into(), serde_json::json!(image));
        fields.insert("CommandLine".into(), serde_json::json!(cmdline));
        fields.insert("SubjectUserName".into(), serde_json::json!(user));
        Event {
            ts_ms,
            host: "WS01".into(),
            tags: vec!["windows".into()],
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptr: None,
            fields,
        }
    }

    fn engine(yaml: &str) -> PlaybookEngine {
        PlaybookEngine::new(vec![parse_playbook(yaml, None).expect("valid playbook")])
    }

    fn run(engine: &mut PlaybookEngine, events: &[Event]) -> Vec<PlaybookMatch> {
        events
            .iter()
            .flat_map(|e| {
                let facts = extract_facts(e);
                engine.process(e, &facts)
            })
            .collect()
    }

    const HEADER: &str = r#"
id: t
title: "T"
family: discovery
mitre:
  attack_version: "20.1"
  tactics: [discovery]
  techniques:
    - { id: T1033, name: "System Owner/User Discovery" }
"#;

    #[test]
    fn test_count_rule_with_distinct_values() {
        let yaml = format!(
            "{}rules:\n  - name: burst\n    fact: Exec\n    threshold: 3\n    distinct: cmdline\n    window_seconds: 60\n    group_by: user\n    match:\n      - {{ field: image, equals: whoami.exe }}\n",
            HEADER
        );
        let mut e = engine(&yaml);
        let same = (0..3)
            .map(|i| {
                exec_event(
                    1_000 + i * 1000,
                    "C:\\Windows\\System32\\whoami.exe",
                    "whoami",
                    "alice",
                )
            })
            .collect::<Vec<_>>();
        assert!(
            run(&mut e, &same).is_empty(),
            "three identical commands are one distinct value"
        );

        let mut e = engine(&yaml);
        let distinct = vec![
            exec_event(
                1_000,
                "C:\\Windows\\System32\\whoami.exe",
                "whoami",
                "alice",
            ),
            exec_event(
                2_000,
                "C:\\Windows\\System32\\whoami.exe",
                "whoami /priv",
                "alice",
            ),
            exec_event(
                3_000,
                "C:\\Windows\\System32\\whoami.exe",
                "whoami /groups",
                "alice",
            ),
        ];
        let m = run(&mut e, &distinct);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].facts.len(), 3);
        assert_eq!(m[0].group_key, "WS01|alice");
    }

    #[test]
    fn test_count_rule_window_expires() {
        let yaml = format!(
            "{}rules:\n  - name: burst\n    fact: Exec\n    threshold: 2\n    window_seconds: 10\n    match:\n      - {{ field: image, equals: whoami.exe }}\n",
            HEADER
        );
        let mut e = engine(&yaml);
        let events = vec![
            exec_event(1_000, "C:\\w\\whoami.exe", "whoami", "a"),
            exec_event(30_000, "C:\\w\\whoami.exe", "whoami", "a"),
        ];
        assert!(
            run(&mut e, &events).is_empty(),
            "hits 29 seconds apart do not share a 10 second window"
        );
    }

    #[test]
    fn test_cooldown_suppresses_repeat() {
        let yaml = format!(
            "{}cooldown_seconds: 60\nrules:\n  - name: one\n    fact: Exec\n    match:\n      - {{ field: image, equals: whoami.exe }}\n",
            HEADER
        );
        let mut e = engine(&yaml);
        let events = vec![
            exec_event(1_000, "C:\\w\\whoami.exe", "whoami", "a"),
            exec_event(2_000, "C:\\w\\whoami.exe", "whoami /all", "a"),
            exec_event(70_000, "C:\\w\\whoami.exe", "whoami /all", "a"),
        ];
        let m = run(&mut e, &events);
        assert_eq!(
            m.len(),
            2,
            "second hit is inside the cooldown, third is after it"
        );
    }

    #[test]
    fn test_sequence_rule_needs_order() {
        let yaml = format!(
            "{}rules:\n  - name: seq\n    fact: Exec\n    window_seconds: 60\n    group_by: user\n    match:\n      - {{ field: image, equals: whoami.exe }}\n    then:\n      fact: Exec\n      match:\n        - {{ field: image, equals: hostname.exe }}\n",
            HEADER
        );
        let mut e = engine(&yaml);
        let wrong_order = vec![
            exec_event(1_000, "C:\\w\\hostname.exe", "hostname", "a"),
            exec_event(2_000, "C:\\w\\whoami.exe", "whoami", "a"),
        ];
        assert!(run(&mut e, &wrong_order).is_empty());

        let mut e = engine(&yaml);
        let right_order = vec![
            exec_event(1_000, "C:\\w\\whoami.exe", "whoami", "a"),
            exec_event(2_000, "C:\\w\\hostname.exe", "hostname", "a"),
        ];
        let m = run(&mut e, &right_order);
        assert_eq!(m.len(), 1);
        assert_eq!(
            m[0].facts.iter().map(|f| f.step).collect::<Vec<_>>(),
            vec![1, 2]
        );

        let mut e = engine(&yaml);
        let other_user = vec![
            exec_event(1_000, "C:\\w\\whoami.exe", "whoami", "a"),
            exec_event(2_000, "C:\\w\\hostname.exe", "hostname", "b"),
        ];
        assert!(
            run(&mut e, &other_user).is_empty(),
            "steps by different users do not join"
        );
    }

    #[test]
    fn test_missing_field_never_matches_negative_operator() {
        let yaml = format!(
            "{}rules:\n  - name: neg\n    fact: Exec\n    match:\n      - {{ field: ParentImage, not_regex: \"explorer\" }}\n",
            HEADER
        );
        let mut e = engine(&yaml);
        let events = vec![exec_event(1_000, "C:\\w\\whoami.exe", "whoami", "a")];
        assert!(run(&mut e, &events).is_empty());
    }

    #[test]
    fn test_signal_id_is_deterministic() {
        let yaml = format!(
            "{}rules:\n  - name: one\n    fact: Exec\n    match:\n      - {{ field: image, equals: whoami.exe }}\n",
            HEADER
        );
        let events = vec![exec_event(1_000, "C:\\w\\whoami.exe", "whoami", "a")];
        let a = run(&mut engine(&yaml), &events);
        let b = run(&mut engine(&yaml), &events);
        assert_eq!(a[0].signal_id, b[0].signal_id);
        assert!(a[0].signal_id.starts_with("sig_"));
    }
}
