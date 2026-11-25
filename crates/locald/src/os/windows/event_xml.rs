//! Lift Windows EventData fields out of the rendered event XML.
//!
//! The capture agent stores the system fields (channel, event ID, provider) as
//! separate keys and the rest of the event as XML in `windows.xml`. The fact
//! extractor and the playbooks read named fields such as `CommandLine` or
//! `TargetUserName`, so before extraction edr-locald copies every
//! `<Data Name="X">value</Data>` element, and the simple elements under
//! `<UserData>` (used by event 1102), into the event fields.
//!
//! Fields that are already present are never overwritten, so events that were
//! produced with flat fields (imports, tests, scripts) behave the same as before.

use edr_core::Event;
use regex::Regex;
use std::sync::OnceLock;

const XML_FIELD: &str = "windows.xml";

fn data_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?s)<Data\s+Name\s*=\s*['"]([^'"]+)['"]\s*(?:/>|>(.*?)</Data>)"#)
            .expect("static regex")
    })
}

fn element_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"<([A-Za-z_][A-Za-z0-9_.-]*)>([^<]*)</([A-Za-z_][A-Za-z0-9_.-]*)>")
            .expect("static regex")
    })
}

/// Copy EventData and UserData fields from `windows.xml` into `event.fields`.
/// Returns how many fields were added.
pub fn flatten_event_xml(event: &mut Event) -> usize {
    let xml = match event.fields.get(XML_FIELD).and_then(|v| v.as_str()) {
        Some(x) => x.to_string(),
        None => return 0,
    };

    let mut added = 0;
    if let Some(section) = section(&xml, "EventData") {
        for cap in data_regex().captures_iter(section) {
            let name = cap[1].to_string();
            let value = cap.get(2).map(|m| unescape(m.as_str())).unwrap_or_default();
            added += insert_if_absent(event, name, value);
        }
    }
    if let Some(section) = section(&xml, "UserData") {
        for cap in element_regex().captures_iter(section) {
            if cap[1] == cap[3] {
                added += insert_if_absent(event, cap[1].to_string(), unescape(&cap[2]));
            }
        }
    }
    added
}

fn insert_if_absent(event: &mut Event, name: String, value: String) -> usize {
    if event.fields.contains_key(&name) {
        return 0;
    }
    event.fields.insert(name, serde_json::Value::String(value));
    1
}

/// Text between `<tag ...>` and `</tag>`, if both are present.
fn section<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = xml.find(&format!("<{}", tag))?;
    let body_start = open + xml[open..].find('>')? + 1;
    let close = xml[body_start..].find(&format!("</{}>", tag))?;
    Some(&xml[body_start..body_start + close])
}

/// Decode the five XML entities and numeric character references.
fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp..];
        let Some(semi) = after.find(';').filter(|i| *i <= 10) else {
            out.push('&');
            rest = &after[1..];
            continue;
        };
        let entity = &after[1..semi];
        let decoded = match entity {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e if e.starts_with("#x") || e.starts_with("#X") => u32::from_str_radix(&e[2..], 16)
                .ok()
                .and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &after[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &after[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn event_with_xml(xml: &str) -> Event {
        let mut fields = BTreeMap::new();
        fields.insert("windows.event_id".into(), serde_json::json!(4688));
        fields.insert(XML_FIELD.into(), serde_json::json!(xml));
        Event {
            ts_ms: 0,
            host: "WS01".into(),
            tags: vec![],
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptr: None,
            fields,
        }
    }

    #[test]
    fn test_event_data_fields_are_lifted() {
        let xml = "<Event><System><EventID>4688</EventID></System><EventData>\
            <Data Name='SubjectUserName'>alice</Data>\
            <Data Name='NewProcessName'>C:\\Windows\\System32\\cmd.exe</Data>\
            <Data Name='CommandLine'>cmd.exe /c echo &quot;a &amp; b&quot; &gt; out.txt</Data>\
            <Data Name='TargetUserName'/>\
            </EventData></Event>";
        let mut e = event_with_xml(xml);
        assert_eq!(flatten_event_xml(&mut e), 4);
        assert_eq!(e.fields["SubjectUserName"], "alice");
        assert_eq!(e.fields["NewProcessName"], "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(
            e.fields["CommandLine"],
            "cmd.exe /c echo \"a & b\" > out.txt"
        );
        assert_eq!(e.fields["TargetUserName"], "");
    }

    #[test]
    fn test_existing_fields_win() {
        let mut e = event_with_xml(
            "<Event><EventData><Data Name=\"CommandLine\">from xml</Data></EventData></Event>",
        );
        e.fields
            .insert("CommandLine".into(), serde_json::json!("already set"));
        assert_eq!(flatten_event_xml(&mut e), 0);
        assert_eq!(e.fields["CommandLine"], "already set");
    }

    #[test]
    fn test_user_data_fields_are_lifted() {
        let xml = "<Event><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>\
            <SubjectUserName>alice</SubjectUserName><SubjectDomainName>CORP</SubjectDomainName>\
            </LogFileCleared></UserData></Event>";
        let mut e = event_with_xml(xml);
        assert_eq!(flatten_event_xml(&mut e), 2);
        assert_eq!(e.fields["SubjectUserName"], "alice");
    }

    #[test]
    fn test_unescape() {
        assert_eq!(
            unescape("a &lt;b&gt; &#65;&#x42; &amp;amp;"),
            "a <b> AB &amp;"
        );
        assert_eq!(unescape("no entities"), "no entities");
        assert_eq!(unescape("lonely & sign"), "lonely & sign");
    }
}
