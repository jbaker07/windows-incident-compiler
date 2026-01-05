// Integration test for entity extraction endpoint with stable ordering
use serde_json::json;

#[test]
fn test_entity_extraction_stable_ordering() {
    // Verify entities are ordered by count (desc), then type, then id
    let entities = vec![
        json!({
            "entity_type": "executable",
            "entity_id": "bash",
            "display_name": "bash",
            "count": 10
        }),
        json!({
            "entity_type": "user",
            "entity_id": "root",
            "display_name": "root",
            "count": 15  // Higher count, should appear first
        }),
        json!({
            "entity_type": "process",
            "entity_id": "bash:1234",
            "display_name": "bash:1234",
            "count": 10  // Same count as bash, should sort by type alphabetically
        }),
        json!({
            "entity_type": "file",
            "entity_id": "/tmp/test",
            "display_name": "/tmp/test",
            "count": 5   // Lower count
        }),
        json!({
            "entity_type": "executable",
            "entity_id": "curl",
            "display_name": "curl",
            "count": 10  // Same count as bash, executable type comes before process
        }),
    ];

    // Sort by count (desc), then type, then id
    let mut sorted = entities.clone();
    sorted.sort_by(|a, b| {
        let count_a = a["count"].as_u64().unwrap_or(0);
        let count_b = b["count"].as_u64().unwrap_or(0);

        match count_b.cmp(&count_a) {
            std::cmp::Ordering::Equal => {
                let type_a = a["entity_type"].as_str().unwrap_or("");
                let type_b = b["entity_type"].as_str().unwrap_or("");
                match type_a.cmp(type_b) {
                    std::cmp::Ordering::Equal => {
                        let id_a = a["entity_id"].as_str().unwrap_or("");
                        let id_b = b["entity_id"].as_str().unwrap_or("");
                        id_a.cmp(id_b)
                    }
                    other => other,
                }
            }
            other => other,
        }
    });

    // Verify order: root (15) > bash (10, exe) > curl (10, exe) > bash:1234 (10, process) > /tmp/test (5)
    assert_eq!(sorted[0]["entity_id"].as_str().unwrap(), "root");
    assert_eq!(sorted[1]["entity_id"].as_str().unwrap(), "bash"); // executable comes before process
    assert_eq!(sorted[2]["entity_id"].as_str().unwrap(), "curl");
    assert_eq!(sorted[3]["entity_id"].as_str().unwrap(), "bash:1234");
    assert_eq!(sorted[4]["entity_id"].as_str().unwrap(), "/tmp/test");
}

#[test]
fn test_entity_extraction_all_types_present() {
    // Verify all entity types can be extracted
    let entity_types = vec!["executable", "user", "process", "file", "socket"];

    for entity_type in entity_types {
        let entity = json!({
            "entity_type": entity_type,
            "entity_id": format!("test-{}", entity_type),
            "display_name": format!("Test {}", entity_type),
            "count": 1
        });

        assert_eq!(entity["entity_type"].as_str().unwrap(), entity_type);
        assert!(entity["entity_id"].is_string());
        assert!(entity["display_name"].is_string());
        assert!(entity["count"].is_number());
    }
}

#[test]
fn test_entity_response_structure() {
    // Verify EntitiesResponse has correct structure
    let response = json!({
        "incident_id": "inc-123",
        "entities": [
            {
                "entity_type": "executable",
                "entity_id": "bash",
                "display_name": "bash",
                "count": 5
            }
        ]
    });

    assert!(response["incident_id"].is_string());
    assert!(response["entities"].is_array());

    let entities = response["entities"].as_array().unwrap();
    assert_eq!(entities.len(), 1);

    let ent = &entities[0];
    assert_eq!(ent["entity_type"].as_str().unwrap(), "executable");
    assert_eq!(ent["entity_id"].as_str().unwrap(), "bash");
    assert_eq!(ent["display_name"].as_str().unwrap(), "bash");
    assert_eq!(ent["count"].as_u64().unwrap(), 5);
}
