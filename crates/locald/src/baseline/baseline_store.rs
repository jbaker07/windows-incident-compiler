// locald/baseline/baseline_store.rs
// Load/save baselines to persistent storage (JSON)

use super::types::HostBaseline;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

pub struct BaselineStore {
    baselines: HashMap<String, HostBaseline>,
    baselines_dir: PathBuf,
}

impl BaselineStore {
    pub fn new(baselines_dir: PathBuf) -> Self {
        // Ensure directory exists
        let _ = fs::create_dir_all(&baselines_dir);

        Self {
            baselines: HashMap::new(),
            baselines_dir,
        }
    }

    /// Load all host baselines from disk
    pub fn load_all(&mut self) -> std::io::Result<()> {
        if !self.baselines_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&self.baselines_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().is_some_and(|ext| ext == "json") {
                if let Ok(contents) = fs::read_to_string(&path) {
                    if let Ok(baseline) = serde_json::from_str::<HostBaseline>(&contents) {
                        self.baselines.insert(baseline.host.clone(), baseline);
                    }
                }
            }
        }

        Ok(())
    }

    /// Load or create baseline for a specific host
    pub fn get_or_create(&mut self, host: &str) -> &mut HostBaseline {
        let baselines = &mut self.baselines;
        baselines.entry(host.to_string()).or_insert_with(|| {
            // Try to load from disk first
            let filename = format!("baselines_{}.json", host);
            let path = self.baselines_dir.join(&filename);

            if path.exists() {
                if let Ok(contents) = fs::read_to_string(&path) {
                    if let Ok(baseline) = serde_json::from_str::<HostBaseline>(&contents) {
                        return baseline;
                    }
                }
            }

            // Create new baseline
            HostBaseline::new(host.to_string())
        })
    }

    /// Save baseline for a specific host
    pub fn save(&self, host: &str) -> std::io::Result<()> {
        if let Some(baseline) = self.baselines.get(host) {
            let filename = format!("baselines_{}.json", host);
            let path = self.baselines_dir.join(&filename);
            let json = serde_json::to_string_pretty(baseline)?;
            fs::write(path, json)?;
        }
        Ok(())
    }

    /// Save all baselines
    pub fn save_all(&self) -> std::io::Result<()> {
        for host in self.baselines.keys() {
            self.save(host)?;
        }
        Ok(())
    }

    /// Get baseline (read-only)
    pub fn get(&self, host: &str) -> Option<&HostBaseline> {
        self.baselines.get(host)
    }

    /// Get mutable baseline
    pub fn get_mut(&mut self, host: &str) -> Option<&mut HostBaseline> {
        self.baselines.get_mut(host)
    }

    /// List all loaded hosts
    pub fn list_hosts(&self) -> Vec<String> {
        self.baselines.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_baseline_store_create() {
        let temp_dir = TempDir::new().unwrap();
        let store = BaselineStore::new(temp_dir.path().to_path_buf());
        assert!(store.baselines.is_empty());
    }

    #[test]
    fn test_baseline_store_get_or_create() {
        let temp_dir = TempDir::new().unwrap();
        let mut store = BaselineStore::new(temp_dir.path().to_path_buf());

        let baseline = store.get_or_create("host1");
        assert_eq!(baseline.host, "host1");

        let baseline2 = store.get_or_create("host1");
        assert_eq!(baseline2.host, "host1");
        assert_eq!(store.list_hosts().len(), 1);
    }

    #[test]
    fn test_baseline_store_persistence() {
        let temp_dir = TempDir::new().unwrap();
        {
            let mut store = BaselineStore::new(temp_dir.path().to_path_buf());
            let baseline = store.get_or_create("host1");
            baseline.last_updated_ts = 12345;
            let _ = store.save("host1");
        }

        {
            let mut store = BaselineStore::new(temp_dir.path().to_path_buf());
            let _ = store.load_all();
            let baseline = store.get("host1");
            assert!(baseline.is_some());
            assert_eq!(baseline.unwrap().last_updated_ts, 12345);
        }
    }
}
