use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const MANIFEST_NAME: &str = "envault.toml";

pub fn find_manifest(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let candidate = d.join(MANIFEST_NAME);
        if candidate.exists() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

#[derive(Debug)]
pub struct Manifest {
    pub path: PathBuf,
    pub mappings: BTreeMap<String, String>,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Manifest> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let value: toml::Value = raw
            .parse()
            .with_context(|| format!("parsing {}", path.display()))?;
        let table = value.as_table().context("envault.toml must be a TOML table")?;
        let mut mappings = BTreeMap::new();
        for (k, v) in table {
            match v.as_str() {
                Some(alias) => {
                    mappings.insert(k.clone(), alias.to_string());
                }
                None => bail!(
                    "envault.toml must contain only flat ENV_VAR = \"alias\" pairs (offending key: {k})"
                ),
            }
        }
        Ok(Manifest { path: path.to_path_buf(), mappings })
    }

    pub fn save(&self) -> Result<()> {
        let mut out = String::from(
            "# envault manifest: ENV_VAR = \"vault alias\" (names only, no secrets)\n",
        );
        for (k, v) in &self.mappings {
            out.push_str(&format!("{k} = \"{v}\"\n"));
        }
        std::fs::write(&self.path, out)
            .with_context(|| format!("writing {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn find_walks_up() {
        let root = TempDir::new().unwrap();
        std::fs::write(root.path().join(MANIFEST_NAME), "").unwrap();
        let nested = root.path().join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        let found = find_manifest(&nested).unwrap();
        assert_eq!(found, root.path().join(MANIFEST_NAME));
        let elsewhere = TempDir::new().unwrap();
        assert!(find_manifest(elsewhere.path()).is_none());
    }

    #[test]
    fn load_save_roundtrip_flat_pairs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(MANIFEST_NAME);
        std::fs::write(&path, "OPENROUTER_API_KEY = \"openrouter\"\n").unwrap();
        let mut m = Manifest::load(&path).unwrap();
        assert_eq!(m.mappings["OPENROUTER_API_KEY"], "openrouter");
        m.mappings.insert("OTHER_KEY".into(), "other".into());
        m.save().unwrap();
        let re = Manifest::load(&path).unwrap();
        assert_eq!(re.mappings.len(), 2);
        assert_eq!(re.mappings["OTHER_KEY"], "other");
    }

    #[test]
    fn non_flat_manifest_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(MANIFEST_NAME);
        std::fs::write(&path, "[table]\nkey = \"x\"\n").unwrap();
        let err = Manifest::load(&path).unwrap_err().to_string();
        assert!(err.contains("flat"), "got: {err}");
    }
}
