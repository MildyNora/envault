use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// The canonical, harness-neutral skill text. Single source of truth: the same
/// file backs the Claude Code plugin and every `skill install` target, embedded
/// at build time so the installed binary is self-contained.
const SKILL_MD: &str = include_str!("../../plugin/skills/envault/SKILL.md");

/// Global skill directories the major coding agents read. One SKILL.md in these
/// two covers Claude Code (`~/.claude/skills`), Codex (`~/.agents/skills`), and
/// opencode (which reads both). Paths verified against each tool's docs (2026).
pub fn skill_targets(home: &Path) -> Vec<(&'static str, PathBuf)> {
    vec![
        ("Claude Code", home.join(".claude/skills/envault/SKILL.md")),
        (
            "Codex / opencode",
            home.join(".agents/skills/envault/SKILL.md"),
        ),
    ]
}

/// Write the skill into every target dir, creating parents as needed. Only ever
/// touches the `envault/SKILL.md` file inside each skills dir — never anything
/// else — so re-running after an upgrade simply refreshes it. Returns the list
/// of (label, path) that were written.
pub fn install_skill(home: &Path) -> Result<Vec<(&'static str, PathBuf)>> {
    let targets = skill_targets(home);
    for (_label, file) in &targets {
        let parent = file.parent().expect("skill target always has a parent dir");
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        std::fs::write(file, SKILL_MD).with_context(|| format!("writing {}", file.display()))?;
    }
    Ok(targets)
}

pub fn cmd_skill_install() -> Result<()> {
    let home = dirs::home_dir().context("could not locate your home directory")?;
    let written = install_skill(&home)?;
    println!("Installed the envault skill — it loads only when a task needs a secret:");
    for (label, file) in &written {
        println!("  {label:<18} {}", file.display());
    }
    println!();
    println!("Re-run `envault skill install` after upgrading envault to refresh it.");
    println!("For any other agent, pipe `envault skill print` into whatever it reads.");
    Ok(())
}

pub fn cmd_skill_print() -> Result<()> {
    print!("{SKILL_MD}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn embeds_a_neutral_skill() {
        assert!(SKILL_MD.contains("name: envault"), "frontmatter name present");
        // The universal skill must not reference the Claude-Code-only hook
        // mechanism — the guidance has to read correctly on every harness.
        assert!(!SKILL_MD.contains("hooks block you"));
    }

    #[test]
    fn installs_into_both_agent_dirs() {
        let home = TempDir::new().unwrap();
        let written = install_skill(home.path()).unwrap();
        assert_eq!(written.len(), 2);
        let claude = home.path().join(".claude/skills/envault/SKILL.md");
        let agents = home.path().join(".agents/skills/envault/SKILL.md");
        assert!(claude.exists(), "Claude Code skill written");
        assert!(agents.exists(), "Codex/opencode skill written");
        assert_eq!(std::fs::read_to_string(&claude).unwrap(), SKILL_MD);
        assert_eq!(std::fs::read_to_string(&agents).unwrap(), SKILL_MD);
    }

    #[test]
    fn reinstall_refreshes_stale_content() {
        let home = TempDir::new().unwrap();
        let file = home.path().join(".claude/skills/envault/SKILL.md");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "stale").unwrap();
        install_skill(home.path()).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), SKILL_MD);
    }

    #[test]
    fn leaves_sibling_skills_untouched() {
        let home = TempDir::new().unwrap();
        let other = home.path().join(".claude/skills/other/SKILL.md");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        std::fs::write(&other, "someone else's skill").unwrap();
        install_skill(home.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&other).unwrap(),
            "someone else's skill"
        );
    }
}
