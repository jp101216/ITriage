//! Clear the current user's temp directory. MUTATING (the UI confirms before
//! running any module flagged this way). Locked or in-use entries are skipped
//! and counted instead of failing the whole run.

use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use crate::util::human_bytes;
use std::fs;
use std::path::Path;

pub struct ClearTemp;

impl TriageModule for ClearTemp {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "fix.temp",
            "Clear temp files",
            Category::Fixes,
            "Deletes the contents of the user temp directory. Skips files in use.",
        )
        .mutating()
        .warning("Permanently deletes everything in your temp folder that isn't currently in use.")
    }

    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let dir = std::env::temp_dir();
        ctx.log(format!("Clearing {}", dir.display()));
        let entries = fs::read_dir(&dir)
            .map_err(|e| format!("cannot read temp dir {}: {e}", dir.display()))?;

        let (mut removed, mut skipped, mut freed) = (0u64, 0u64, 0u64);
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                skipped += 1;
                continue;
            };
            let size = path_size(&path, meta.is_dir());
            let result = if meta.is_dir() {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
            match result {
                Ok(()) => {
                    removed += 1;
                    freed += size;
                }
                Err(_) => skipped += 1, // locked / in use / permission
            }
        }

        let findings = vec![
            Finding::info("Temp directory", dir.display().to_string()),
            Finding::ok("Entries removed", removed.to_string()),
            Finding::info("Space freed", human_bytes(freed)),
            Finding::new(
                "Entries skipped (in use / locked)",
                skipped.to_string(),
                if skipped > 0 { Severity::Info } else { Severity::Ok },
            ),
        ];
        let summary = format!(
            "Freed {} ({removed} removed, {skipped} skipped)",
            human_bytes(freed)
        );
        Ok(Output::new(summary, findings))
    }
}

/// Best-effort size of a path. Directories are walked; unreadable entries are
/// ignored.
fn path_size(path: &Path, is_dir: bool) -> u64 {
    if !is_dir {
        return fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    }
    let mut total = 0;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            match entry.metadata() {
                Ok(m) if m.is_dir() => total += path_size(&entry.path(), true),
                Ok(m) => total += m.len(),
                Err(_) => {}
            }
        }
    }
    total
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn clears_a_throwaway_temp_dir() {
        let dir = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("itriage-temp-test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("nested")).unwrap();
        fs::write(dir.join("a.log"), vec![0u8; 2048]).unwrap();
        fs::write(dir.join("nested").join("b.tmp"), vec![0u8; 1024]).unwrap();

        // temp_dir() reads TMPDIR on Unix; point it at the throwaway folder.
        std::env::set_var("TMPDIR", &dir);
        let result = ClearTemp.run(&RunContext::silent());
        std::env::remove_var("TMPDIR");

        assert!(result.error.is_none(), "{:?}", result.error);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        assert!(result.summary.starts_with("Freed 3.0 KB (2 removed"), "{}", result.summary);
        let _ = fs::remove_dir_all(&dir);
    }
}
