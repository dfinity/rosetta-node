//! Functions related to spawning processes and executing commands.

use std::{env, path};

/// Tests whether `file` exists in any of the directories listed in the `PATH`
/// environment variable.
pub fn is_file_on_path(file: &str) -> bool {
    find_file_on_path(file).map(|_| true).unwrap_or(false)
}

/// Finds the `file` in the directories listed in the `PATH` environment
/// variable.
pub fn find_file_on_path(file: &str) -> Option<path::PathBuf> {
    match env::var("PATH") {
        Ok(path_var) => path_var.split(':').find_map(|p| {
            let path = path::PathBuf::from(p).join(file);
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::command::is_file_on_path;

    #[test]
    fn can_find_sh() {
        assert!(is_file_on_path("sh"));
    }

    #[test]
    fn can_not_find_nonexistent() {
        assert!(!is_file_on_path("certainlynonexistent"))
    }
}
