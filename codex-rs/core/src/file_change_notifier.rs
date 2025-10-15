use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use dunce::canonicalize;
use notify::Config;
use notify::Event;
use notify::EventKind;
use notify::RecommendedWatcher;
use notify::RecursiveMode;
use notify::Watcher;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::warn;

#[derive(Clone)]
pub(crate) struct FileChangeCollector {
    root: Arc<PathBuf>,
    changes: Arc<Mutex<HashSet<PathBuf>>>,
}

impl FileChangeCollector {
    fn new(root: PathBuf) -> Self {
        Self {
            root: Arc::new(root),
            changes: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn root_path(&self) -> &Path {
        self.root.as_ref()
    }

    pub(crate) async fn record_event(&self, event: Event) {
        let Event { kind, paths, .. } = event;
        if should_skip(kind) {
            return;
        }

        let mut normalized_paths = Vec::new();
        for path in paths {
            if let Some(rel) = self.normalize_path(&path) {
                normalized_paths.push(rel);
            }
        }

        if normalized_paths.is_empty() {
            return;
        }

        let mut guard = self.changes.lock().await;
        guard.extend(normalized_paths);
    }

    fn normalize_path(&self, path: &Path) -> Option<PathBuf> {
        let rel = path.strip_prefix(self.root_path()).ok()?;
        if should_ignore(rel) {
            return None;
        }
        Some(rel.to_path_buf())
    }

    pub(crate) async fn drain(&self) -> Vec<PathBuf> {
        let mut guard = self.changes.lock().await;
        let mut entries: Vec<PathBuf> = guard.drain().collect();
        entries.sort();
        entries
    }
}

fn should_skip(kind: EventKind) -> bool {
    matches!(
        kind,
        EventKind::Access(_) | EventKind::Other | EventKind::Any
    )
}

fn should_ignore(path: &Path) -> bool {
    path.components().any(|component| {
        if let std::path::Component::Normal(part) = component {
            matches!(
                part.to_str(),
                Some(".git") | Some(".codex") | Some("target") | Some(".DS_Store") | Some(".idea")
            )
        } else {
            false
        }
    })
}

pub(crate) struct FileChangeWatcher {
    _watcher: RecommendedWatcher,
    task: JoinHandle<()>,
}

impl FileChangeWatcher {
    pub(crate) fn start(root: PathBuf) -> Result<(Self, FileChangeCollector)> {
        let canonical_root = canonicalize(&root)
            .with_context(|| format!("failed to canonicalize {}", root.display()))?;
        let collector = FileChangeCollector::new(canonical_root.clone());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            Config::default(),
        )
        .context("failed to initialize file watcher")?;
        watcher
            .watch(&canonical_root, RecursiveMode::Recursive)
            .with_context(|| format!("failed to watch path {}", canonical_root.display()))?;

        let collector_clone = collector.clone();
        let task = tokio::spawn(async move {
            while let Some(event_result) = rx.recv().await {
                match event_result {
                    Ok(event) => collector_clone.record_event(event).await,
                    Err(err) => warn!("file watcher error: {err}"),
                }
            }
        });

        Ok((
            Self {
                _watcher: watcher,
                task,
            },
            collector,
        ))
    }
}

impl Drop for FileChangeWatcher {
    fn drop(&mut self) {
        if self.task.is_finished() {
            return;
        }
        self.task.abort();
    }
}

#[cfg(test)]
pub(crate) fn collector_for_tests(root: PathBuf) -> FileChangeCollector {
    FileChangeCollector::new(root)
}

#[cfg(test)]
impl FileChangeCollector {
    pub(crate) async fn record_for_tests(&self, path: PathBuf) {
        let mut guard = self.changes.lock().await;
        guard.insert(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drain_returns_empty_when_no_changes() {
        let collector = collector_for_tests(PathBuf::from("."));
        let drained = collector.drain().await;
        assert!(drained.is_empty());
    }

    #[tokio::test]
    async fn record_and_drain_changes() {
        let collector = collector_for_tests(PathBuf::from("/tmp/root"));
        collector.record_for_tests(PathBuf::from("file.txt")).await;
        let drained = collector.drain().await;
        assert_eq!(drained, vec![PathBuf::from("file.txt")]);
    }
}
