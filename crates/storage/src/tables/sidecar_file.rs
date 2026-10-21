//! Durable sidecar publication. Writers run on blocking workers, outside fork choice locks.
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::{LazyLock, Mutex},
};

use crate::errors::StoreError;
const TEMP_PREFIX: &str = ".ream-sidecar-";
// Only writers serialize. No filesystem I/O runs under the reader visibility lock.
// true denotes a rollback failure: readers report an error until a writer repairs it.
static WRITER: Mutex<()> = Mutex::new(());
#[derive(Default)]
struct Visibility {
    generation: u128,
    pending: HashMap<PathBuf, bool>,
}
static PENDING: LazyLock<Mutex<Visibility>> = LazyLock::new(|| Mutex::new(Visibility::default()));

impl Visibility {
    fn insert(&mut self, path: PathBuf, failed: bool) {
        self.generation += 1;
        self.pending.insert(path, failed);
    }

    fn remove(&mut self, path: &Path) {
        self.generation += 1;
        self.pending.remove(path);
    }

    fn get(&self, path: &Path) -> Option<&bool> {
        self.pending.get(path)
    }
}

fn visible_generation(path: &Path) -> Result<Option<u128>, StoreError> {
    let visibility = PENDING.lock().unwrap_or_else(|err| err.into_inner());
    match visibility.get(path) {
        Some(true) => Err(std::io::Error::other(
            "Sidecar publication rollback failed; storage repair or retry required",
        )
        .into()),
        Some(false) => Ok(None),
        None => Ok(Some(visibility.generation)),
    }
}

pub(crate) fn open_published(path: &Path) -> Result<Option<File>, StoreError> {
    open_published_with(path, || {}, || {})
}

fn open_published_with(
    path: &Path,
    before_open: impl FnOnce(),
    after_open: impl FnOnce(),
) -> Result<Option<File>, StoreError> {
    let mut before_open = Some(before_open);
    let mut after_open = Some(after_open);
    loop {
        let Some(generation) = visible_generation(path)? else {
            return Ok(None);
        };
        if let Some(hook) = before_open.take() {
            hook();
        }
        let file = match File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        if let Some(hook) = after_open.take() {
            hook();
        }
        // Generation survives pending-entry removal, detecting complete rollback
        // cycles. Retry because unrelated writes also advance this global counter.
        // No I/O or decoding holds the visibility lock.
        if visible_generation(path)? == Some(generation) {
            return Ok(Some(file));
        }
    }
}

/// Serialize removal (including the returned value's read) with publication.
pub(crate) fn remove_published<T>(
    path: &Path,
    read: impl FnOnce() -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let _writer = WRITER.lock().unwrap_or_else(|err| err.into_inner());
    let value = read()?;
    PENDING
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .insert(path.to_path_buf(), false);
    let result = remove_and_sync(path);
    let mut visibility = PENDING.lock().unwrap_or_else(|err| err.into_inner());
    if result.is_err() {
        visibility.insert(path.to_path_buf(), true);
    } else {
        visibility.remove(path);
    }
    result?;
    Ok(value)
}

/// Deletes a root's columns under the publication lock, with one directory flush. The caller
/// retains its durable index on error and retries this operation after restart.
pub(crate) fn remove_published_batch(paths: &[PathBuf]) -> Result<usize, StoreError> {
    let _writer = WRITER.lock().unwrap_or_else(|err| err.into_inner());
    let mut removed = 0;
    for path in paths {
        match fs::remove_file(path) {
            Ok(()) => removed += 1,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        PENDING
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(path);
    }
    let directories = paths
        .iter()
        .map(|path| path.parent().expect("sidecar parent"))
        .collect::<HashSet<_>>();
    for directory in directories {
        match File::open(directory) {
            Ok(file) => file.sync_all()?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(removed)
}

fn remove_and_sync(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    File::open(path.parent().expect("sidecar parent"))?.sync_all()
}

/// Hands the file's data to the drive. Publication ends with a directory `sync_all`, which on
/// macOS is `F_FULLFSYNC` and flushes the drive cache for every file written before it. A
/// `F_FULLFSYNC` per file costs a drive cache flush each, tens of milliseconds on an external
/// drive, for each of the 128 columns of a block, so macOS uses a plain `fsync` here.
fn write_to_drive(file: &File) -> std::io::Result<()> {
    #[cfg(target_vendor = "apple")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: `fsync` only reads the descriptor, which `file` keeps open for the call.
        if unsafe { libc::fsync(file.as_raw_fd()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(target_vendor = "apple"))]
    file.sync_all()
}

pub struct PreparedSidecarFile {
    file: tempfile::NamedTempFile,
    destination: PathBuf,
}
impl PreparedSidecarFile {
    pub fn new(destination: PathBuf, bytes: &[u8]) -> Result<Self, StoreError> {
        let parent = destination
            .parent()
            .ok_or_else(|| std::io::Error::other("Sidecar path has no parent"))?;
        let mut file = tempfile::Builder::new()
            .prefix(TEMP_PREFIX)
            .tempfile_in(parent)?;
        file.write_all(bytes)?;
        write_to_drive(file.as_file())?;
        Ok(Self { file, destination })
    }
    pub fn publish(self) -> Result<(), StoreError> {
        Self::publish_batch(vec![self])
    }

    /// Run the entire publication in one blocking task: cancellation cannot interrupt it.
    /// Byte-identical duplicates remain readable; different bytes are atomically replaced.
    pub fn publish_batch(files: Vec<Self>) -> Result<(), StoreError> {
        let _writer = WRITER.lock().unwrap_or_else(|err| err.into_inner());
        let mut publication = Publication::default();
        let mut directories = HashSet::new();
        for prepared in files {
            let failed = PENDING
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .get(&prepared.destination)
                .copied()
                == Some(true);
            if failed {
                remove_and_sync(&prepared.destination)?;
                PENDING
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .remove(&prepared.destination);
            }
            let replace = match fs::read(&prepared.destination) {
                Ok(existing) => {
                    if existing == fs::read(prepared.file.path())? {
                        continue;
                    }
                    true
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
                Err(err) => return Err(err.into()),
            };
            let parent = prepared
                .destination
                .parent()
                .ok_or_else(|| std::io::Error::other("Sidecar path has no parent"))?
                .to_path_buf();
            if replace {
                // Preserve the old inode so a later batch failure cannot destroy a
                // previously readable sidecar (including a different valid encoding).
                let backup = tempfile::Builder::new()
                    .prefix(TEMP_PREFIX)
                    .tempfile_in(&parent)?;
                fs::remove_file(backup.path())?;
                fs::hard_link(&prepared.destination, backup.path())?;
                publication
                    .backups
                    .insert(prepared.destination.clone(), backup);
            }
            PENDING
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .insert(prepared.destination.clone(), false);
            publication.paths.push(prepared.destination.clone());
            if replace {
                // A verified reimport repairs truncated or otherwise different bytes.
                prepared
                    .file
                    .persist(&prepared.destination)
                    .map_err(|err| err.error)?;
            } else {
                prepared
                    .file
                    .persist_noclobber(&prepared.destination)
                    .map_err(|err| err.error)?;
            }
            directories.insert(parent);
        }
        for directory in directories {
            File::open(directory)?.sync_all()?;
        }
        publication.durable = true;
        Ok(())
    }
}

#[derive(Default)]
struct Publication {
    paths: Vec<PathBuf>,
    backups: HashMap<PathBuf, tempfile::NamedTempFile>,
    durable: bool,
}
impl Drop for Publication {
    fn drop(&mut self) {
        // Roll back new files and restore replacements. Backups are temporary files:
        // after a successful directory flush they may safely be cleaned on restart.
        for path in &self.paths {
            let failed = if self.durable {
                false
            } else if let Some(backup) = self.backups.get(path) {
                fs::rename(backup.path(), path)
                    .and_then(|()| File::open(path.parent().expect("sidecar parent"))?.sync_all())
                    .is_err()
            } else {
                remove_and_sync(path).is_err()
            };
            let mut pending = PENDING.lock().unwrap_or_else(|err| err.into_inner());
            if failed {
                tracing::error!(?path, "Failed to roll back sidecar publication");
                pending.insert(path.clone(), true);
            } else {
                pending.remove(path);
            }
        }
    }
}

/// Startup only, before any writers start. Never run this during live pruning: a tempfile
/// could still belong to an active write. `.tmp` covers files from the previous implementation.
pub(crate) fn cleanup_temporary_sidecars(directory: &Path) -> Result<(), StoreError> {
    let mut removed = false;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.file_type()?.is_file()
            && (name.starts_with(TEMP_PREFIX) || name.starts_with(".tmp"))
        {
            fs::remove_file(entry.path())?;
            removed = true;
        }
    }
    if removed {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reader_rejects_file_opened_during_rolled_back_publication() {
        let dir = tempdir::TempDir::new("sidecar_reader_rollback").unwrap();
        let path = dir.path().join("a");
        let _writer = WRITER.lock().unwrap_or_else(|err| err.into_inner());
        let publication = std::cell::RefCell::new(None);
        let file = open_published_with(
            &path,
            || {
                PENDING
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .insert(path.clone(), false);
                fs::write(&path, b"uncommitted").unwrap();
                *publication.borrow_mut() = Some(Publication {
                    paths: vec![path.clone()],
                    backups: HashMap::new(),
                    durable: false,
                });
            },
            || drop(publication.borrow_mut().take()),
        )
        .unwrap();
        assert!(file.is_none());
        assert!(!path.exists());
        assert!(visible_generation(&path).unwrap().is_some());
    }

    #[test]
    fn removal_waits_for_publication_and_removes_committed_file() {
        let dir = tempdir::TempDir::new("sidecar_remove_writer").unwrap();
        let path = dir.path().join("a");
        let writer = WRITER.lock().unwrap_or_else(|err| err.into_inner());
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let removal_path = path.clone();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = remove_published(&removal_path, || Ok(()));
            done_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(done_rx.try_recv().is_err());
        // Simulate the publisher committing while still owning its writer guard.
        fs::write(&path, b"committed").unwrap();
        File::open(&path).unwrap().sync_all().unwrap();
        File::open(dir.path()).unwrap().sync_all().unwrap();
        drop(writer);
        done_rx.recv().unwrap().unwrap();
        worker.join().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn batch_publication_preserves_duplicates_and_cleans_staging() {
        let dir = tempdir::TempDir::new("sidecar_batch").unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        PreparedSidecarFile::publish_batch(vec![
            PreparedSidecarFile::new(a.clone(), b"first").unwrap(),
            PreparedSidecarFile::new(b.clone(), b"second").unwrap(),
        ])
        .unwrap();
        PreparedSidecarFile::new(a.clone(), b"first")
            .unwrap()
            .publish()
            .unwrap();
        assert_eq!(fs::read(&a).unwrap(), b"first");
        assert!(open_published(&b).unwrap().is_some());
        fs::write(dir.path().join(".ream-sidecar-orphan"), b"partial").unwrap();
        cleanup_temporary_sidecars(dir.path()).unwrap();
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
    #[test]
    fn reimport_repairs_truncated_file() {
        let dir = tempdir::TempDir::new("sidecar_repair").unwrap();
        let path = dir.path().join("column");
        fs::write(&path, b"truncated").unwrap();
        PreparedSidecarFile::new(path.clone(), b"verified complete file")
            .unwrap()
            .publish()
            .unwrap();
        assert_eq!(fs::read(path).unwrap(), b"verified complete file");
    }

    #[test]
    fn failed_repair_batch_restores_existing_file() {
        let dir = tempdir::TempDir::new("sidecar_repair_failure").unwrap();
        let path = dir.path().join("a");
        fs::write(&path, b"previous").unwrap();
        let replacement = PreparedSidecarFile::new(path.clone(), b"replacement").unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let failing = PreparedSidecarFile::new(nested.join("b"), b"new").unwrap();
        fs::remove_dir_all(nested).unwrap();
        assert!(PreparedSidecarFile::publish_batch(vec![replacement, failing]).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"previous");
        assert!(open_published(&path).unwrap().is_some());
    }

    #[test]
    fn failed_batch_does_not_hide_files_or_leave_partial_publications() {
        let dir = tempdir::TempDir::new("sidecar_failure").unwrap();
        let a = dir.path().join("a");
        let first = PreparedSidecarFile::new(a.clone(), b"first").unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let second = PreparedSidecarFile::new(nested.join("b"), b"second").unwrap();
        fs::remove_dir_all(&nested).unwrap();
        assert!(PreparedSidecarFile::publish_batch(vec![first, second]).is_err());
        assert!(open_published(&a).unwrap().is_none());
        PreparedSidecarFile::new(a.clone(), b"retry")
            .unwrap()
            .publish()
            .unwrap();
        assert!(open_published(&a).unwrap().is_some());
    }
}
