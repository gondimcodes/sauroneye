use crate::fim::hasher::{compute_file_hash, HashAlgorithm};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFingerprint {
    pub path: PathBuf,
    pub inode: u64,
    pub size: u64,
    pub mtime: i64,
    pub permissions: u32,
    pub hash_algorithm: String,
    pub hash_value: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub last_verified: i64,
}

impl FileFingerprint {
    pub fn generate<P: AsRef<Path>>(path: P, algorithm: HashAlgorithm) -> std::io::Result<Self> {
        let path_buf = path.as_ref().to_path_buf();
        let metadata = fs::metadata(&path_buf)?;

        let inode = metadata.ino();
        let size = metadata.size();
        let mtime = metadata.mtime();
        let permissions = metadata.mode();
        let now = chrono::Utc::now().timestamp();

        let hash_value = compute_file_hash(&path_buf, algorithm)?;

        Ok(Self {
            path: path_buf,
            inode,
            size,
            mtime,
            permissions,
            hash_algorithm: algorithm.as_str().to_string(),
            hash_value,
            package_name: None,
            package_version: None,
            last_verified: now,
        })
    }
}
