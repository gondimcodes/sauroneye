use rusqlite::{params, Connection};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::warn;

use crate::db::schema::SCHEMA_SQL;
use crate::db::user::AdminAuth;
use crate::fim::state::FileFingerprint;

/// Acquire a Mutex<Connection> with poison recovery.
/// If the mutex is poisoned (a thread panicked while holding it), we log a warning
/// and recover the inner value rather than propagating the panic to the caller.
macro_rules! lock_conn {
    ($self:expr) => {
        $self.conn.lock().unwrap_or_else(|poisoned| {
            warn!(
                "SQLite mutex was poisoned — recovering inner connection. Check for prior panics."
            );
            poisoned.into_inner()
        })
    };
}

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
    /// Stored for diagnostics and status display (get_db_path)
    #[allow(dead_code)]
    db_path: PathBuf,
}

impl Database {
    pub fn open<P: AsRef<Path>>(
        path: P,
        enable_wal: bool,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let path_ref = path.as_ref();
        if let Some(parent) = path_ref.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        let conn = Connection::open(path_ref)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if path_ref.exists() {
                let _ = std::fs::set_permissions(path_ref, std::fs::Permissions::from_mode(0o600));
            }
        }

        if enable_wal {
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "synchronous", "NORMAL")?;
            conn.pragma_update(None, "temp_store", "MEMORY")?;
            conn.pragma_update(None, "cache_size", -64000)?; // 64MB cache
        }

        conn.execute_batch(SCHEMA_SQL)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: path_ref.to_path_buf(),
        })
    }

    pub fn is_initialized(&self) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let conn = lock_conn!(self);
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM admin_users WHERE username = 'admin'")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count > 0)
    }

    pub fn create_admin_user(
        &self,
        password_hash: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let conn = lock_conn!(self);
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
            params!["admin", password_hash, now],
        )?;
        Ok(())
    }

    pub fn update_admin_password(
        &self,
        new_password_hash: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let conn = lock_conn!(self);
        conn.execute(
            "UPDATE admin_users SET password_hash = ?1 WHERE username = 'admin'",
            params![new_password_hash],
        )?;
        Ok(())
    }

    pub fn verify_admin_login(&self, password: &str) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let conn = lock_conn!(self);
        let mut stmt =
            conn.prepare("SELECT password_hash FROM admin_users WHERE username = 'admin'")?;
        let hash_opt: Option<String> = stmt.query_row([], |row| row.get(0)).ok();

        if let Some(hash) = hash_opt {
            Ok(AdminAuth::verify_password(password, &hash))
        } else {
            Ok(false)
        }
    }

    pub fn save_fingerprints_batch(
        &self,
        fingerprints: &[FileFingerprint],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut conn = lock_conn!(self);
        let tx = conn.transaction()?;

        {
            let mut stmt = tx.prepare(
                "INSERT INTO file_fingerprints
                (path, inode, size, mtime, permissions, hash_algorithm, hash_value, last_verified)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(path) DO UPDATE SET
                    inode = excluded.inode,
                    size = excluded.size,
                    mtime = excluded.mtime,
                    permissions = excluded.permissions,
                    hash_algorithm = excluded.hash_algorithm,
                    hash_value = excluded.hash_value,
                    last_verified = excluded.last_verified",
            )?;

            for fp in fingerprints {
                stmt.execute(params![
                    fp.path.to_string_lossy(),
                    fp.inode as i64,
                    fp.size as i64,
                    fp.mtime,
                    fp.permissions as i64,
                    fp.hash_algorithm,
                    fp.hash_value,
                    fp.last_verified,
                ])?;
            }
        }

        tx.commit()?;
        Ok(())
    }

    pub fn get_fingerprint(
        &self,
        path: &Path,
    ) -> Result<Option<FileFingerprint>, Box<dyn Error + Send + Sync>> {
        let conn = lock_conn!(self);
        let mut stmt = conn.prepare(
            "SELECT path, inode, size, mtime, permissions, hash_algorithm, hash_value, last_verified
             FROM file_fingerprints WHERE path = ?1",
        )?;

        let path_str = path.to_string_lossy();
        let result = stmt.query_row(params![path_str], |row| {
            let p_str: String = row.get(0)?;
            let inode_i64: i64 = row.get(1)?;
            let size_i64: i64 = row.get(2)?;
            let mtime: i64 = row.get(3)?;
            let perm_i64: i64 = row.get(4)?;
            let hash_algo: String = row.get(5)?;
            let hash_val: String = row.get(6)?;
            let last_ver: i64 = row.get(7)?;

            Ok(FileFingerprint {
                path: PathBuf::from(p_str),
                inode: inode_i64 as u64,
                size: size_i64 as u64,
                mtime,
                permissions: perm_i64 as u32,
                hash_algorithm: hash_algo,
                hash_value: hash_val,
                last_verified: last_ver,
            })
        });

        match result {
            Ok(fp) => Ok(Some(fp)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Box::new(e)),
        }
    }

    pub fn delete_fingerprint(&self, path: &Path) -> Result<(), Box<dyn Error + Send + Sync>> {
        let conn = lock_conn!(self);
        let path_str = path.to_string_lossy();
        conn.execute(
            "DELETE FROM file_fingerprints WHERE path = ?1",
            params![path_str],
        )?;
        Ok(())
    }

    pub fn record_audit_log(
        &self,
        action: &str,
        actor: &str,
        details: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let conn = lock_conn!(self);
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO audit_logs (timestamp, action, actor, details) VALUES (?1, ?2, ?3, ?4)",
            params![now, action, actor, details],
        )?;
        Ok(())
    }

    pub fn query_audit_logs(
        &self,
        start_ts: i64,
        end_ts: i64,
    ) -> Result<Vec<AuditLogEntry>, Box<dyn Error + Send + Sync>> {
        let conn = lock_conn!(self);
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, action, actor, details FROM audit_logs WHERE timestamp >= ?1 AND timestamp <= ?2 ORDER BY timestamp ASC, id ASC"
        )?;

        let rows = stmt.query_map(params![start_ts, end_ts], |row| {
            Ok(AuditLogEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                action: row.get(2)?,
                actor: row.get(3)?,
                details: row.get(4)?,
            })
        })?;

        let mut entries = Vec::new();
        for r in rows {
            entries.push(r?);
        }
        Ok(entries)
    }

    pub fn purge_audit_logs(
        &self,
        start_ts: i64,
        end_ts: i64,
    ) -> Result<usize, Box<dyn Error + Send + Sync>> {
        let conn = lock_conn!(self);
        let count = conn.execute(
            "DELETE FROM audit_logs WHERE timestamp >= ?1 AND timestamp <= ?2",
            params![start_ts, end_ts],
        )?;
        Ok(count)
    }

    /// Returns the path of the SQLite database file (used for diagnostics).
    #[allow(dead_code)]
    pub fn get_db_path(&self) -> &Path {
        &self.db_path
    }
}

#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    /// DB primary key — kept for future use in deletion/deduplication
    #[allow(dead_code)]
    pub id: i64,
    pub timestamp: i64,
    pub action: String,
    pub actor: String,
    pub details: String,
}
