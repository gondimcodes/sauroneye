use rusqlite::{params, Connection};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::db::schema::SCHEMA_SQL;
use crate::db::user::AdminAuth;
use crate::fim::state::FileFingerprint;

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
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
        }

        let conn = Connection::open(path_ref)?;

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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM admin_users WHERE username = 'admin'")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count > 0)
    }

    pub fn create_admin_user(
        &self,
        password_hash: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
            params!["admin", password_hash, now],
        )?;
        Ok(())
    }

    pub fn verify_admin_login(&self, password: &str) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let conn = self.conn.lock().unwrap();
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
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        {
            let mut stmt = tx.prepare(
                "INSERT INTO file_fingerprints 
                (path, inode, size, mtime, permissions, hash_algorithm, hash_value, package_name, package_version, last_verified)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(path) DO UPDATE SET
                    inode = excluded.inode,
                    size = excluded.size,
                    mtime = excluded.mtime,
                    permissions = excluded.permissions,
                    hash_algorithm = excluded.hash_algorithm,
                    hash_value = excluded.hash_value,
                    package_name = excluded.package_name,
                    package_version = excluded.package_version,
                    last_verified = excluded.last_verified"
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
                    fp.package_name,
                    fp.package_version,
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT path, inode, size, mtime, permissions, hash_algorithm, hash_value, package_name, package_version, last_verified
             FROM file_fingerprints WHERE path = ?1"
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
            let pkg_name: Option<String> = row.get(7)?;
            let pkg_ver: Option<String> = row.get(8)?;
            let last_ver: i64 = row.get(9)?;

            Ok(FileFingerprint {
                path: PathBuf::from(p_str),
                inode: inode_i64 as u64,
                size: size_i64 as u64,
                mtime,
                permissions: perm_i64 as u32,
                hash_algorithm: hash_algo,
                hash_value: hash_val,
                package_name: pkg_name,
                package_version: pkg_ver,
                last_verified: last_ver,
            })
        });

        match result {
            Ok(fp) => Ok(Some(fp)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Box::new(e)),
        }
    }

    pub fn record_audit_log(
        &self,
        action: &str,
        actor: &str,
        details: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO audit_logs (timestamp, action, actor, details) VALUES (?1, ?2, ?3, ?4)",
            params![now, action, actor, details],
        )?;
        Ok(())
    }

    pub fn get_db_path(&self) -> &Path {
        &self.db_path
    }
}
