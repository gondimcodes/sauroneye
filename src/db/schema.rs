pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS file_fingerprints (
    path TEXT PRIMARY KEY,
    inode INTEGER NOT NULL,
    size INTEGER NOT NULL,
    mtime INTEGER NOT NULL,
    permissions INTEGER NOT NULL,
    hash_algorithm TEXT NOT NULL,
    hash_value TEXT NOT NULL,
    package_name TEXT,
    package_version TEXT,
    last_verified INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_file_inode ON file_fingerprints (inode);

CREATE TABLE IF NOT EXISTS admin_users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_login INTEGER
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    details TEXT
);
"#;
