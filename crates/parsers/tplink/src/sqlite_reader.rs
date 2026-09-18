//! # SQLite Forensic Reader
//!
//! Read-only forensic wrapper around `rusqlite` for sys.bin.

use forensic_core::ForensicError;
use rusqlite::{Connection, OpenFlags};

pub struct SqliteForensicReader {
    pub connection: Connection,
}

impl SqliteForensicReader {
    pub fn open_read_only(path: &str) -> Result<Self, ForensicError> {
        // Enforce forensic safety: URI params for Read-Only + Immutable
        let uri = format!("file:{}?mode=ro&immutable=1", path);
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
        let connection = Connection::open_with_flags(&uri, flags)
            .map_err(|e| ForensicError::corrupt("sqlite_reader", format!("Failed to open immutable SQLite DB: {}", e)))?;

        Ok(Self { connection })
    }
}
