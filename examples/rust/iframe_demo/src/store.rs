//! SQLite token store — same schema as `examples/python/iframe_demo_common/store.py`.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::error::DemoError;

#[derive(Debug, Clone, Serialize)]
pub struct TokenRecord {
    pub session_id: String,
    pub email: Option<String>,
    pub sub: Option<String>,
    pub access_token: String,
    pub refresh_token: String,
    pub updated_at: f64,
}

#[derive(Clone)]
pub struct SqliteTokenStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteTokenStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DemoError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| DemoError::msg(format!("create_dir_all: {e}")))?;
        }
        let conn = Connection::open(path).map_err(|e| DemoError::msg(e.to_string()))?;
        conn.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS demo_sessions (
                client_label TEXT NOT NULL,
                session_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (client_label, session_id)
            );
            CREATE TABLE IF NOT EXISTS demo_tokens (
                client_label TEXT NOT NULL,
                session_id TEXT NOT NULL,
                email TEXT,
                sub TEXT,
                access_token TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (client_label, session_id),
                FOREIGN KEY(client_label, session_id)
                  REFERENCES demo_sessions(client_label, session_id)
            );
            ",
        )
        .map_err(|e| DemoError::msg(e.to_string()))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn ensure_session(
        &self,
        session_id: &str,
        client_label: &str,
    ) -> Result<(), rusqlite::Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let conn = self.conn.lock().unwrap();
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM demo_sessions WHERE client_label = ?1 AND session_id = ?2",
                params![client_label, session_id],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if !exists {
            conn.execute(
                "INSERT INTO demo_sessions (client_label, session_id, created_at) VALUES (?1, ?2, ?3)",
                params![client_label, session_id, now],
            )?;
        }
        Ok(())
    }

    pub fn save_tokens(
        &self,
        session_id: &str,
        client_label: &str,
        email: Option<&str>,
        sub: Option<&str>,
        access_token: &str,
        refresh_token: &str,
    ) -> Result<(), rusqlite::Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO demo_tokens (client_label, session_id, email, sub, access_token, refresh_token, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(client_label, session_id) DO UPDATE SET
               email = excluded.email,
               sub = excluded.sub,
               access_token = excluded.access_token,
               refresh_token = excluded.refresh_token,
               updated_at = excluded.updated_at",
            params![
                client_label,
                session_id,
                email,
                sub,
                access_token,
                refresh_token,
                now
            ],
        )?;
        Ok(())
    }

    pub fn get_tokens(
        &self,
        session_id: &str,
        client_label: &str,
    ) -> Result<Option<TokenRecord>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT session_id, email, sub, access_token, refresh_token, updated_at
             FROM demo_tokens WHERE client_label = ?1 AND session_id = ?2",
        )?;
        let mut rows = stmt.query(params![client_label, session_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(TokenRecord {
                session_id: row.get(0)?,
                email: row.get(1)?,
                sub: row.get(2)?,
                access_token: row.get(3)?,
                refresh_token: row.get(4)?,
                updated_at: row.get(5)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn clear_tokens(
        &self,
        session_id: &str,
        client_label: &str,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM demo_tokens WHERE client_label = ?1 AND session_id = ?2",
            params![client_label, session_id],
        )?;
        Ok(())
    }

    pub fn list_for_client(
        &self,
        client_label: &str,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT session_id, email, sub, updated_at FROM demo_tokens
             WHERE client_label = ?1 ORDER BY updated_at DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![client_label, limit as i64], |row| {
            Ok(serde_json::json!({
                "session_id": row.get::<_, String>(0)?,
                "email": row.get::<_, Option<String>>(1)?,
                "sub": row.get::<_, Option<String>>(2)?,
                "updated_at": row.get::<_, f64>(3)?,
            }))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}
