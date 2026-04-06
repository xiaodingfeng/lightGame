import fs from 'node:fs/promises';
import path from 'node:path';
import { open } from 'sqlite';
import sqlite3 from 'sqlite3';

async function addColumnIfMissing(db: Awaited<ReturnType<typeof open>>, table: string, column: string, definition: string) {
  const columns = await db.all<{ name: string }[]>(`PRAGMA table_info(${table})`);
  if (columns.some((item) => item.name === column)) {
    return;
  }
  await db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

async function createIndexIfMissing(db: Awaited<ReturnType<typeof open>>, name: string, sql: string) {
  const index = await db.get<{ name: string }>('SELECT name FROM sqlite_master WHERE type = ? AND name = ?', ['index', name]);
  if (index) {
    return;
  }
  await db.exec(sql);
}

export async function initDb() {
  const preferCloudStorage =
    process.env.DOUYIN_CLOUD === 'true' || process.env.NODE_ENV === 'production';
  const dbPath = process.env.DB_PATH || (preferCloudStorage ? '/data/database.sqlite' : './database.sqlite');

  await fs.mkdir(path.dirname(dbPath), { recursive: true });
  console.log(`[db] path: ${dbPath}`);

  const db = await open({
    filename: dbPath,
    driver: sqlite3.Database,
  });

  await db.exec('PRAGMA journal_mode = WAL;');
  await db.exec('PRAGMA foreign_keys = ON;');

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      openid TEXT UNIQUE,
      anonymous_openid TEXT UNIQUE,
      unionid TEXT,
      is_vip BOOLEAN NOT NULL DEFAULT 0,
      auth_type TEXT NOT NULL DEFAULT 'anonymous',
      app_id TEXT,
      session_key TEXT,
      nickname TEXT,
      avatar_url TEXT,
      profile_authorized BOOLEAN NOT NULL DEFAULT 0,
      profile_verified BOOLEAN NOT NULL DEFAULT 0,
      profile_payload TEXT,
      profile_raw_data TEXT,
      last_login_at DATETIME,
      last_profile_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS progress (
      user_id TEXT PRIMARY KEY,
      unlocked_level INTEGER NOT NULL DEFAULT 1,
      stars TEXT NOT NULL DEFAULT '[]',
      win_streak INTEGER NOT NULL DEFAULT 0,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS checkins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      checkin_date TEXT NOT NULL, -- YYYY-MM-DD
      stars_rewarded INTEGER NOT NULL DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(user_id, checkin_date)
    );

    CREATE TABLE IF NOT EXISTS rankings (
      user_id TEXT PRIMARY KEY,
      total_stars INTEGER NOT NULL DEFAULT 0,
      daily_stars INTEGER NOT NULL DEFAULT 0,
      win_streak INTEGER NOT NULL DEFAULT 0,
      last_updated_date TEXT NOT NULL, -- YYYY-MM-DD
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      out_order_no TEXT UNIQUE NOT NULL,
      order_token TEXT,
      amount INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      paid_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS ad_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      ad_unit_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS operation_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      action TEXT NOT NULL,
      details TEXT DEFAULT '{}',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await addColumnIfMissing(db, 'users', 'anonymous_openid', 'TEXT');
  await addColumnIfMissing(db, 'users', 'unionid', 'TEXT');
  await addColumnIfMissing(db, 'users', 'auth_type', "TEXT NOT NULL DEFAULT 'anonymous'");
  await addColumnIfMissing(db, 'users', 'app_id', 'TEXT');
  await addColumnIfMissing(db, 'users', 'session_key', 'TEXT');
  await addColumnIfMissing(db, 'users', 'nickname', 'TEXT');
  await addColumnIfMissing(db, 'users', 'avatar_url', 'TEXT');
  await addColumnIfMissing(db, 'users', 'profile_authorized', 'BOOLEAN NOT NULL DEFAULT 0');
  await addColumnIfMissing(db, 'users', 'profile_verified', 'BOOLEAN NOT NULL DEFAULT 0');
  await addColumnIfMissing(db, 'users', 'profile_payload', 'TEXT');
  await addColumnIfMissing(db, 'users', 'profile_raw_data', 'TEXT');
  await addColumnIfMissing(db, 'users', 'last_login_at', 'DATETIME');
  await addColumnIfMissing(db, 'users', 'last_profile_at', 'DATETIME');
  await createIndexIfMissing(db, 'idx_users_openid_unique', 'CREATE UNIQUE INDEX idx_users_openid_unique ON users(openid)');
  await createIndexIfMissing(db, 'idx_users_anonymous_openid_unique', 'CREATE UNIQUE INDEX idx_users_anonymous_openid_unique ON users(anonymous_openid)');

  console.log('[db] initialized');
  return db;
}
