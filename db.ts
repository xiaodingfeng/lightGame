import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

function addColumnIfMissing(db: Database.Database, table: string, column: string, definition: string) {
  const info = db.pragma(`table_info(${table})`) as any[];
  if (info.some((col) => col.name === column)) {
    return;
  }
  db.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`).run();
}

function createIndexIfMissing(db: Database.Database, name: string, sql: string) {
  const index = db.prepare('SELECT name FROM sqlite_master WHERE type = ? AND name = ?').get('index', name);
  if (index) {
    return;
  }
  db.prepare(sql).run();
}

export function initDb() {
  const preferCloudStorage =
    process.env.DOUYIN_CLOUD === 'true' || process.env.NODE_ENV === 'production';
  const dbPath = process.env.DB_PATH || (preferCloudStorage ? '/data/database.sqlite' : './database.sqlite');

  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  console.log(`[db] path: ${dbPath}`);

  const db = new Database(dbPath);

  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
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
      milestone_stars TEXT NOT NULL DEFAULT '[]',
      bonus_stars INTEGER NOT NULL DEFAULT 0,
      last_played_level INTEGER NOT NULL DEFAULT 1,
      energy INTEGER NOT NULL DEFAULT 10,
      energy_updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      energy_paid_levels TEXT NOT NULL DEFAULT '[]',
      sidebar_reward_claimed INTEGER NOT NULL DEFAULT 0,
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

    CREATE TABLE IF NOT EXISTS subscribe_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      template_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'unknown',
      always_subscribe INTEGER NOT NULL DEFAULT 0,
      reminder_statuses TEXT NOT NULL DEFAULT '[]',
      scene TEXT,
      raw_payload TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS operation_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      action TEXT NOT NULL,
      details TEXT DEFAULT '{}',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  addColumnIfMissing(db, 'users', 'anonymous_openid', 'TEXT');
  addColumnIfMissing(db, 'users', 'unionid', 'TEXT');
  addColumnIfMissing(db, 'users', 'auth_type', "TEXT NOT NULL DEFAULT 'anonymous'");
  addColumnIfMissing(db, 'users', 'app_id', 'TEXT');
  addColumnIfMissing(db, 'users', 'session_key', 'TEXT');
  addColumnIfMissing(db, 'users', 'nickname', 'TEXT');
  addColumnIfMissing(db, 'users', 'avatar_url', 'TEXT');
  addColumnIfMissing(db, 'users', 'profile_authorized', 'BOOLEAN NOT NULL DEFAULT 0');
  addColumnIfMissing(db, 'users', 'profile_verified', 'BOOLEAN NOT NULL DEFAULT 0');
  addColumnIfMissing(db, 'users', 'profile_payload', 'TEXT');
  addColumnIfMissing(db, 'users', 'profile_raw_data', 'TEXT');
  addColumnIfMissing(db, 'users', 'last_login_at', 'DATETIME');
  addColumnIfMissing(db, 'users', 'last_profile_at', 'DATETIME');
  
  createIndexIfMissing(db, 'idx_users_openid_unique', 'CREATE UNIQUE INDEX idx_users_openid_unique ON users(openid)');
  createIndexIfMissing(db, 'idx_users_anonymous_openid_unique', 'CREATE UNIQUE INDEX idx_users_anonymous_openid_unique ON users(anonymous_openid)');
  addColumnIfMissing(db, 'progress', 'milestone_stars', "TEXT NOT NULL DEFAULT '[]'");
  addColumnIfMissing(db, 'progress', 'bonus_stars', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing(db, 'progress', 'last_played_level', 'INTEGER NOT NULL DEFAULT 1');
  addColumnIfMissing(db, 'progress', 'energy', 'INTEGER NOT NULL DEFAULT 10');
  addColumnIfMissing(db, 'progress', 'energy_updated_at', 'TEXT');
  addColumnIfMissing(db, 'progress', 'energy_paid_levels', "TEXT NOT NULL DEFAULT '[]'");
  addColumnIfMissing(db, 'progress', 'sidebar_reward_claimed', 'INTEGER NOT NULL DEFAULT 0');
  db.prepare("UPDATE progress SET energy = COALESCE(energy, 10) WHERE energy IS NULL").run();
  db.prepare("UPDATE progress SET last_played_level = COALESCE(last_played_level, unlocked_level, 1) WHERE last_played_level IS NULL").run();
  db.prepare("UPDATE progress SET energy_updated_at = COALESCE(NULLIF(energy_updated_at, ''), datetime('now')) WHERE energy_updated_at IS NULL OR energy_updated_at = ''").run();
  db.prepare("UPDATE progress SET energy_paid_levels = COALESCE(NULLIF(energy_paid_levels, ''), '[]') WHERE energy_paid_levels IS NULL OR energy_paid_levels = ''").run();
  db.prepare("UPDATE progress SET sidebar_reward_claimed = COALESCE(sidebar_reward_claimed, 0) WHERE sidebar_reward_claimed IS NULL").run();
  createIndexIfMissing(db, 'idx_subscribe_records_user_created_at', 'CREATE INDEX idx_subscribe_records_user_created_at ON subscribe_records(user_id, created_at DESC)');

  console.log('[db] initialized');
  return db;
}
