import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const DEFAULT_DATABASE_PATH = fileURLToPath(
  new URL('../../../data/sql-injection.sqlite', import.meta.url),
);

// Synthetic credentials only. Plaintext passwords are deliberately insecure.
export const SEED_USERS = Object.freeze([
  Object.freeze({ id: 1, username: 'admin', password: 'admin123', role: 'administrator' }),
  Object.freeze({ id: 2, username: 'student', password: 'student123', role: 'student' }),
  Object.freeze({ id: 3, username: 'guest', password: 'guest123', role: 'guest' }),
]);

export function resetDatabase(db) {
  const insert = db.prepare('INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)');
  db.transaction(() => {
    db.prepare('DELETE FROM users').run();
    for (const user of SEED_USERS) {
      insert.run(user.id, user.username, user.password, user.role);
    }
  })();
}

export function openDatabase(databasePath = DEFAULT_DATABASE_PATH) {
  if (databasePath !== ':memory:') mkdirSync(dirname(resolve(databasePath)), { recursive: true });
  const db = new Database(databasePath);
  try {
    // Startup must preserve existing data. Seed only when creating the table.
    const exists = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?").get('users');
    db.exec(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL
    )`);
    if (!exists) resetDatabase(db);
    return db;
  } catch (error) {
    db.close();
    throw error;
  }
}

// Run the reset directly from npm without a separate wrapper file.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)
    && process.argv.includes('--reset')) {
  const db = openDatabase();
  try {
    resetDatabase(db);
    console.log(`SQL Injection database reset: ${SEED_USERS.length} synthetic users restored.`);
  } finally {
    db.close();
  }
}
