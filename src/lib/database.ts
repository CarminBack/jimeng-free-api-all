import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs-extra';
import crypto from 'crypto';

// 数据库文件路径
const DB_PATH = process.env.DB_PATH || './data/jimeng.db';

// 确保数据目录存在
fs.ensureDirSync(path.dirname(DB_PATH));

// 初始化数据库连接
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// 初始化表结构
db.exec(`
  -- 用户表（管理员账号）
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now', 'localtime'))
  );

  -- Session表
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  -- API Key统计表
  CREATE TABLE IF NOT EXISTS key_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT NOT NULL,
    key_preview TEXT NOT NULL,
    model TEXT NOT NULL,
    credits_used INTEGER DEFAULT 0,
    remaining_credits INTEGER DEFAULT 0,
    call_count INTEGER DEFAULT 1,
    last_used TEXT DEFAULT (datetime('now', 'localtime')),
    created_at TEXT DEFAULT (datetime('now', 'localtime'))
  );

  -- 媒体记录表
  CREATE TABLE IF NOT EXISTS media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    url TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt TEXT,
    key_preview TEXT,
    created_at TEXT DEFAULT (datetime('now', 'localtime'))
  );

  -- 日志缓冲表
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now', 'localtime'))
  );

  -- 即梦账号池。Token 使用 AES-256-GCM 加密，列表接口只返回掩码。
  CREATE TABLE IF NOT EXISTS pool_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_encrypted TEXT NOT NULL,
    token_preview TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'unchecked',
    points INTEGER,
    failure_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    last_checked TEXT,
    last_used TEXT,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT DEFAULT (datetime('now', 'localtime'))
  );

  -- 创建索引
  CREATE INDEX IF NOT EXISTS idx_key_stats_key ON key_stats(key_hash);
  CREATE INDEX IF NOT EXISTS idx_media_created ON media(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);
  CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at DESC);
`);

// 密码哈希
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

// 生成Session ID
export function generateSessionId(): string {
  return crypto.randomBytes(32).toString('hex');
}

// Key预览（隐藏中间部分）
export function keyPreview(key: string): string {
  if (key.length <= 8) return key;
  return `${key.slice(0, 4)}****${key.slice(-4)}`;
}

// Key哈希
export function hashKey(key: string): string {
  return crypto.createHash('md5').update(key).digest('hex');
}

// ==================== 用户管理 ====================

export function isSetupComplete(): boolean {
  const result = db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number };
  return result.count > 0;
}

export function createUser(username: string, password: string): void {
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hashPassword(password));
}

export function validateUser(username: string, password: string): number | null {
  const user = db.prepare('SELECT id, password_hash FROM users WHERE username = ?').get(username) as { id: number; password_hash: string } | undefined;
  if (!user) return null;

  const [scheme, saltHex, hashHex] = user.password_hash.split('$');
  if (scheme === 'scrypt' && saltHex && hashHex) {
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
    return crypto.timingSafeEqual(actual, expected) ? user.id : null;
  }

  // Migrate accounts created by older releases after a successful login.
  const legacyHash = crypto.createHash('sha256').update(password).digest('hex');
  if (legacyHash !== user.password_hash) return null;
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(password), user.id);
  return user.id;
}

export function changePassword(userId: number, newPassword: string): void {
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), userId);
}

// ==================== Session管理 ====================

export function createSession(userId: number): string {
  const sessionId = generateSessionId();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24小时
  db.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').run(sessionId, userId, expiresAt);
  return sessionId;
}

export function validateSession(sessionId: string): number | null {
  const session = db.prepare('SELECT user_id, expires_at FROM sessions WHERE id = ?').get(sessionId) as { user_id: number; expires_at: string } | undefined;
  if (session && new Date(session.expires_at) > new Date()) {
    return session.user_id;
  }
  if (session) {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
  }
  return null;
}

export function deleteSession(sessionId: string): void {
  db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
}

// ==================== 统计管理 ====================

export function recordCall(key: string, model: string, creditsUsed: number = 0, remainingCredits: number = 0): void {
  console.log(`[DB] recordCall called: model=${model}, creditsUsed=${creditsUsed}, remainingCredits=${remainingCredits}`);
  const keyHash = hashKey(key);
  const preview = keyPreview(key);
  
  try {
    const existing = db.prepare('SELECT id, call_count, credits_used FROM key_stats WHERE key_hash = ? AND model = ?').get(keyHash, model) as { id: number; call_count: number; credits_used: number } | undefined;
    
    if (existing) {
      db.prepare(`UPDATE key_stats SET call_count = ?, credits_used = ?, remaining_credits = ?, last_used = datetime('now', 'localtime') WHERE id = ?`)
        .run(existing.call_count + 1, existing.credits_used + creditsUsed, remainingCredits, existing.id);
      console.log(`[DB] Updated key_stats: id=${existing.id}, call_count=${existing.call_count + 1}, creditsUsed=${creditsUsed}`);
    } else {
      db.prepare('INSERT INTO key_stats (key_hash, key_preview, model, credits_used, remaining_credits) VALUES (?, ?, ?, ?, ?)')
        .run(keyHash, preview, model, creditsUsed, remainingCredits);
      console.log(`[DB] Inserted new key_stats: model=${model}, preview=${preview}, creditsUsed=${creditsUsed}`);
    }
  } catch (e) {
    console.error(`[DB] recordCall error:`, e);
  }
}

export function getStats() {
  // 按Key汇总（包含剩余积分）
  const keyStats = db.prepare(`
    SELECT key_preview, SUM(call_count) as total_calls, SUM(credits_used) as total_credits, 
           MAX(remaining_credits) as remaining_credits, MAX(last_used) as last_used
    FROM key_stats GROUP BY key_hash ORDER BY total_calls DESC
  `).all();
  
  // 按模型汇总
  const modelStats = db.prepare(`
    SELECT model, SUM(call_count) as total_calls, SUM(credits_used) as total_credits
    FROM key_stats GROUP BY model ORDER BY total_calls DESC
  `).all();
  
  // 总计
  const totals = db.prepare(`
    SELECT SUM(call_count) as total_calls, SUM(credits_used) as total_credits FROM key_stats
  `).get() as { total_calls: number; total_credits: number };
  
  return { keyStats, modelStats, totals };
}

// ==================== 媒体管理 ====================

export function saveMedia(type: 'image' | 'video', url: string, model: string, prompt: string, key: string): void {
  db.prepare('INSERT INTO media (type, url, model, prompt, key_preview) VALUES (?, ?, ?, ?, ?)')
    .run(type, url, model, prompt, keyPreview(key));
}

export function getMedia(page: number = 1, limit: number = 20, type?: string) {
  const offset = (page - 1) * limit;
  let query = 'SELECT * FROM media';
  let countQuery = 'SELECT COUNT(*) as total FROM media';
  const params: any[] = [];
  
  if (type) {
    query += ' WHERE type = ?';
    countQuery += ' WHERE type = ?';
    params.push(type);
  }
  
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  
  const items = db.prepare(query).all(...params, limit, offset);
  const countResult = db.prepare(countQuery).get(...params) as { total: number };
  
  return {
    items,
    total: countResult.total,
    page,
    limit,
    totalPages: Math.ceil(countResult.total / limit)
  };
}

// ==================== 日志管理 ====================

const MAX_LOGS = 1000;

export function addLog(level: string, message: string): void {
  db.prepare('INSERT INTO logs (level, message) VALUES (?, ?)').run(level, message);
  
  // 清理旧日志
  db.prepare(`DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT ${MAX_LOGS})`).run();
}

export function getLogs(level?: string, limit: number = 100) {
  let query = 'SELECT * FROM logs';
  const params: any[] = [];
  
  if (level && level !== 'ALL') {
    query += ' WHERE level = ?';
    params.push(level);
  }
  
  query += ' ORDER BY id DESC LIMIT ?';
  params.push(limit);
  
  return db.prepare(query).all(...params);
}

export function clearLogs(): void {
  db.prepare('DELETE FROM logs').run();
}

// ==================== 即梦账号池 ====================

export type PoolToken = {
  id: number;
  name: string;
  token_preview: string;
  enabled: number;
  status: string;
  points: number | null;
  failure_count: number;
  last_error: string | null;
  last_checked: string | null;
  last_used: string | null;
  created_at: string;
  updated_at: string;
};

function tokenEncryptionKey(): Buffer {
  const value = process.env.TOKEN_ENCRYPTION_KEY || '';
  if (!/^[a-f0-9]{64}$/i.test(value)) {
    throw new Error('TOKEN_ENCRYPTION_KEY must be a 64-character hexadecimal value');
  }
  return Buffer.from(value, 'hex');
}

function encryptToken(token: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', tokenEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map(value => value.toString('base64url')).join('.');
}

function decryptToken(payload: string): string {
  const [ivValue, tagValue, encryptedValue] = payload.split('.');
  if (!ivValue || !tagValue || !encryptedValue) throw new Error('Invalid encrypted token');
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    tokenEncryptionKey(),
    Buffer.from(ivValue, 'base64url')
  );
  decipher.setAuthTag(Buffer.from(tagValue, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(encryptedValue, 'base64url')),
    decipher.final()
  ]).toString('utf8');
}

export function isTokenPoolConfigured(): boolean {
  return /^[a-f0-9]{64}$/i.test(process.env.TOKEN_ENCRYPTION_KEY || '') &&
    Boolean(process.env.JIMENG_API_KEY);
}

export function listPoolTokens(): PoolToken[] {
  return db.prepare(`
    SELECT id, name, token_preview, enabled, status, points, failure_count,
           last_error, last_checked, last_used, created_at, updated_at
    FROM pool_tokens ORDER BY enabled DESC, id ASC
  `).all() as PoolToken[];
}

export function addPoolToken(name: string, token: string): number {
  const result = db.prepare(`
    INSERT INTO pool_tokens (name, token_encrypted, token_preview)
    VALUES (?, ?, ?)
  `).run(name.trim(), encryptToken(token.trim()), keyPreview(token.trim()));
  return Number(result.lastInsertRowid);
}

export function updatePoolToken(id: number, values: { name?: string; token?: string; enabled?: boolean }): boolean {
  const current = db.prepare('SELECT id FROM pool_tokens WHERE id = ?').get(id);
  if (!current) return false;
  if (typeof values.name === 'string') {
    db.prepare(`UPDATE pool_tokens SET name = ?, updated_at = datetime('now', 'localtime') WHERE id = ?`)
      .run(values.name.trim(), id);
  }
  if (typeof values.token === 'string' && values.token.trim()) {
    const token = values.token.trim();
    db.prepare(`
      UPDATE pool_tokens
      SET token_encrypted = ?, token_preview = ?, status = 'unchecked', points = NULL,
          failure_count = 0, last_error = NULL, updated_at = datetime('now', 'localtime')
      WHERE id = ?
    `).run(encryptToken(token), keyPreview(token), id);
  }
  if (typeof values.enabled === 'boolean') {
    db.prepare(`UPDATE pool_tokens SET enabled = ?, updated_at = datetime('now', 'localtime') WHERE id = ?`)
      .run(values.enabled ? 1 : 0, id);
  }
  return true;
}

export function deletePoolToken(id: number): boolean {
  return db.prepare('DELETE FROM pool_tokens WHERE id = ?').run(id).changes > 0;
}

export function getPoolTokenSecret(id: number): string | null {
  const row = db.prepare('SELECT token_encrypted FROM pool_tokens WHERE id = ?').get(id) as { token_encrypted: string } | undefined;
  return row ? decryptToken(row.token_encrypted) : null;
}

export function getPoolTokensForUse(): Array<{ id: number; token: string }> {
  const rows = db.prepare(`
    SELECT id, token_encrypted FROM pool_tokens
    WHERE enabled = 1 AND status != 'invalid'
    ORDER BY CASE WHEN last_used IS NULL THEN 0 ELSE 1 END, last_used ASC, id ASC
  `).all() as Array<{ id: number; token_encrypted: string }>;
  return rows.map(row => ({ id: row.id, token: decryptToken(row.token_encrypted) }));
}

export function markPoolTokenUsed(id: number): void {
  db.prepare(`
    UPDATE pool_tokens
    SET status = 'healthy', failure_count = 0,
        last_error = NULL, updated_at = datetime('now', 'localtime')
    WHERE id = ?
  `).run(id);
}

export function reservePoolToken(id: number): void {
  db.prepare(`
    UPDATE pool_tokens
    SET last_used = datetime('now', 'localtime'), updated_at = datetime('now', 'localtime')
    WHERE id = ?
  `).run(id);
}

export function markPoolTokenFailure(id: number, error: string): void {
  db.prepare(`
    UPDATE pool_tokens
    SET status = 'error', failure_count = failure_count + 1, last_error = ?,
        updated_at = datetime('now', 'localtime')
    WHERE id = ?
  `).run(error.slice(0, 500), id);
}

export function recordPoolTokenCheck(id: number, live: boolean, points: number | null, error?: string): void {
  db.prepare(`
    UPDATE pool_tokens
    SET status = ?, points = ?, last_error = ?, last_checked = datetime('now', 'localtime'),
        failure_count = CASE WHEN ? THEN 0 ELSE failure_count + 1 END,
        updated_at = datetime('now', 'localtime')
    WHERE id = ?
  `).run(live ? 'healthy' : 'invalid', points, error?.slice(0, 500) || null, live ? 1 : 0, id);
}

export default {
  isSetupComplete,
  createUser,
  validateUser,
  changePassword,
  createSession,
  validateSession,
  deleteSession,
  recordCall,
  getStats,
  saveMedia,
  getMedia,
  addLog,
  getLogs,
  clearLogs,
  isTokenPoolConfigured,
  listPoolTokens,
  addPoolToken,
  updatePoolToken,
  deletePoolToken,
  getPoolTokenSecret,
  getPoolTokensForUse,
  reservePoolToken,
  markPoolTokenUsed,
  markPoolTokenFailure,
  recordPoolTokenCheck
};
