import { pool, isPostgresAvailable } from '../config/db.js';
import { cryptoUtil } from '../utils/crypto.js';
import { env } from '../config/env.js';

export interface SessionRecord {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
}

// In-Memory session fallback store
export const memorySessions = new Map<string, SessionRecord>();

export class SessionRepository {
  async createSession(
    userId: string,
    rawToken: string,
    ipAddress?: string,
    userAgent?: string,
    ttlMs: number = env.SESSION_TTL_MS
  ): Promise<SessionRecord> {
    const tokenHash = cryptoUtil.hashToken(rawToken);
    const expiresAt = new Date(Date.now() + ttlMs);

    const session: SessionRecord = {
      id: cryptoUtil.generateToken(),
      userId,
      tokenHash,
      expiresAt,
    };

    memorySessions.set(tokenHash, session);

    if (isPostgresAvailable) {
      try {
        const query = `
          INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, expires_at)
          VALUES ($1, $2, $3, $4, $5)
        `;
        await pool.query(query, [userId, tokenHash, ipAddress || null, userAgent || null, expiresAt]);
      } catch {
        // Fallback already saved in memory
      }
    }

    return session;
  }

  async findSessionByToken(rawToken: string): Promise<SessionRecord | null> {
    const tokenHash = cryptoUtil.hashToken(rawToken);

    if (!isPostgresAvailable) {
      const session = memorySessions.get(tokenHash);
      if (!session) return null;
      if (Date.now() > session.expiresAt.getTime()) {
        memorySessions.delete(tokenHash);
        return null;
      }
      return session;
    }

    try {
      const query = `
        SELECT id, user_id AS "userId", token_hash AS "tokenHash", expires_at AS "expiresAt"
        FROM sessions
        WHERE token_hash = $1
      `;
      const res = await pool.query(query, [tokenHash]);
      if (res.rows.length === 0) return null;

      const session = res.rows[0];
      if (new Date() > new Date(session.expiresAt)) {
        await this.deleteSessionByToken(rawToken);
        return null;
      }
      return session;
    } catch {
      const session = memorySessions.get(tokenHash);
      if (!session) return null;
      if (Date.now() > session.expiresAt.getTime()) {
        memorySessions.delete(tokenHash);
        return null;
      }
      return session;
    }
  }

  async deleteSessionByToken(rawToken: string): Promise<boolean> {
    const tokenHash = cryptoUtil.hashToken(rawToken);
    memorySessions.delete(tokenHash);

    if (isPostgresAvailable) {
      try {
        const query = `DELETE FROM sessions WHERE token_hash = $1`;
        const res = await pool.query(query, [tokenHash]);
        return (res.rowCount ?? 0) > 0;
      } catch {
        return true;
      }
    }
    return true;
  }

  async deleteSessionsByUserId(userId: string): Promise<number> {
    let count = 0;
    for (const [key, sess] of memorySessions.entries()) {
      if (sess.userId === userId) {
        memorySessions.delete(key);
        count++;
      }
    }

    if (isPostgresAvailable) {
      try {
        const query = `DELETE FROM sessions WHERE user_id = $1`;
        const res = await pool.query(query, [userId]);
        return res.rowCount ?? count;
      } catch {
        return count;
      }
    }
    return count;
  }
}

export const sessionRepository = new SessionRepository();
