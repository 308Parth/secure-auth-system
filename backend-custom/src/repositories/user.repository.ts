import { pool, isPostgresAvailable } from '../config/db.js';

export interface UserProfile {
  fullName: string;
  displayName: string;
  bio: string;
  createdAt: string;
  role: string;
}

export interface UserRecord {
  id: string;
  email: string;
  passwordHash: string;
  createdAt: string;
  profile?: UserProfile;
}

// In-Memory fallback store
export const memoryUsers = new Map<string, UserRecord>();

export class UserRepository {
  async findByEmail(email: string): Promise<UserRecord | null> {
    const normalized = email.toLowerCase().trim();

    if (!isPostgresAvailable) {
      for (const u of memoryUsers.values()) {
        if (u.email.toLowerCase().trim() === normalized) {
          return u;
        }
      }
      return null;
    }

    try {
      const query = `
        SELECT 
          u.id, u.email, u.password_hash AS "passwordHash", u.created_at AS "createdAt",
          p.full_name AS "fullName", p.display_name AS "displayName", p.bio, p.role, p.created_at AS "profileCreatedAt"
        FROM users u
        LEFT JOIN profiles p ON p.user_id = u.id
        WHERE LOWER(u.email) = LOWER($1)
      `;
      const res = await pool.query(query, [normalized]);
      if (res.rows.length === 0) return null;

      const row = res.rows[0];
      return {
        id: row.id,
        email: row.email,
        passwordHash: row.passwordHash,
        createdAt: row.createdAt.toISOString(),
        profile: {
          fullName: row.fullName || '',
          displayName: row.displayName || row.email.split('@')[0],
          bio: row.bio || '',
          role: row.role || 'user',
          createdAt: (row.profileCreatedAt || row.createdAt).toISOString(),
        },
      };
    } catch {
      for (const u of memoryUsers.values()) {
        if (u.email.toLowerCase().trim() === normalized) return u;
      }
      return null;
    }
  }

  async findById(id: string): Promise<UserRecord | null> {
    if (!isPostgresAvailable) {
      return memoryUsers.get(id) || null;
    }

    try {
      const query = `
        SELECT 
          u.id, u.email, u.password_hash AS "passwordHash", u.created_at AS "createdAt",
          p.full_name AS "fullName", p.display_name AS "displayName", p.bio, p.role, p.created_at AS "profileCreatedAt"
        FROM users u
        LEFT JOIN profiles p ON p.user_id = u.id
        WHERE u.id = $1
      `;
      const res = await pool.query(query, [id]);
      if (res.rows.length === 0) return null;

      const row = res.rows[0];
      return {
        id: row.id,
        email: row.email,
        passwordHash: row.passwordHash,
        createdAt: row.createdAt.toISOString(),
        profile: {
          fullName: row.fullName || '',
          displayName: row.displayName || row.email.split('@')[0],
          bio: row.bio || '',
          role: row.role || 'user',
          createdAt: (row.profileCreatedAt || row.createdAt).toISOString(),
        },
      };
    } catch {
      return memoryUsers.get(id) || null;
    }
  }

  async createUser(
    id: string,
    email: string,
    passwordHash: string,
    profile?: Partial<UserProfile>
  ): Promise<UserRecord> {
    const record: UserRecord = {
      id,
      email: email.toLowerCase().trim(),
      passwordHash,
      createdAt: new Date().toISOString(),
      profile: {
        fullName: profile?.fullName || '',
        displayName: profile?.displayName || email.split('@')[0],
        bio: profile?.bio || '',
        role: profile?.role || 'user',
        createdAt: new Date().toISOString(),
      },
    };

    memoryUsers.set(id, record);

    if (isPostgresAvailable) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(
          `INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)`,
          [record.id, record.email, record.passwordHash]
        );
        await client.query(
          `INSERT INTO profiles (user_id, full_name, display_name, bio, role) VALUES ($1, $2, $3, $4, $5)`,
          [record.id, record.profile!.fullName, record.profile!.displayName, record.profile!.bio, record.profile!.role]
        );
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
      } finally {
        client.release();
      }
    }

    return record;
  }
}

export const userRepository = new UserRepository();
