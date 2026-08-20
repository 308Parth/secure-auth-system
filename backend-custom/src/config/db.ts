import pg from 'pg';
import { env } from './env.js';
import fs from 'fs';
import path from 'path';
import { logger } from '../utils/logger.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: env.DATABASE_URL,
  connectionTimeoutMillis: 2000,
});

export let isPostgresAvailable = false;

export async function initDatabase(): Promise<boolean> {
  try {
    const client = await pool.connect();
    try {
      const schemaPath = path.resolve(process.cwd(), 'db/schema.sql');
      if (fs.existsSync(schemaPath)) {
        const ddl = fs.readFileSync(schemaPath, 'utf-8');
        await client.query(ddl);
      }
      isPostgresAvailable = true;
      logger.info('Connected to PostgreSQL database and verified schema.');
      return true;
    } finally {
      client.release();
    }
  } catch (err) {
    isPostgresAvailable = false;
    logger.warn('PostgreSQL not detected. Running in Standalone In-Memory Database Mode with full Argon2id and isolation enforcement.');
    return false;
  }
}
