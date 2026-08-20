import fs from 'fs';
import path from 'path';
import { pool, initDatabase } from '../src/config/db.js';
import { cryptoUtil } from '../src/utils/crypto.js';
import { logger } from '../src/utils/logger.js';

interface SeedFile {
  id: string;
  ownerId: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  uploadedAt: string;
}

interface SeedUser {
  id: string;
  email: string;
  password: string;
  profile: {
    fullName: string;
    displayName: string;
    bio: string;
    createdAt: string;
    role: string;
  };
  files: SeedFile[];
}

interface SeedDataset {
  users: SeedUser[];
}

async function runSeed() {
  logger.info('Starting PostgreSQL database seed...');
  await initDatabase();

  // Load seed-data.json
  const seedPath = path.resolve(process.cwd(), '../frontend/seed-data.json');
  let seedData: SeedDataset;

  if (fs.existsSync(seedPath)) {
    seedData = JSON.parse(fs.readFileSync(seedPath, 'utf-8'));
  } else {
    throw new Error(`Cannot find seed data file at: ${seedPath}`);
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Clear existing data
    logger.info('Purging old data...');
    await client.query('TRUNCATE TABLE sessions, files, profiles, users CASCADE');

    const storageBaseDir = path.resolve(process.cwd(), 'storage');
    if (!fs.existsSync(storageBaseDir)) {
      fs.mkdirSync(storageBaseDir, { recursive: true });
    }

    for (const u of seedData.users) {
      logger.info(`Seeding user: ${u.email} (${u.id}) with Argon2id hash...`);
      const passwordHash = await cryptoUtil.hashPassword(u.password);

      // Insert User
      await client.query(
        `INSERT INTO users (id, email, password_hash, created_at) VALUES ($1, $2, $3, $4)`,
        [u.id, u.email.toLowerCase().trim(), passwordHash, u.profile.createdAt]
      );

      // Insert Profile
      await client.query(
        `INSERT INTO profiles (user_id, full_name, display_name, bio, role, created_at) VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          u.id,
          u.profile.fullName,
          u.profile.displayName,
          u.profile.bio,
          u.profile.role,
          u.profile.createdAt,
        ]
      );

      // Create user storage folder
      const userDir = path.join(storageBaseDir, u.id);
      if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
      }

      // Insert Files
      for (const f of u.files) {
        const relativeStoragePath = `storage/${u.id}/${f.fileName}`;
        const absoluteStoragePath = path.join(userDir, f.fileName);

        // Write a physical mock binary file to disk
        const sampleContent = `Document: ${f.fileName}\nOwner: ${u.email} (${u.id})\nSize: ${f.sizeBytes} bytes\nMIME: ${f.mimeType}\nGenerated: ${f.uploadedAt}\n\n[CONFIDENTIAL SECURE USER ASSET]`;
        fs.writeFileSync(absoluteStoragePath, sampleContent, 'utf-8');

        await client.query(
          `INSERT INTO files (id, owner_id, file_name, storage_path, mime_type, size_bytes, uploaded_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [f.id, u.id, f.fileName, relativeStoragePath, f.mimeType, f.sizeBytes, f.uploadedAt]
        );
      }
    }

    await client.query('COMMIT');
    logger.info('Database seeded successfully with 3 users, profiles, and 6 scoped files.');
  } catch (err) {
    await client.query('ROLLBACK');
    logger.error('Failed to seed database', err);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

runSeed();
