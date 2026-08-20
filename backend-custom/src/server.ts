import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import fs from 'fs';
import path from 'path';
import { env } from './config/env.js';
import { initDatabase, isPostgresAvailable } from './config/db.js';
import { logger } from './utils/logger.js';
import { authController } from './controllers/auth.controller.js';
import { fileController } from './controllers/file.controller.js';
import { authMiddleware } from './middlewares/auth.js';
import { rateLimiter } from './middlewares/rate-limiter.js';
import { errorHandler } from './middlewares/error-handler.js';
import { memoryUsers } from './repositories/user.repository.js';
import { memoryFiles } from './repositories/file.repository.js';
import { cryptoUtil } from './utils/crypto.js';

const app = express();

// Trust proxy for reverse proxies / rate limiting headers
app.set('trust proxy', 1);

// Global Middlewares
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json());

// Request logging
app.use((req, res, next) => {
  logger.info(`HTTP ${req.method} ${req.path}`, { ip: req.ip });
  next();
});

// Authentication Routes
app.post('/register', (req, res) => authController.register(req, res));
app.post('/login', (req, res, next) => rateLimiter.checkLockout(req, res, next), (req, res) =>
  authController.login(req, res)
);
app.post('/logout', authMiddleware, (req, res) => authController.logout(req, res));
app.get('/me', authMiddleware, (req, res) => authController.me(req, res));

// Protected File Resource Routes
app.get('/files', authMiddleware, (req, res) => fileController.listFiles(req, res));
app.get('/files/:id', authMiddleware, (req, res) => fileController.getFileById(req, res));
app.get('/files/:id/download', authMiddleware, (req, res) => fileController.downloadFileById(req, res));

// Error Boundary Middleware
app.use(errorHandler);

async function autoSeedMemoryStore() {
  try {
    const seedPath = path.resolve(process.cwd(), '../frontend/seed-data.json');
    if (!fs.existsSync(seedPath)) return;

    const raw = fs.readFileSync(seedPath, 'utf-8');
    const data = JSON.parse(raw);

    logger.info('Auto-populating in-memory database with Alice, Bob, and Carol seed data...');

    for (const u of data.users) {
      const passwordHash = await cryptoUtil.hashPassword(u.password);
      memoryUsers.set(u.id, {
        id: u.id,
        email: u.email.toLowerCase().trim(),
        passwordHash,
        createdAt: u.profile.createdAt,
        profile: {
          fullName: u.profile.fullName,
          displayName: u.profile.displayName,
          bio: u.profile.bio,
          role: u.profile.role,
          createdAt: u.profile.createdAt,
        },
      });

      for (const f of u.files) {
        memoryFiles.set(f.id, {
          id: f.id,
          ownerId: u.id,
          fileName: f.fileName,
          storagePath: `storage/${u.id}/${f.fileName}`,
          mimeType: f.mimeType,
          sizeBytes: f.sizeBytes,
          uploadedAt: f.uploadedAt,
        });
      }
    }
    logger.info(`Auto-seeded ${memoryUsers.size} users and ${memoryFiles.size} scoped files with Argon2id.`);
  } catch (err) {
    logger.error('Failed to auto-seed in-memory store', err);
  }
}

// Start Server
async function bootstrap() {
  const connected = await initDatabase();
  if (!connected) {
    await autoSeedMemoryStore();
  }

  app.listen(env.PORT, () => {
    logger.info(`Custom Secure Auth Backend listening on port ${env.PORT} (Base URL: http://localhost:${env.PORT})`);
  });
}

bootstrap();

export default app;
