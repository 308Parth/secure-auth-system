import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const envSchema = z.object({
  PORT: z.string().default('3000').transform((v) => parseInt(v, 10)),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  DATABASE_URL: z.string().default('postgresql://postgres:postgres@localhost:5432/secure_auth_eval'),
  CORS_ORIGIN: z.string().default('http://localhost:8080'),
  MAX_FAILED_ATTEMPTS: z.string().default('5').transform((v) => parseInt(v, 10)),
  LOCKOUT_MS: z.string().default('60000').transform((v) => parseInt(v, 10)),
  SESSION_TTL_MS: z.string().default('1800000').transform((v) => parseInt(v, 10)),
  STORAGE_LOCAL_DIR: z.string().default('./storage'),
});

const parsedEnv = envSchema.safeParse(process.env);

if (!parsedEnv.success) {
  console.error('Invalid environment variables:', parsedEnv.error.format());
  process.exit(1);
}

export const env = parsedEnv.data;
