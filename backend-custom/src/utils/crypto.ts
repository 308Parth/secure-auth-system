import * as argon2 from 'argon2';
import crypto from 'crypto';

// Pre-computed static Argon2id hash for constant-time dummy verification
const DUMMY_HASH =
  '$argon2id$v=19$m=65536,t=3,p=4$dGVzdF9zYWx0XzEyMzQ1Ng$8j0g3Xq7K5iFwL4mN2oP1qR3sT5uV7wX9yZ0aB1cD2E';

export const cryptoUtil = {
  async hashPassword(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });
  },

  async verifyPassword(hash: string, password: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  },

  /**
   * Executes a constant-time Argon2id calculation when the user does not exist
   * to protect against timing-based user enumeration.
   */
  async dummyVerify(password: string): Promise<boolean> {
    try {
      await argon2.verify(DUMMY_HASH, password);
    } catch {
      // Ignored intentionally
    }
    return false;
  },

  generateToken(): string {
    const rawUuid = crypto.randomUUID();
    const entropy = crypto.randomBytes(8).toString('hex');
    return `${rawUuid}.${Date.now()}.${entropy}`;
  },

  hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  },
};
