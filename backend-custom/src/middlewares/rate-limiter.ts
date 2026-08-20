import { Request, Response, NextFunction } from 'express';
import { env } from '../config/env.js';
import { ErrorMessages } from '../constants/errors.js';
import { logger } from '../utils/logger.js';

interface FailedAttemptRecord {
  count: number;
  lockedUntil: number;
}

class LoginRateLimiter {
  private failedAttempts = new Map<string, FailedAttemptRecord>();

  private getKey(req: Request, email?: string): string {
    const ip = req.ip || req.socket.remoteAddress || 'unknown-ip';
    const normalizedEmail = (email || '').toLowerCase().trim();
    return `${ip}:${normalizedEmail}`;
  }

  public checkLockout(req: Request, res: Response, next: NextFunction): void {
    const email = req.body?.email;
    const key = this.getKey(req, email);
    const record = this.failedAttempts.get(key);

    if (record && record.lockedUntil && Date.now() < record.lockedUntil) {
      logger.authEvent({
        event: 'RATE_LIMIT_BLOCKED',
        ip: req.ip,
        email,
        details: { lockedUntil: new Date(record.lockedUntil).toISOString() },
      });

      res.status(429).json({ error: ErrorMessages.RATE_LIMIT_LOCKOUT });
      return;
    }

    next();
  }

  public recordFailure(req: Request, email?: string): void {
    const key = this.getKey(req, email);
    const now = Date.now();
    const entry = this.failedAttempts.get(key) || { count: 0, lockedUntil: 0 };

    entry.count += 1;
    if (entry.count >= env.MAX_FAILED_ATTEMPTS) {
      entry.lockedUntil = now + env.LOCKOUT_MS;
      entry.count = 0;
      logger.authEvent({
        event: 'RATE_LIMIT_BLOCKED',
        ip: req.ip,
        email,
        details: { lockedForMs: env.LOCKOUT_MS },
      });
    }

    this.failedAttempts.set(key, entry);
  }

  public reset(req: Request, email?: string): void {
    const key = this.getKey(req, email);
    this.failedAttempts.delete(key);
  }
}

export const rateLimiter = new LoginRateLimiter();
