import { Request, Response, NextFunction } from 'express';
import { sessionRepository } from '../repositories/session.repository.js';
import { userRepository, UserRecord } from '../repositories/user.repository.js';
import { ErrorMessages } from '../constants/errors.js';
import { logger } from '../utils/logger.js';

export interface AuthenticatedRequest extends Request {
  user?: UserRecord;
  sessionToken?: string;
}

export async function authMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers['authorization'] || '';
  let token: string | null = null;

  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else if (req.cookies && (req.cookies.session || req.cookies.token)) {
    token = req.cookies.session || req.cookies.token;
  }

  if (!token) {
    logger.authEvent({
      event: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      ip: req.ip,
      details: { path: req.path, method: req.method, reason: 'Missing token' },
    });
    res.status(401).json({ error: ErrorMessages.UNAUTHENTICATED });
    return;
  }

  try {
    const session = await sessionRepository.findSessionByToken(token);
    if (!session) {
      logger.authEvent({
        event: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        ip: req.ip,
        details: { path: req.path, method: req.method, reason: 'Invalid or expired session token' },
      });
      res.status(401).json({ error: ErrorMessages.UNAUTHENTICATED });
      return;
    }

    const user = await userRepository.findById(session.userId);
    if (!user) {
      res.status(401).json({ error: ErrorMessages.UNAUTHENTICATED });
      return;
    }

    req.user = user;
    req.sessionToken = token;
    next();
  } catch (err) {
    logger.error('Error in auth middleware', err);
    res.status(401).json({ error: ErrorMessages.UNAUTHENTICATED });
  }
}
