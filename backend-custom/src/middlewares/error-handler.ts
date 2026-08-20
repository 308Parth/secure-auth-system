import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger.js';
import { ErrorMessages } from '../constants/errors.js';

export function errorHandler(
  err: unknown,
  req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  next: NextFunction
): void {
  logger.error('Unhandled server error', err, { path: req.path, method: req.method });

  if (res.headersSent) {
    return;
  }

  res.status(500).json({
    error: ErrorMessages.SERVER_ERROR,
  });
}
