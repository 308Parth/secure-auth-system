import { Request, Response } from 'express';
import { authService } from '../services/auth.service.js';
import { rateLimiter } from '../middlewares/rate-limiter.js';
import { AuthenticatedRequest } from '../middlewares/auth.js';
import { env } from '../config/env.js';

export class AuthController {
  async register(req: Request, res: Response): Promise<void> {
    const { email, password } = req.body || {};
    const result = await authService.register(email, password);
    res.status(result.status).json(result.body);
  }

  async login(req: Request, res: Response): Promise<void> {
    const { email, password } = req.body || {};
    const ip = req.ip || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];

    const result = await authService.login(email, password, ip, userAgent);

    if (result.status !== 200) {
      rateLimiter.recordFailure(req, email);
      res.status(result.status).json(result.body);
      return;
    }

    rateLimiter.reset(req, email);

    // Set cookie for browser cookie mode
    res.cookie('session', result.token, {
      httpOnly: true,
      secure: env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: env.SESSION_TTL_MS,
    });

    res.status(result.status).json(result.body);
  }

  async logout(req: AuthenticatedRequest, res: Response): Promise<void> {
    const result = await authService.logout(req.sessionToken, req.user?.id);
    res.clearCookie('session');
    res.status(result.status).json(result.body);
  }

  async me(req: AuthenticatedRequest, res: Response): Promise<void> {
    const user = req.user!;
    res.status(200).json({
      id: user.id,
      email: user.email,
      profile: user.profile,
    });
  }
}

export const authController = new AuthController();
