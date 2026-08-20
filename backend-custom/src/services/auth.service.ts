import { userRepository } from '../repositories/user.repository.js';
import { sessionRepository } from '../repositories/session.repository.js';
import { cryptoUtil } from '../utils/crypto.js';
import { ErrorMessages } from '../constants/errors.js';
import { logger } from '../utils/logger.js';
import crypto from 'crypto';

export class AuthService {
  async register(email?: string, password?: string) {
    if (!email || !password || email.trim() === '' || password.trim() === '') {
      return { status: 400, body: { error: ErrorMessages.REQUIRED_CREDENTIALS } };
    }

    const normalizedEmail = email.toLowerCase().trim();
    const existing = await userRepository.findByEmail(normalizedEmail);
    if (existing) {
      logger.authEvent({
        event: 'REGISTER_FAILED',
        email: normalizedEmail,
        details: { reason: 'Email already registered' },
      });
      return { status: 409, body: { error: ErrorMessages.EMAIL_EXISTS } };
    }

    const id = `usr_${crypto.randomBytes(4).toString('hex')}`;
    const passwordHash = await cryptoUtil.hashPassword(password);
    const user = await userRepository.createUser(id, normalizedEmail, passwordHash, {
      fullName: '',
      displayName: normalizedEmail.split('@')[0],
      bio: '',
      role: 'user',
    });

    logger.authEvent({
      event: 'REGISTER_SUCCESS',
      userId: user.id,
      email: user.email,
    });

    return {
      status: 201,
      body: { id: user.id, email: user.email },
    };
  }

  async login(email?: string, password?: string, ipAddress?: string, userAgent?: string) {
    if (!email || !password || email.trim() === '' || password.trim() === '') {
      return { status: 400, body: { error: ErrorMessages.REQUIRED_CREDENTIALS } };
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await userRepository.findByEmail(normalizedEmail);

    if (!user) {
      // Execute dummy verification to equalize response timing
      await cryptoUtil.dummyVerify(password);
      logger.authEvent({
        event: 'LOGIN_FAILED',
        ip: ipAddress,
        email: normalizedEmail,
        details: { reason: 'User not found' },
      });
      return { status: 401, body: { error: ErrorMessages.INVALID_CREDENTIALS } };
    }

    const isValid = await cryptoUtil.verifyPassword(user.passwordHash, password);
    if (!isValid) {
      logger.authEvent({
        event: 'LOGIN_FAILED',
        ip: ipAddress,
        email: normalizedEmail,
        userId: user.id,
        details: { reason: 'Invalid password' },
      });
      return { status: 401, body: { error: ErrorMessages.INVALID_CREDENTIALS } };
    }

    const rawToken = cryptoUtil.generateToken();
    await sessionRepository.createSession(user.id, rawToken, ipAddress, userAgent);

    logger.authEvent({
      event: 'LOGIN_SUCCESS',
      ip: ipAddress,
      email: normalizedEmail,
      userId: user.id,
    });

    return {
      status: 200,
      token: rawToken,
      body: {
        token: rawToken,
        user: { id: user.id, email: user.email },
      },
    };
  }

  async logout(token?: string, userId?: string) {
    if (token) {
      await sessionRepository.deleteSessionByToken(token);
    }
    logger.authEvent({
      event: 'LOGOUT_SUCCESS',
      userId,
    });
    return {
      status: 200,
      body: { message: 'Logged out' },
    };
  }
}

export const authService = new AuthService();
