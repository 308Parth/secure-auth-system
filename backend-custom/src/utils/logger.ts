export type AuthEventType =
  | 'REGISTER_SUCCESS'
  | 'REGISTER_FAILED'
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILED'
  | 'LOGOUT_SUCCESS'
  | 'RATE_LIMIT_BLOCKED'
  | 'UNAUTHORIZED_ACCESS_ATTEMPT'
  | 'IDOR_ACCESS_BLOCKED';

interface AuthLogPayload {
  event: AuthEventType;
  ip?: string;
  email?: string;
  userId?: string;
  resourceId?: string;
  details?: Record<string, unknown>;
}

export const logger = {
  info: (message: string, meta?: Record<string, unknown>) => {
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', message, ...meta }));
  },
  warn: (message: string, meta?: Record<string, unknown>) => {
    console.warn(JSON.stringify({ timestamp: new Date().toISOString(), level: 'WARN', message, ...meta }));
  },
  error: (message: string, error?: unknown, meta?: Record<string, unknown>) => {
    console.error(
      JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'ERROR',
        message,
        error: error instanceof Error ? { message: error.message, stack: error.stack } : error,
        ...meta,
      })
    );
  },
  authEvent: (payload: AuthLogPayload) => {
    const isFailure =
      payload.event.includes('FAILED') ||
      payload.event.includes('BLOCKED') ||
      payload.event.includes('UNAUTHORIZED');

    const logFn = isFailure ? console.warn : console.log;
    logFn(
      JSON.stringify({
        timestamp: new Date().toISOString(),
        audit: 'AUTH_AUDIT_LOG',
        ...payload,
      })
    );
  },
};
