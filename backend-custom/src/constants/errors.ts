export const ErrorMessages = {
  REQUIRED_CREDENTIALS: 'email and password are required',
  EMAIL_EXISTS: 'An account with that email already exists',
  INVALID_CREDENTIALS: 'Invalid email or password',
  RATE_LIMIT_LOCKOUT: 'Too many failed attempts. Try again in a bit.',
  UNAUTHENTICATED: 'Not authenticated',
  FILE_NOT_FOUND: 'File not found',
  FILE_FORBIDDEN: 'You do not have access to this file',
  SERVER_ERROR: 'Internal server error',
} as const;
