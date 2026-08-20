import app from '../src/server.js';
import { cryptoUtil } from '../src/utils/crypto.js';
import http from 'http';

interface TestResult {
  suite: string;
  test: string;
  passed: boolean;
  error?: string;
  details?: unknown;
}

const results: TestResult[] = [];

function assert(condition: boolean, suite: string, testName: string, errorMsg?: string) {
  if (!condition) {
    results.push({ suite, test: testName, passed: false, error: errorMsg || 'Assertion failed' });
    console.error(`  ❌ [FAIL] ${suite} -> ${testName}: ${errorMsg || 'Assertion failed'}`);
  } else {
    results.push({ suite, test: testName, passed: true });
    console.log(`  ✅ [PASS] ${suite} -> ${testName}`);
  }
}

let server: http.Server;
let baseUrl: string;

async function request(path: string, options: { method?: string; headers?: Record<string, string>; body?: unknown } = {}) {
  const url = `${baseUrl}${path}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  const res = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  let body: any;
  const text = await res.text();
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }

  return { status: res.status, headers: res.headers, body };
}

async function runSecurityTestSuite() {
  console.log('\n===============================================================');
  console.log('🔒 EXECUTING COMPREHENSIVE SECURITY & ISOLATION TEST SUITE');
  console.log('===============================================================\n');

  // Start test server on random port
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      const addr = server.address() as any;
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });

  try {
    // -------------------------------------------------------------
    // SUITE 1: Cryptographic Password Hashing & Anti-Enumeration
    // -------------------------------------------------------------
    console.log('\n[Suite 1: Cryptography & Timing-Attack Defense]');
    const rawPass = 'StrongPassword123!';
    const hash = await cryptoUtil.hashPassword(rawPass);
    assert(hash.startsWith('$argon2id$'), 'Cryptography', 'Password is fully hashed using Argon2id algorithm');
    assert(!hash.includes(rawPass), 'Cryptography', 'Plaintext password is never stored or leaked');
    
    const isValid = await cryptoUtil.verifyPassword(hash, rawPass);
    assert(isValid === true, 'Cryptography', 'Argon2id verify succeeds with correct plaintext');

    const isInvalid = await cryptoUtil.verifyPassword(hash, 'WrongPassword!');
    assert(isInvalid === false, 'Cryptography', 'Argon2id verify fails with incorrect plaintext');

    // -------------------------------------------------------------
    // SUITE 2: Registration Validation & Duplication
    // -------------------------------------------------------------
    console.log('\n[Suite 2: Registration & Input Validation]');
    const regRes = await request('/register', {
      method: 'POST',
      body: { email: 'david@example.com', password: 'Password123!' },
    });
    assert(regRes.status === 201 && regRes.body.email === 'david@example.com', 'Registration', 'Registers new user with 201 status');

    const dupRes = await request('/register', {
      method: 'POST',
      body: { email: 'david@example.com', password: 'Password123!' },
    });
    assert(dupRes.status === 409 && dupRes.body.error === 'An account with that email already exists', 'Registration', 'Rejects duplicate email with 409 status');

    const missingRes = await request('/register', {
      method: 'POST',
      body: { email: '', password: '' },
    });
    assert(missingRes.status === 400 && missingRes.body.error === 'email and password are required', 'Registration', 'Rejects empty credentials with 400 status');

    // -------------------------------------------------------------
    // SUITE 3: Authentication, Generic Errors & Lockout
    // -------------------------------------------------------------
    console.log('\n[Suite 3: Authentication & Rate Limiting]');
    // Valid login
    const loginAlice = await request('/login', {
      method: 'POST',
      body: { email: 'alice@example.com', password: 'Password123!' },
    });
    assert(loginAlice.status === 200 && typeof loginAlice.body.token === 'string', 'Auth', 'Successful login returns 200 and session token');
    const aliceToken = loginAlice.body.token;

    // Login for Bob
    const loginBob = await request('/login', {
      method: 'POST',
      body: { email: 'bob@example.com', password: 'Password123!' },
    });
    const bobToken = loginBob.body.token;

    // Login for Carol
    const loginCarol = await request('/login', {
      method: 'POST',
      body: { email: 'carol@example.com', password: 'Password123!' },
    });
    const carolToken = loginCarol.body.token;

    // Indistinguishable Error Check: Unregistered email vs Wrong password
    const wrongPassRes = await request('/login', {
      method: 'POST',
      body: { email: 'alice@example.com', password: 'IncorrectPassword' },
    });
    const unknownEmailRes = await request('/login', {
      method: 'POST',
      body: { email: 'nonexistent_user@example.com', password: 'AnyPassword123' },
    });
    assert(
      wrongPassRes.status === 401 &&
      unknownEmailRes.status === 401 &&
      wrongPassRes.body.error === unknownEmailRes.body.error,
      'Anti-Enumeration',
      'Unregistered email and wrong password return identical 401 error message ("Invalid email or password")'
    );

    // Rate Limiting / Lockout Test: 5 consecutive failures triggers 429
    console.log('  ...Testing 5-attempt rate limit lockout on attacker@example.com...');
    for (let i = 0; i < 4; i++) {
      await request('/login', {
        method: 'POST',
        body: { email: 'attacker@example.com', password: 'bad' },
      });
    }
    const fifthFail = await request('/login', {
      method: 'POST',
      body: { email: 'attacker@example.com', password: 'bad' },
    });
    const sixthAttempt = await request('/login', {
      method: 'POST',
      body: { email: 'attacker@example.com', password: 'bad' },
    });
    assert(
      sixthAttempt.status === 429 && sixthAttempt.body.error.includes('Too many failed attempts'),
      'Rate-Limiting',
      'Exceeding 5 failed attempts triggers 429 lockout response'
    );

    // -------------------------------------------------------------
    // SUITE 4: Identity & Profile Isolation (/me)
    // -------------------------------------------------------------
    console.log('\n[Suite 4: Zero-Trust Identity Inspection (/me)]');
    const meAlice = await request('/me', {
      headers: { Authorization: `Bearer ${aliceToken}` },
    });
    assert(meAlice.status === 200 && meAlice.body.id === 'usr_001' && meAlice.body.email === 'alice@example.com', 'Identity', '/me strictly returns authenticated user (Alice)');
    assert(meAlice.body.profile && meAlice.body.profile.fullName === 'Alice Nakamura', 'Identity', '/me hydrates correct profile metadata for Alice');

    // Tampered Token Rejection
    const tamperedRes = await request('/me', {
      headers: { Authorization: `Bearer ${aliceToken}_tampered` },
    });
    assert(tamperedRes.status === 401, 'Identity', 'Tampered / forged token is rejected with 401');

    // Missing Token Rejection
    const missingTokenRes = await request('/me');
    assert(missingTokenRes.status === 401, 'Identity', 'Request with missing Authorization header is rejected with 401');

    // -------------------------------------------------------------
    // SUITE 5: Multi-Tenant Scoped File Isolation (/files)
    // -------------------------------------------------------------
    console.log('\n[Suite 5: Multi-Tenant Scoped File Isolation]');
    const filesAlice = await request('/files', { headers: { Authorization: `Bearer ${aliceToken}` } });
    const filesBob = await request('/files', { headers: { Authorization: `Bearer ${bobToken}` } });
    const filesCarol = await request('/files', { headers: { Authorization: `Bearer ${carolToken}` } });

    assert(
      filesAlice.status === 200 &&
      filesAlice.body.files.length === 2 &&
      filesAlice.body.files.every((f: any) => f.ownerId === 'usr_001'),
      'Multi-User Isolation',
      'Alice only sees her own files (file_001, file_002)'
    );

    assert(
      filesBob.status === 200 &&
      filesBob.body.files.length === 2 &&
      filesBob.body.files.every((f: any) => f.ownerId === 'usr_002'),
      'Multi-User Isolation',
      'Bob only sees his own files (file_003, file_004)'
    );

    assert(
      filesCarol.status === 200 &&
      filesCarol.body.files.length === 2 &&
      filesCarol.body.files.every((f: any) => f.ownerId === 'usr_003'),
      'Multi-User Isolation',
      'Carol only sees her own files (file_005, file_006)'
    );

    // -------------------------------------------------------------
    // SUITE 6: Cross-Tenant Direct Object Reference (IDOR) Defense
    // -------------------------------------------------------------
    console.log('\n[Suite 6: IDOR Cross-Tenant Access Defense (/files/:id)]');
    // Alice accesses her own file (file_001) -> 200 OK
    const ownFileRes = await request('/files/file_001', { headers: { Authorization: `Bearer ${aliceToken}` } });
    assert(ownFileRes.status === 200 && ownFileRes.body.file.id === 'file_001', 'IDOR Defense', 'User can access their own file metadata');

    // Alice probes Bob's file (file_003) -> 403 Forbidden
    const idorProbeBob = await request('/files/file_003', { headers: { Authorization: `Bearer ${aliceToken}` } });
    assert(idorProbeBob.status === 403 && idorProbeBob.body.error === 'You do not have access to this file', 'IDOR Defense', "Alice probing Bob's file (file_003) is blocked with 403 Forbidden");

    // Bob probes Carol's file (file_005) -> 403 Forbidden
    const idorProbeCarol = await request('/files/file_005', { headers: { Authorization: `Bearer ${bobToken}` } });
    assert(idorProbeCarol.status === 403, 'IDOR Defense', "Bob probing Carol's file (file_005) is blocked with 403 Forbidden");

    // Alice probes non-existent file (file_999) -> 404 Not Found
    const nonExistentFile = await request('/files/file_999', { headers: { Authorization: `Bearer ${aliceToken}` } });
    assert(nonExistentFile.status === 404 && nonExistentFile.body.error === 'File not found', 'IDOR Defense', 'Probing non-existent file returns 404 Not Found');

    // -------------------------------------------------------------
    // SUITE 7: Server-Side Logout Revocation
    // -------------------------------------------------------------
    console.log('\n[Suite 7: Server-Side Logout Invalidation]');
    const logoutRes = await request('/logout', {
      method: 'POST',
      headers: { Authorization: `Bearer ${aliceToken}` },
    });
    assert(logoutRes.status === 200 && logoutRes.body.message === 'Logged out', 'Session Revocation', 'Logout endpoint returns 200 OK');

    // Immediate replay of Alice's token against /me must fail with 401
    const postLogoutMe = await request('/me', {
      headers: { Authorization: `Bearer ${aliceToken}` },
    });
    assert(postLogoutMe.status === 401 && postLogoutMe.body.error === 'Not authenticated', 'Session Revocation', 'Token replay after logout fails with 401 (Server-side revocation verified)');

  } finally {
    server.close();
  }

  // -------------------------------------------------------------
  // Summary Report
  // -------------------------------------------------------------
  const total = results.length;
  const passed = results.filter((r) => r.passed).length;
  const failed = total - passed;

  console.log('\n===============================================================');
  console.log(`📊 TEST SUITE SUMMARY: ${passed}/${total} PASSED (${failed} FAILED)`);
  console.log('===============================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runSecurityTestSuite().catch((err) => {
  console.error('Fatal error during test suite execution:', err);
  process.exit(1);
});
