/**
 * mock-api.js
 * -----------
 * A tiny in-browser "fake backend" so index.html feels alive before you've
 * written the real one. It reads seed-data.json, keeps everything in memory,
 * and intercepts window.fetch for the routes the task describes:
 *
 *   POST /register
 *   POST /login
 *   POST /logout
 *   GET  /me
 *   GET  /files
 *   GET  /files/:id
 *   GET  /files/:id/download
 *
 * IMPORTANT: this is a teaching/demo aid, not a reference implementation.
 * - "Hashing" here is a trivial non-cryptographic hash, just so the code
 *   never compares or stores plaintext passwords directly. Your real
 *   backend must use bcrypt/argon2/scrypt, not this.
 * - Sessions are an in-memory Map, wiped on page reload. A real backend
 *   would use a signed JWT or a server-side session store (e.g. Redis, DB).
 * - Everything below runs client-side and is fully visible/editable by
 *   whoever opens devtools — that's fine for a local demo, never fine for
 *   production auth.
 *
 * Enable/disable from index.html with the "Use in-browser mock API" checkbox.
 */

(function () {
  const SESSION_TTL_MS = 30 * 60 * 1000; // 30 min
  const MAX_FAILED_ATTEMPTS = 5;
  const LOCKOUT_MS = 60 * 1000; // 60 sec

  // Fallback copy of seed-data.json, used only if the fetch below fails
  // (e.g. you double-clicked index.html instead of serving it, and the
  // browser's file:// CORS rules blocked loading the JSON file).
  const FALLBACK_SEED = {
    users: [
      {
        id: "usr_001", email: "alice@example.com", password: "Password123!",
        profile: { fullName: "Alice Nakamura", displayName: "alice", bio: "Product designer who likes clean UIs.", createdAt: "2025-01-14T09:32:00Z", role: "user" },
        files: [
          { id: "file_001", ownerId: "usr_001", fileName: "resume_alice.pdf", mimeType: "application/pdf", sizeBytes: 84213, uploadedAt: "2025-01-15T10:02:00Z" },
          { id: "file_002", ownerId: "usr_001", fileName: "profile_photo.jpg", mimeType: "image/jpeg", sizeBytes: 231044, uploadedAt: "2025-01-16T14:20:00Z" }
        ]
      },
      {
        id: "usr_002", email: "bob@example.com", password: "Password123!",
        profile: { fullName: "Bob Alvarez", displayName: "bob", bio: "Backend engineer, coffee enthusiast.", createdAt: "2025-02-02T11:15:00Z", role: "user" },
        files: [
          { id: "file_003", ownerId: "usr_002", fileName: "project_notes.txt", mimeType: "text/plain", sizeBytes: 5210, uploadedAt: "2025-02-03T09:40:00Z" },
          { id: "file_004", ownerId: "usr_002", fileName: "invoice_march.pdf", mimeType: "application/pdf", sizeBytes: 62890, uploadedAt: "2025-03-01T08:05:00Z" }
        ]
      },
      {
        id: "usr_003", email: "carol@example.com", password: "Password123!",
        profile: { fullName: "Carol Whitfield", displayName: "carol", bio: "QA lead focused on security testing.", createdAt: "2025-03-10T16:48:00Z", role: "user" },
        files: [
          { id: "file_005", ownerId: "usr_003", fileName: "test_plan.docx", mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", sizeBytes: 41200, uploadedAt: "2025-03-11T12:30:00Z" },
          { id: "file_006", ownerId: "usr_003", fileName: "vacation.png", mimeType: "image/png", sizeBytes: 512300, uploadedAt: "2025-04-02T18:00:00Z" }
        ]
      }
    ]
  };

  // ---- tiny non-cryptographic hash, demo purposes ONLY ----
  function fakeHash(password) {
    let h = 0;
    for (let i = 0; i < password.length; i++) {
      h = (Math.imul(31, h) + password.charCodeAt(i)) | 0;
    }
    return "demo_hash_" + h.toString(16);
  }

  // ---- in-memory state ----
  const state = {
    usersByEmail: new Map(),   // email -> user record (with hashed password)
    filesByOwner: new Map(),   // ownerId -> [files]
    filesById: new Map(),      // fileId -> file
    sessions: new Map(),       // token -> { userId, expiresAt }
    failedAttempts: new Map(), // email -> { count, lockedUntil }
  };

  function loadSeed(seed) {
    for (const u of seed.users) {
      const record = {
        id: u.id,
        email: u.email,
        passwordHash: fakeHash(u.password),
        profile: u.profile,
      };
      state.usersByEmail.set(u.email, record);
      state.filesByOwner.set(u.id, u.files);
      for (const f of u.files) state.filesById.set(f.id, f);
    }
    console.info("[mock-api] loaded", state.usersByEmail.size, "users and", state.filesById.size, "files");
  }

  async function init() {
    try {
      const res = await fetch("./seed-data.json");
      if (!res.ok) throw new Error("HTTP " + res.status);
      loadSeed(await res.json());
    } catch (err) {
      console.warn("[mock-api] could not load seed-data.json (" + err.message + "), using built-in fallback data. Serve this folder over http:// for the real file to load.");
      loadSeed(FALLBACK_SEED);
    }
  }
  const ready = init();

  // ---- helpers ----
  function json(status, body) {
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  }

  function newToken() {
    return (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()).slice(2)) + "." + Date.now();
  }

  function getBearer(req) {
    const auth = req.headers.get("Authorization") || "";
    const match = auth.match(/^Bearer (.+)$/);
    return match ? match[1] : null;
  }

  function authenticate(req) {
    const token = getBearer(req);
    if (!token) return null;
    const session = state.sessions.get(token);
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
      state.sessions.delete(token);
      return null;
    }
    return session.userId;
  }

  function findUserById(userId) {
    for (const u of state.usersByEmail.values()) if (u.id === userId) return u;
    return null;
  }

  // ---- route handlers ----
  async function handleRegister(req) {
    const { email, password } = await req.json();
    if (!email || !password) return json(400, { error: "email and password are required" });
    if (state.usersByEmail.has(email)) return json(409, { error: "An account with that email already exists" });

    const id = "usr_" + Math.random().toString(36).slice(2, 8);
    const record = {
      id,
      email,
      passwordHash: fakeHash(password),
      profile: { fullName: "", displayName: email.split("@")[0], bio: "", createdAt: new Date().toISOString(), role: "user" },
    };
    state.usersByEmail.set(email, record);
    state.filesByOwner.set(id, []);
    return json(201, { id, email });
  }

  async function handleLogin(req) {
    const { email, password } = await req.json();
    const GENERIC_ERROR = { error: "Invalid email or password" };

    const lock = state.failedAttempts.get(email);
    if (lock && lock.lockedUntil && Date.now() < lock.lockedUntil) {
      return json(429, { error: "Too many failed attempts. Try again in a bit." });
    }

    const user = state.usersByEmail.get(email);
    const valid = user && user.passwordHash === fakeHash(password);

    if (!valid) {
      const entry = state.failedAttempts.get(email) || { count: 0, lockedUntil: 0 };
      entry.count += 1;
      if (entry.count >= MAX_FAILED_ATTEMPTS) {
        entry.lockedUntil = Date.now() + LOCKOUT_MS;
        entry.count = 0;
      }
      state.failedAttempts.set(email, entry);
      return json(401, GENERIC_ERROR); // never reveal whether the email exists
    }

    state.failedAttempts.delete(email);
    const token = newToken();
    state.sessions.set(token, { userId: user.id, expiresAt: Date.now() + SESSION_TTL_MS });
    return json(200, { token, user: { id: user.id, email: user.email } });
  }

  async function handleLogout(req) {
    const token = getBearer(req);
    if (token) state.sessions.delete(token); // server-side invalidation, not just a client-side clear
    return json(200, { message: "Logged out" });
  }

  async function handleMe(req) {
    const userId = authenticate(req);
    if (!userId) return json(401, { error: "Not authenticated" });
    const user = findUserById(userId);
    if (!user) return json(401, { error: "Not authenticated" });
    return json(200, { id: user.id, email: user.email, profile: user.profile });
  }

  async function handleFiles(req) {
    const userId = authenticate(req);
    if (!userId) return json(401, { error: "Not authenticated" });
    const files = state.filesByOwner.get(userId) || [];
    return json(200, { files });
  }

  async function handleFileById(req, fileId) {
    const userId = authenticate(req);
    if (!userId) return json(401, { error: "Not authenticated" });
    const file = state.filesById.get(fileId);
    if (!file) return json(404, { error: "File not found" });
    if (file.ownerId !== userId) return json(403, { error: "You do not have access to this file" }); // distinct from 404
    return json(200, { file });
  }

  async function handleFileDownload(req, fileId) {
    const userId = authenticate(req);
    if (!userId) return new Response("Not authenticated", { status: 401 });
    const file = state.filesById.get(fileId);
    if (!file) return new Response("File not found", { status: 404 });
    if (file.ownerId !== userId) return new Response("Forbidden", { status: 403 });
    const fakeContent = `This is a mock stand-in for "${file.fileName}" (${file.mimeType}, ${file.sizeBytes} bytes).\nIn the real backend this endpoint would stream the actual file bytes.`;
    return new Response(fakeContent, { status: 200, headers: { "Content-Type": "text/plain" } });
  }

  // ---- patch window.fetch, but only when mock mode is enabled ----
  const realFetch = window.fetch.bind(window);

  window.fetch = async function (input, init) {
    const mockToggle = document.getElementById("mockMode");
    const mockEnabled = mockToggle && mockToggle.checked;

    if (!mockEnabled) return realFetch(input, init);

    await ready; // make sure seed data is loaded
    const url = typeof input === "string" ? input : input.url;
    const { pathname } = new URL(url, window.location.href);
    const req = new Request(url, init);

    // simulate a little network latency so it feels real
    await new Promise((r) => setTimeout(r, 150));

    if (pathname === "/register" && req.method === "POST") return handleRegister(req);
    if (pathname === "/login" && req.method === "POST") return handleLogin(req);
    if (pathname === "/logout" && req.method === "POST") return handleLogout(req);
    if (pathname === "/me" && req.method === "GET") return handleMe(req);
    if (pathname === "/files" && req.method === "GET") return handleFiles(req);

    let m = pathname.match(/^\/files\/([^/]+)\/download$/);
    if (m && req.method === "GET") return handleFileDownload(req, m[1]);

    m = pathname.match(/^\/files\/([^/]+)$/);
    if (m && req.method === "GET") return handleFileById(req, m[1]);

    return json(404, { error: "No mock route for " + req.method + " " + pathname });
  };

  console.info("[mock-api] ready — check the 'Use in-browser mock API' box in index.html to enable it");
})();