'use strict';

/**
 * BCM — Black Coin Messages
 * Express backend: auth, messages, redeem
 *
 * Data is stored in-process (Map/Object) by default.
 * Swap the "DB" section for a real DB (SQLite, Postgres, etc.) when ready.
 *
 * Endpoints:
 *   POST /auth/register      { pin }            → { token, login_id }
 *   POST /auth/login         { login_id, pin }  → { token, login_id }
 *   GET  /profile            (auth)             → profile + stats
 *   GET  /messages           (auth)             → { messages: [...] }
 *   POST /messages/text      (auth)             → { redemption_code }
 *   POST /messages/media     (auth, multipart)  → { redemption_code }
 *   POST /redeem             (auth) { code }    → message content
 */

const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');
const { v4: uuidv4 } = require('uuid');

// ── CONFIG ────────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'bcm-super-secret-change-in-prod';
const BCRYPT_ROUNDS = 10;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const MAX_FILE_MB = 20;

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ── IN-MEMORY "DB" ────────────────────────────────────────────────────────────
// Replace these Maps with real DB queries as needed.
/** @type {Map<string, {id,login_id,pin_hash,created_at}>} */
const users = new Map();

/** @type {Map<string, {id,user_id,message_type,text_content?,file_path?,
 *                      one_time_view,expiry_at,created_at,redeemed,redeemed_at?}>} */
const messages = new Map();

/** @type {Map<string, string>}  code → message_id */
const codeIndex = new Map();

// ── HELPERS ───────────────────────────────────────────────────────────────────

/** Generate a random adjective-noun style login_id, e.g. "swift-falcon-42" */
function generateLoginId() {
  const adj  = ['swift','silent','dark','golden','iron','shadow','jade','velvet','obsidian','ember'];
  const noun = ['falcon','specter','wolf','raven','cipher','herald','echo','prism','vault','nexus'];
  const num  = Math.floor(Math.random() * 90) + 10;
  const id   = `${adj[Math.floor(Math.random()*adj.length)]}-${noun[Math.floor(Math.random()*noun.length)]}-${num}`;
  // Ensure uniqueness
  for (const u of users.values()) if (u.login_id === id) return generateLoginId();
  return id;
}

/** Generate a BCM redemption code: 3 uppercase letters + dash + 6 alphanumeric chars */
function generateCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const prefix = Array.from({length:3}, () => chars[Math.floor(Math.random()*chars.length)]).join('');
  const body   = Array.from({length:6}, () => chars[Math.floor(Math.random()*chars.length)]).join('');
  const code   = `${prefix}-${body}`;
  if (codeIndex.has(code)) return generateCode(); // collision-safe
  return code;
}

function signToken(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '30d' });
}

function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = users.get(payload.sub);
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/** Read uploaded file as a base64 data URL so the frontend can render it directly */
function fileToDataUrl(filePath, mimetype) {
  const buf = fs.readFileSync(filePath);
  return `data:${mimetype};base64,${buf.toString('base64')}`;
}

function isExpired(msg) {
  if (!msg.expiry_at) return false;
  return new Date() > new Date(msg.expiry_at);
}

/** Compute derived stats for a user */
function userStats(userId) {
  let total = 0, active = 0, redemptions = 0;
  for (const m of messages.values()) {
    if (m.user_id !== userId) continue;
    total++;
    if (m.redeemed) { redemptions++; continue; }
    if (!isExpired(m)) active++;
  }
  return { total_messages: total, active_messages: active, total_redemptions: redemptions };
}

// ── MULTER (file upload) ───────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename:    (_, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`),
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_MB * 1024 * 1024 },
  fileFilter(_, file, cb) {
    const allowed = /image\/(jpeg|png|gif|webp)|video\/(mp4|webm|ogg)/;
    if (allowed.test(file.mimetype)) cb(null, true);
    else cb(new Error('Only images and videos are allowed'));
  },
});

// ── APP ───────────────────────────────────────────────────────────────────────
const app = express();

app.use(cors());
app.use(express.json());

// Serve the frontend HTML
app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH ──────────────────────────────────────────────────────────────────────

/**
 * POST /auth/register
 * Body: { pin: "123456" }
 * Creates a new user with a generated login_id.
 */
app.post('/auth/register', async (req, res) => {
  try {
    const { pin } = req.body;
    if (!pin || !/^\d{6}$/.test(String(pin))) {
      return res.status(400).json({ error: 'PIN must be exactly 6 digits' });
    }
    const pin_hash  = await bcrypt.hash(String(pin), BCRYPT_ROUNDS);
    const id        = uuidv4();
    const login_id  = generateLoginId();
    const created_at = new Date().toISOString();

    users.set(id, { id, login_id, pin_hash, created_at });

    const token = signToken(id);
    return res.status(201).json({ token, login_id });
  } catch (err) {
    console.error('/auth/register', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /auth/login
 * Body: { login_id: "...", pin: "123456" }
 */
app.post('/auth/login', async (req, res) => {
  try {
    const { login_id, pin } = req.body;
    if (!login_id || !pin) {
      return res.status(400).json({ error: 'login_id and pin are required' });
    }

    let found = null;
    for (const u of users.values()) {
      if (u.login_id === login_id) { found = u; break; }
    }
    if (!found) return res.status(401).json({ error: 'Invalid Login ID or PIN' });

    const ok = await bcrypt.compare(String(pin), found.pin_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid Login ID or PIN' });

    const token = signToken(found.id);
    return res.json({ token, login_id: found.login_id });
  } catch (err) {
    console.error('/auth/login', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── PROFILE ───────────────────────────────────────────────────────────────────

/**
 * GET /profile
 * Returns the authenticated user's profile + stats.
 */
app.get('/profile', requireAuth, (req, res) => {
  const { id, login_id, created_at } = req.user;
  const stats = userStats(id);
  return res.json({ login_id, created_at, ...stats });
});

// ── MESSAGES ──────────────────────────────────────────────────────────────────

/**
 * GET /messages
 * Returns all messages belonging to the authenticated user (newest first).
 */
app.get('/messages', requireAuth, (req, res) => {
  const result = [];
  for (const m of messages.values()) {
    if (m.user_id !== req.user.id) continue;
    result.push(publicMessage(m));
  }
  result.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  return res.json({ messages: result });
});

/** Strip internal fields before sending to client */
function publicMessage(m) {
  return {
    id:               m.id,
    message_type:     m.message_type,
    redemption_code:  m.redemption_code,
    one_time_view:    m.one_time_view,
    expiry_at:        m.expiry_at,
    created_at:       m.created_at,
    redeemed:         m.redeemed,
    redeemed_at:      m.redeemed_at || null,
    expired:          isExpired(m),
  };
}

/**
 * POST /messages/text
 * Auth required.
 * Body: { text_content, one_time_view, expiry_ms }
 *   expiry_ms: number of ms from now, or "never" / 0 for no expiry.
 */
app.post('/messages/text', requireAuth, (req, res) => {
  try {
    const { text_content, one_time_view, expiry_ms } = req.body;
    if (!text_content || !text_content.trim()) {
      return res.status(400).json({ error: 'text_content is required' });
    }

    const id = uuidv4();
    const code = generateCode();
    const expiry_at = resolveExpiry(expiry_ms);

    const msg = {
      id, user_id: req.user.id,
      message_type: 'text',
      text_content: text_content.trim(),
      one_time_view: !!one_time_view,
      expiry_at,
      created_at: new Date().toISOString(),
      redemption_code: code,
      redeemed: false,
    };

    messages.set(id, msg);
    codeIndex.set(code, id);

    return res.status(201).json({ redemption_code: code });
  } catch (err) {
    console.error('/messages/text', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /messages/media
 * Auth required. Multipart form.
 * Fields: file, one_time_view, expiry_ms
 */
app.post('/messages/media', requireAuth, upload.single('file'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const { one_time_view, expiry_ms } = req.body;
    const message_type = req.file.mimetype.startsWith('image/') ? 'image' : 'video';
    const id   = uuidv4();
    const code = generateCode();
    const expiry_at = resolveExpiry(expiry_ms);

    const msg = {
      id, user_id: req.user.id,
      message_type,
      file_path: req.file.path,
      file_mimetype: req.file.mimetype,
      one_time_view: one_time_view === 'true' || one_time_view === true,
      expiry_at,
      created_at: new Date().toISOString(),
      redemption_code: code,
      redeemed: false,
    };

    messages.set(id, msg);
    codeIndex.set(code, id);

    return res.status(201).json({ redemption_code: code });
  } catch (err) {
    console.error('/messages/media', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

// ── REDEEM ────────────────────────────────────────────────────────────────────

/**
 * POST /redeem
 * Auth required.
 * Body: { code: "ABC-123456" }
 * Returns the message content (text or base64 media_data).
 */
app.post('/redeem', requireAuth, (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'code is required' });

    const normalised = String(code).trim().toUpperCase();
    const msgId = codeIndex.get(normalised);
    if (!msgId) return res.status(404).json({ error: 'Invalid or unknown code' });

    const msg = messages.get(msgId);
    if (!msg) return res.status(404).json({ error: 'Message not found' });

    if (msg.redeemed) return res.status(410).json({ error: 'This code has already been redeemed' });
    if (isExpired(msg)) return res.status(410).json({ error: 'This code has expired' });

    // Build response payload
    const payload = {
      message_type: msg.message_type,
      one_time_view: msg.one_time_view,
    };

    if (msg.message_type === 'text') {
      payload.text_content = msg.text_content;
    } else {
      // Inline base64 so frontend renders without a separate file endpoint
      payload.media_data = fileToDataUrl(msg.file_path, msg.file_mimetype);
    }

    // Mark redeemed for one-time-view
    if (msg.one_time_view) {
      msg.redeemed   = true;
      msg.redeemed_at = new Date().toISOString();
      // Optionally delete the file from disk
      if (msg.file_path && fs.existsSync(msg.file_path)) {
        fs.unlink(msg.file_path, () => {});
      }
    }

    return res.json(payload);
  } catch (err) {
    console.error('/redeem', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── HELPERS ───────────────────────────────────────────────────────────────────

/**
 * Convert expiry_ms (number of milliseconds) into an ISO expiry timestamp.
 * "never", 0, or missing → null (no expiry).
 */
function resolveExpiry(expiry_ms) {
  const ms = Number(expiry_ms);
  if (!ms || ms <= 0 || expiry_ms === 'never') return null;
  return new Date(Date.now() + ms).toISOString();
}

// ── 404 / ERROR ───────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  BCM backend running → http://localhost:${PORT}`);
  console.log(`  Serve the frontend HTML from ./public/index.html\n`);
});

module.exports = app; // for testing
