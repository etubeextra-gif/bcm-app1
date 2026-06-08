/**
 * BCM — Secret Messages Backend
 * Pure Node.js, no external dependencies
 * Run: node server.js
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const url = require('url');

// ── CONFIG ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const DB_FILE = path.join(__dirname, 'data', 'db.json');
const UPLOADS_DIR = path.join(__dirname, 'data', 'uploads');
const MAX_BODY = 20 * 1024 * 1024; // 20 MB

// ── ENSURE DATA DIRS ──────────────────────────────────────────────────────────
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ── DB HELPERS ────────────────────────────────────────────────────────────────
function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch {
    return { users: {}, messages: {}, redemptions: [] };
  }
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ── CRYPTO HELPERS ────────────────────────────────────────────────────────────
function uuid() {
  return crypto.randomUUID();
}

function hashPin(pin) {
  return crypto.createHash('sha256').update('bcm_salt_' + pin).digest('hex');
}

function checkPin(pin, hash) {
  return hashPin(pin) === hash;
}

function signJWT(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000) })).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyJWT(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (sig !== expected) return null;
    return JSON.parse(Buffer.from(body, 'base64url').toString());
  } catch {
    return null;
  }
}

// ── WORD LIST FOR LOGIN IDs ───────────────────────────────────────────────────
const ADJECTIVES = ['Silent','Shadow','Iron','Crimson','Jade','Neon','Phantom','Steel','Obsidian','Amber','Cobalt','Violet','Onyx','Silver','Ghost','Cipher','Raven','Storm','Frost','Ember'];
const NOUNS = ['Falcon','Cipher','Wolf','Dagger','Viper','Sphinx','Raven','Lynx','Hawk','Cobra','Fox','Tiger','Bear','Eagle','Shark','Panther','Scorpion','Dragon','Phoenix','Wraith'];

function uniqueLoginId() {
  const db = loadDB();
  const existing = new Set(Object.values(db.users).map(u => u.login_id));
  let id;
  do {
    const adj = ADJECTIVES[Math.floor(Math.random() * ADJECTIVES.length)];
    const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
    const num = Math.floor(10 + Math.random() * 90);
    id = `${adj}${noun}${num}`;
  } while (existing.has(id));
  return id;
}

function uniqueCode() {
  const db = loadDB();
  const existing = new Set(Object.values(db.messages).map(m => m.redemption_code));
  let code;
  do {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let body = '';
    for (let i = 0; i < 6; i++) body += chars[Math.floor(Math.random() * chars.length)];
    code = 'BCM-' + body;
  } while (existing.has(code));
  return code;
}

// ── HTTP HELPERS ──────────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BODY) { reject(new Error('Request too large')); return; }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseMultipart(buffer, boundary) {
  const result = { fields: {}, files: {} };
  const sep = Buffer.from('--' + boundary);
  const parts = [];
  let start = 0;

  while (true) {
    const idx = buffer.indexOf(sep, start);
    if (idx === -1) break;
    const end = buffer.indexOf(sep, idx + sep.length);
    if (end === -1) break;
    parts.push(buffer.slice(idx + sep.length + 2, end - 2));
    start = end;
  }

  for (const part of parts) {
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd === -1) continue;
    const headerStr = part.slice(0, headerEnd).toString();
    const body = part.slice(headerEnd + 4);

    const nameMatch = headerStr.match(/name="([^"]+)"/);
    const filenameMatch = headerStr.match(/filename="([^"]+)"/);
    const ctMatch = headerStr.match(/Content-Type:\s*([^\r\n]+)/i);

    if (!nameMatch) continue;
    const name = nameMatch[1];

    if (filenameMatch) {
      result.files[name] = {
        filename: filenameMatch[1],
        mimetype: ctMatch ? ctMatch[1].trim() : 'application/octet-stream',
        data: body,
      };
    } else {
      result.fields[name] = body.toString().trim();
    }
  }
  return result;
}

function send(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function authMiddleware(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  const payload = verifyJWT(token);
  return payload ? payload.userId : null;
}

// ── ROUTES ────────────────────────────────────────────────────────────────────
const routes = {};

function route(method, path, handler) {
  routes[`${method}:${path}`] = handler;
}

// GET /health
route('GET', '/health', async (req, res) => {
  send(res, 200, { status: 'ok' });
});
route('POST', '/auth/register', async (req, res) => {
  const buf = await readBody(req);
  const { pin } = JSON.parse(buf.toString());
  if (!/^\d{6}$/.test(pin)) return send(res, 400, { error: 'PIN must be exactly 6 digits' });
  const db = loadDB();
  const id = uuid();
  const login_id = uniqueLoginId();
  db.users[id] = { id, login_id, pin_hash: hashPin(pin), created_at: new Date().toISOString() };
  saveDB(db);
  const token = signJWT({ userId: id });
  send(res, 201, { token, login_id });
});

// POST /auth/login
route('POST', '/auth/login', async (req, res) => {
  const buf = await readBody(req);
  const { login_id, pin } = JSON.parse(buf.toString());
  if (!login_id || !pin) return send(res, 400, { error: 'Login ID and PIN are required' });
  const db = loadDB();
  const user = Object.values(db.users).find(u => u.login_id === login_id);
  if (!user || !checkPin(String(pin), user.pin_hash)) return send(res, 401, { error: 'Invalid Login ID or PIN' });
  const token = signJWT({ userId: user.id });
  send(res, 200, { token, login_id: user.login_id });
});

// GET /profile
route('GET', '/profile', async (req, res) => {
  const userId = authMiddleware(req);
  if (!userId) return send(res, 401, { error: 'Unauthorized' });
  const db = loadDB();
  const user = db.users[userId];
  if (!user) return send(res, 404, { error: 'User not found' });
  const allMsgs = Object.values(db.messages).filter(m => m.user_id === userId && !m.deleted);
  const now = Date.now();
  const unredeemedMsgs = allMsgs.filter(m => !db.redemptions.some(r => r.message_id === m.id));
  const activeMsgs = unredeemedMsgs.filter(m => !m.expires_at || new Date(m.expires_at).getTime() >= now);
  const totalRedemptions = db.redemptions.filter(r => allMsgs.some(m => m.id === r.message_id)).length;
  send(res, 200, {
    login_id: user.login_id,
    total_messages: allMsgs.length,
    active_messages: activeMsgs.length,
    total_redemptions: totalRedemptions,
    created_at: user.created_at,
  });
});

// GET /messages
route('GET', '/messages', async (req, res) => {
  const userId = authMiddleware(req);
  if (!userId) return send(res, 401, { error: 'Unauthorized' });
  const db = loadDB();
  const now = Date.now();
  const msgs = Object.values(db.messages)
    .filter(m => m.user_id === userId && !m.deleted)
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .map(m => {
      const redeemed = db.redemptions.some(r => r.message_id === m.id);
      const isExpired = m.expires_at && new Date(m.expires_at).getTime() < now;
      return {
        id: m.id,
        message_type: m.message_type,
        redemption_code: m.redemption_code,
        one_time_view: m.one_time_view,
        expires_at: m.expires_at,
        created_at: m.created_at,
        is_active: !redeemed && !isExpired,
        redeemed,
        expired: isExpired,
      };
    });
  send(res, 200, { messages: msgs });
});

// POST /messages/text
route('POST', '/messages/text', async (req, res) => {
  const userId = authMiddleware(req);
  if (!userId) return send(res, 401, { error: 'Unauthorized' });
  const buf = await readBody(req);
  const { text_content, one_time_view, expiry_ms } = JSON.parse(buf.toString());
  if (!text_content || !text_content.trim()) return send(res, 400, { error: 'Message cannot be empty' });
  const db = loadDB();
  const id = uuid();
  const code = uniqueCode();
  const expires_at = expiry_ms && expiry_ms !== 'never'
    ? new Date(Date.now() + parseInt(expiry_ms)).toISOString() : null;
  db.messages[id] = {
    id, user_id: userId, message_type: 'text',
    text_content: text_content.trim(), media_file: null,
    redemption_code: code, one_time_view: !!one_time_view,
    expires_at, created_at: new Date().toISOString(), deleted: false,
  };
  saveDB(db);
  send(res, 201, { redemption_code: code, id });
});

// POST /messages/media  (multipart/form-data)
route('POST', '/messages/media', async (req, res) => {
  const userId = authMiddleware(req);
  if (!userId) return send(res, 401, { error: 'Unauthorized' });
  const ct = req.headers['content-type'] || '';
  const boundaryMatch = ct.match(/boundary=([^\s;]+)/);
  if (!boundaryMatch) return send(res, 400, { error: 'Missing multipart boundary' });
  const buf = await readBody(req);
  const parsed = parseMultipart(buf, boundaryMatch[1]);
  const file = parsed.files['file'];
  if (!file) return send(res, 400, { error: 'No file uploaded' });
  if (file.data.length > 10 * 1024 * 1024) return send(res, 400, { error: 'File too large (max 10 MB)' });

  const ext = path.extname(file.filename) || '.bin';
  const fileId = uuid();
  const filename = fileId + ext;
  fs.writeFileSync(path.join(UPLOADS_DIR, filename), file.data);

  const db = loadDB();
  const id = uuid();
  const code = uniqueCode();
  const message_type = file.mimetype.startsWith('image/') ? 'image' : 'video';
  const expiry_ms = parsed.fields['expiry_ms'];
  const expires_at = expiry_ms && expiry_ms !== 'never'
    ? new Date(Date.now() + parseInt(expiry_ms)).toISOString() : null;
  db.messages[id] = {
    id, user_id: userId, message_type,
    text_content: null, media_file: filename, media_mime: file.mimetype,
    redemption_code: code, one_time_view: parsed.fields['one_time_view'] === 'true',
    expires_at, created_at: new Date().toISOString(), deleted: false,
  };
  saveDB(db);
  send(res, 201, { redemption_code: code, id });
});

// POST /redeem
route('POST', '/redeem', async (req, res) => {
  const buf = await readBody(req);
  const { code } = JSON.parse(buf.toString());
  if (!code) return send(res, 400, { error: 'Code is required' });

  let raw = code.toUpperCase().replace(/[\s-]/g, '');
  let normalized;
  if (/^BCM[A-Z0-9]{6}$/.test(raw)) {
    normalized = 'BCM-' + raw.slice(3);
  } else if (/^BCM-[A-Z0-9]{6}$/.test(code.toUpperCase().trim())) {
    normalized = code.toUpperCase().trim();
  } else {
    return send(res, 400, { error: 'Invalid code format — must be BCM-XXXXXX' });
  }

  const db = loadDB();
  const msg = Object.values(db.messages).find(m => m.redemption_code === normalized);
  if (!msg || msg.deleted) return send(res, 404, { error: 'Invalid code — transmission not found' });
  if (msg.expires_at && new Date(msg.expires_at).getTime() < Date.now())
    return send(res, 410, { error: 'This transmission has expired' });
  if (msg.one_time_view && db.redemptions.some(r => r.message_id === msg.id))
    return send(res, 410, { error: 'This transmission has already been redeemed' });

  db.redemptions.push({ id: uuid(), message_id: msg.id, redeemed_at: new Date().toISOString() });
  if (msg.one_time_view) db.messages[msg.id].deleted = true;
  saveDB(db);

  const response = {
    message_type: msg.message_type,
    one_time_view: msg.one_time_view,
    text_content: msg.text_content || null,
    media_mime: msg.media_mime || null,
    media_data: null,
  };

  // For media, return base64 data URI
  if (msg.media_file) {
    const filepath = path.join(UPLOADS_DIR, msg.media_file);
    if (fs.existsSync(filepath)) {
      const data = fs.readFileSync(filepath);
      response.media_data = `data:${msg.media_mime};base64,${data.toString('base64')}`;
    }
  }

  send(res, 200, response);
});

// GET /uploads/:filename  (serve media files directly)
function serveUpload(req, res, filename) {
  const filepath = path.join(UPLOADS_DIR, path.basename(filename));
  if (!fs.existsSync(filepath)) return send(res, 404, { error: 'File not found' });
  const ext = path.extname(filename).toLowerCase();
  const mimes = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp', '.mp4': 'video/mp4', '.webm': 'video/webm' };
  const mime = mimes[ext] || 'application/octet-stream';
  const data = fs.readFileSync(filepath);
  res.writeHead(200, { 'Content-Type': mime, 'Content-Length': data.length, 'Access-Control-Allow-Origin': '*' });
  res.end(data);
}

// ── MAIN REQUEST HANDLER ──────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url);
  const pathname = parsed.pathname;

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    });
    return res.end();
  }

  // Serve uploaded files
  if (req.method === 'GET' && pathname.startsWith('/uploads/')) {
    return serveUpload(req, res, pathname.slice(9));
  }

  // Serve frontend HTML
  if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    const htmlPath = fs.existsSync(path.join(__dirname, 'public', 'index.html')) ? path.join(__dirname, 'public', 'index.html') : path.join(__dirname, 'index.html');
    if (fs.existsSync(htmlPath)) {
      const html = fs.readFileSync(htmlPath);
      res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': html.length });
      return res.end(html);
    }
  }

  const handler = routes[`${req.method}:${pathname}`];
  if (!handler) return send(res, 404, { error: 'Route not found' });

  try {
    await handler(req, res);
  } catch (err) {
    console.error(`[ERROR] ${req.method} ${pathname}:`, err.message);
    send(res, 500, { error: err.message || 'Internal server error' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🔐 BCM Backend running on http://localhost:${PORT}`);
  console.log(`   Data stored in: ${DB_FILE}`);
  console.log(`   Uploads stored in: ${UPLOADS_DIR}\n`);
});
