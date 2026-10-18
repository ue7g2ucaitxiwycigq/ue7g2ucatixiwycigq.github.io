/**
 * ============================================================
 *  Vaulta Messenger v2
 *  - Email verification (6-digit) via Gmail SMTP App Password
 *  - Forgot / Reset password
 *  - Admin account "support" (username + password only)
 *  - Admin panel: delete users, purge old users, ban, handle reports
 *  - Report users, block users
 *  - Groups with invitations (accept / decline from notifications)
 *  - Settings: change email, change username, change password,
 *    profile photo, destroy account (all messages removed)
 *  - Unsend message for everyone ("Delete for everyone") + "Delete for me" + Clear chat
 *  - Voice messages (record and send audio in any chat)
 *  - Voice calls: 1-to-1 and group calls (WebRTC, signaling over WebSocket)
 *
 *  Run:
 *    node server.js      (optionally: EMAIL_PASS=... ADMIN_PASSWORD=... node server.js)
 * ============================================================
 */

const express = require('express');
const http = require('http');
const { WebSocketServer, WebSocket } = require('ws');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');

let nodemailer;
try {
  nodemailer = require('nodemailer');
} catch (e) {
  nodemailer = null;
  console.error('[EMAIL] ❌ nodemailer is not installed. Run: npm install nodemailer');
}

const PORT = Number(process.env.PORT) || 3000;
// Paste your ngrok token between the quotes if you cannot set environment variables:
const NGROK_AUTHTOKEN = process.env.NGROK_AUTHTOKEN || '3Ixu21mhhy2OgFLONHzcLtSShOe_7iy2odvLUovQDvmGgmxQN';

// ---------------- Email settings ----------------
const EMAIL_USER = process.env.EMAIL_USER || 'vaulta23987465@gmail.com';
const EMAIL_PASS = String(process.env.EMAIL_PASS || 'utaygsznavddyesn').replace(/\s+/g, '');
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = Number(process.env.SMTP_PORT) || 465;

// ---------------- Admin settings ----------------
const ADMIN_USERNAME = 'support';
// Admin password (can be overridden with the ADMIN_PASSWORD environment variable)
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'bcXeiA54Bc8aK3n9xP95JfaygJdQfDbB';
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || EMAIL_USER).trim().toLowerCase();
const RESERVED_NAMES = ['support', 'admin', 'administrator', 'root'];

const MAX_CODE_ATTEMPTS = 5;
const CODE_TTL_MS = 15 * 60 * 1000;

const DATA_DIR = path.resolve('data');
const UPLOADS_DIR = path.resolve('uploads');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const GROUPS_FILE = path.join(DATA_DIR, 'groups.json');
const REPORTS_FILE = path.join(DATA_DIR, 'reports.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

function loadJSON(filePath, fallback) {
  try {
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');
      return content.trim() ? JSON.parse(content) : fallback;
    }
  } catch (err) {
    console.error('[DATA] Failed to load', filePath, err.message);
  }
  return fallback;
}

function saveJSON(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error('[DATA] Failed to save', filePath, err.message);
  }
}

let users = loadJSON(USERS_FILE, {});
let messages = loadJSON(MESSAGES_FILE, []);
let groups = loadJSON(GROUPS_FILE, {});
let reports = loadJSON(REPORTS_FILE, []);
const sessions = new Map();
const clients = new Map(); // ws -> username

const saveUsers = () => saveJSON(USERS_FILE, users);
const saveMessages = () => saveJSON(MESSAGES_FILE, messages);
const saveGroups = () => saveJSON(GROUPS_FILE, groups);
const saveReports = () => saveJSON(REPORTS_FILE, reports);

// ---------------- Helpers ----------------
function escapeHtmlServer(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function generateToken(username) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username, expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000 });
  return token;
}

function verifyToken(token) {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session || Date.now() > session.expiresAt) return null;
  return session.username;
}

function dropSessions(username) {
  for (const [t, s] of sessions.entries()) if (s.username === username) sessions.delete(t);
  leaveCall(username);
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function createPasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: hashPassword(password, salt) };
}

function verifyPassword(password, record) {
  const a = Buffer.from(hashPassword(String(password), record.salt), 'hex');
  const b = Buffer.from(record.passwordHash || '', 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function hashCode(code) {
  return crypto.createHash('sha256').update(String(code).trim()).digest('hex');
}

function generate6DigitCode() {
  return crypto.randomInt(100000, 1000000).toString();
}

function newChallenge(code) {
  return { codeHash: hashCode(code), expiresAt: Date.now() + CODE_TTL_MS, attempts: 0 };
}

function checkChallenge(challenge, code) {
  if (Date.now() > challenge.expiresAt) {
    return { ok: false, expired: true, error: 'Code expired, please request a new one' };
  }
  if ((challenge.attempts || 0) >= MAX_CODE_ATTEMPTS) {
    return { ok: false, locked: true, error: 'Too many attempts. Request a new code' };
  }
  const given = Buffer.from(hashCode(code), 'hex');
  const real = Buffer.from(challenge.codeHash, 'hex');
  if (given.length === real.length && crypto.timingSafeEqual(given, real)) return { ok: true };
  challenge.attempts = (challenge.attempts || 0) + 1;
  const left = MAX_CODE_ATTEMPTS - challenge.attempts;
  return {
    ok: false,
    error: left > 0 ? 'Incorrect code (attempts left: ' + left + ')' : 'Incorrect code. Request a new code'
  };
}

// login brute-force protection
const fails = new Map();
function lockedOut(key) {
  const f = fails.get(key);
  if (!f || f.count < 8) return false;
  if (Date.now() >= f.until) {
    fails.delete(key);
    return false;
  }
  return true;
}
function addFail(key) {
  const f = fails.get(key) || { count: 0, until: 0 };
  f.count++;
  if (f.count >= 8) f.until = Date.now() + 5 * 60 * 1000;
  fails.set(key, f);
}

function findUserByIdentifier(identifier) {
  const id = String(identifier || '').trim().toLowerCase();
  if (!id) return null;
  return users[id] || Object.values(users).find(u => !u.isAdmin && u.email && u.email.toLowerCase() === id) || null;
}

function publicUser(u) {
  return { username: u.username, email: u.email, avatar: u.avatar, isAdmin: !!u.isAdmin };
}

function isBlocked(by, target) {
  const u = users[by];
  return !!(u && (u.blocked || []).includes(target));
}

// ---------------- Realtime helpers ----------------
function sendTo(names, obj) {
  const out = JSON.stringify(obj);
  const set = new Set(names);
  for (const [w, u] of clients.entries()) {
    if (set.has(u) && w.readyState === WebSocket.OPEN) w.send(out);
  }
}

function broadcastAll(obj) {
  const out = JSON.stringify(obj);
  for (const [w] of clients.entries()) if (w.readyState === WebSocket.OPEN) w.send(out);
}

function isUserOnline(username) {
  for (const [w, u] of clients.entries()) if (u === username && w.readyState === WebSocket.OPEN) return true;
  return false;
}

// ---------------- Messages / files ----------------
function removeMessageFiles(m) {
  try {
    if (!m.fileInfo || !m.fileInfo.url) return;
    const p = path.join(UPLOADS_DIR, path.basename(String(m.fileInfo.url)));
    if (p.startsWith(UPLOADS_DIR + path.sep)) fs.unlinkSync(p);
  } catch (e) {}
}

function recipientsOf(m) {
  if (m.groupId) return groups[m.groupId] ? groups[m.groupId].members.slice() : [];
  return [m.sender, m.receiver].filter(Boolean);
}

// ---------- "Delete for me" support: messages keep a hiddenFor list ----------
function publicMsg(m) {
  const { hiddenFor, ...rest } = m; // never expose who hid a message
  return rest;
}
function isHiddenFor(m, username) {
  return Array.isArray(m.hiddenFor) && m.hiddenFor.includes(username);
}
// Hides the message for one user. Returns true when everybody has hidden it
// (the caller then removes it from storage; its file is deleted here).
function markHidden(m, username) {
  m.hiddenFor = m.hiddenFor || [];
  if (!m.hiddenFor.includes(username)) m.hiddenFor.push(username);
  const recipients = recipientsOf(m);
  if (recipients.length && recipients.every(u => m.hiddenFor.includes(u))) {
    removeMessageFiles(m);
    return true;
  }
  return false;
}

function unsendMessageById(sender, msgId) {
  const idx = messages.findIndex(m => m.id === msgId && m.sender === sender);
  if (idx === -1) return false;
  const [target] = messages.splice(idx, 1);
  removeMessageFiles(target);
  saveMessages();
  sendTo(recipientsOf(target).concat(sender), { type: 'message_unsent', messageId: msgId });
  return true;
}

// ---------------- Voice calls (signaling only; audio is peer-to-peer WebRTC) ----------------
const MAX_CALL_PARTICIPANTS = 6; // full-mesh WebRTC: keep it small
const RING_TIMEOUT_MS = 45 * 1000;
const calls = new Map(); // callId -> { id, type:'dm'|'group', groupId, participants:Set, invited:Set, sockets:Map, ringTimer }

function userCall(username) {
  for (const c of calls.values()) if (c.participants.has(username)) return c;
  return null;
}

function findGroupCall(groupId) {
  for (const c of calls.values()) if (c.groupId === groupId) return c;
  return null;
}

function endCall(call, reason) {
  clearTimeout(call.ringTimer);
  calls.delete(call.id);
  sendTo([...call.participants, ...call.invited], { type: 'call_ended', callId: call.id, reason });
}

function joinCall(call, username, ws) {
  const peers = [...call.participants];
  call.participants.add(username);
  call.invited.delete(username);
  call.sockets.set(username, ws);
  if (call.type === 'dm') clearTimeout(call.ringTimer);
  sendTo([username], { type: 'call_dismiss', callId: call.id }); // stop ringing on this user's other tabs/devices
  sendTo(peers, { type: 'call_peer_joined', callId: call.id, username });
  ws.send(JSON.stringify({ type: 'call_joined', callId: call.id, peers, mode: call.type, groupId: call.groupId || null }));
}

function leaveCall(username) {
  const call = userCall(username);
  if (!call) return;
  call.participants.delete(username);
  call.sockets.delete(username);
  sendTo([...call.participants], { type: 'call_peer_left', callId: call.id, username });
  if (call.type === 'dm' || call.participants.size === 0) {
    endCall(call, call.type === 'dm' ? 'hangup' : 'ended');
  }
}

function handleCallMessage(ws, sender, msg) {
  const fail = text => ws.send(JSON.stringify({ type: 'call_error', message: text }));

  if (msg.type === 'call_start') {
    if (userCall(sender)) return fail('You are already in a call');

    if (msg.groupId) {
      const g = groups[msg.groupId];
      if (!g || !g.members.includes(sender)) return fail('You are not a member of this group');
      const existing = findGroupCall(g.id);
      if (existing) {
        if (existing.participants.size >= MAX_CALL_PARTICIPANTS) return fail('This call is full');
        return joinCall(existing, sender, ws); // a call is already running: join it
      }
      const invited = g.members.filter(n => n !== sender && isUserOnline(n) && !userCall(n));
      const call = {
        id: crypto.randomUUID(),
        type: 'group',
        groupId: g.id,
        participants: new Set([sender]),
        invited: new Set(invited),
        sockets: new Map([[sender, ws]]),
        ringTimer: null
      };
      calls.set(call.id, call);
      call.ringTimer = setTimeout(() => {
        const c = calls.get(call.id);
        if (c && c.participants.size === 1) endCall(c, 'no_answer'); // nobody joined: stop everyone's ringing
      }, RING_TIMEOUT_MS);
      ws.send(JSON.stringify({ type: 'call_started', callId: call.id, mode: 'group', groupId: g.id }));
      sendTo(invited, { type: 'call_incoming', callId: call.id, from: sender, mode: 'group', groupId: g.id, groupName: g.name });
      return;
    }

    const to = typeof msg.to === 'string' ? msg.to.trim().toLowerCase() : '';
    const r = users[to];
    if (!r || !r.emailVerified || r.banned || to === sender) return fail('Invalid user');
    if (isBlocked(to, sender)) return fail('You cannot call this user');
    if (isBlocked(sender, to)) return fail('You blocked this user. Unblock them first');
    if (!isUserOnline(to)) return fail('User is offline');
    if (userCall(to)) return ws.send(JSON.stringify({ type: 'call_busy' }));

    const call = {
      id: crypto.randomUUID(),
      type: 'dm',
      groupId: null,
      participants: new Set([sender]),
      invited: new Set([to]),
      sockets: new Map([[sender, ws]]),
      ringTimer: null
    };
    call.ringTimer = setTimeout(() => {
      const c = calls.get(call.id);
      if (c && c.participants.size === 1) endCall(c, 'no_answer');
    }, RING_TIMEOUT_MS);
    calls.set(call.id, call);
    ws.send(JSON.stringify({ type: 'call_started', callId: call.id, mode: 'dm' }));
    sendTo([to], { type: 'call_incoming', callId: call.id, from: sender, mode: 'dm' });
  } else if (msg.type === 'call_accept') {
    const call = calls.get(msg.callId);
    if (!call) return fail('This call has ended');
    if (userCall(sender)) return fail('You are already in a call');
    const g = call.groupId ? groups[call.groupId] : null;
    const allowed = call.invited.has(sender) || (g && g.members.includes(sender));
    if (!allowed) return fail('You are not allowed to join this call');
    if (call.participants.size >= MAX_CALL_PARTICIPANTS) return fail('This call is full');
    joinCall(call, sender, ws);
  } else if (msg.type === 'call_decline') {
    const call = calls.get(msg.callId);
    if (!call) return;
    sendTo([sender], { type: 'call_dismiss', callId: call.id });
    if (call.type === 'dm' && call.invited.has(sender)) endCall(call, 'declined');
    else call.invited.delete(sender);
  } else if (msg.type === 'call_leave') {
    const call = userCall(sender);
    if (call && call.id === msg.callId) leaveCall(sender);
  } else if (msg.type === 'call_signal') {
    const call = calls.get(msg.callId);
    if (!call || !call.participants.has(sender)) return;
    if (typeof msg.to !== 'string' || !call.participants.has(msg.to)) return;
    if (JSON.stringify(msg.data || {}).length > 100000) return;
    sendTo([msg.to], { type: 'call_signal', callId: call.id, from: sender, data: msg.data });
  }
}

// ---------------- Profile photo helpers ----------------
function removeAvatarFile(u) {
  try {
    if (!u || !u.avatar) return;
    const p = path.join(UPLOADS_DIR, path.basename(String(u.avatar)));
    if (p.startsWith(UPLOADS_DIR + path.sep)) fs.unlinkSync(p);
  } catch (e) {}
}

// ---------------- Account destruction ----------------
function destroyAccount(username) {
  const u = users[username];
  if (!u) return false;
  removeAvatarFile(u);

  // 1) remove every message involving the user and tell everyone to unsend it
  const removed = messages.filter(m => m.sender === username || m.receiver === username);
  for (const m of removed) {
    sendTo(recipientsOf(m).filter(n => n !== username), { type: 'message_unsent', messageId: m.id });
    removeMessageFiles(m);
  }
  messages = messages.filter(m => !(m.sender === username || m.receiver === username));

  // 2) leave all groups
  for (const g of Object.values(groups)) {
    if (!g.members.includes(username)) continue;
    g.members = g.members.filter(n => n !== username);
    if (!g.members.length) {
      messages.filter(m => m.groupId === g.id).forEach(removeMessageFiles);
      messages = messages.filter(m => m.groupId !== g.id);
      delete groups[g.id];
    } else {
      if (g.owner === username) g.owner = g.members[0];
      sendTo(g.members, { type: 'groups_changed' });
    }
  }

  // 3) clean references in other users
  for (const other of Object.values(users)) {
    if (other.blocked) other.blocked = other.blocked.filter(n => n !== username);
    if (other.notifications) other.notifications = other.notifications.filter(n => n.from !== username);
  }

  // 4) remove the user, sessions and live connections
  delete users[username];
  dropSessions(username);
  for (const [w, n] of clients.entries()) {
    if (n === username) {
      clients.delete(w);
      try { w.close(); } catch (e) {}
    }
  }

  saveUsers();
  saveMessages();
  saveGroups();
  broadcastAll({ type: 'user_removed', username });
  console.log(`[ADMIN] 🗑️ Account fully deleted: ${username}`);
  return true;
}

// ---------------- Rename a user everywhere ----------------
function renameUser(oldName, newName) {
  const u = users[oldName];
  u.username = newName;
  users[newName] = u;
  delete users[oldName];
  const swap = n => (n === oldName ? newName : n);

  messages.forEach(m => {
    if (m.sender === oldName) m.sender = newName;
    if (m.receiver === oldName) m.receiver = newName;
    if (Array.isArray(m.hiddenFor)) m.hiddenFor = m.hiddenFor.map(swap);
  });
  Object.values(groups).forEach(g => {
    g.members = g.members.map(swap);
    if (g.owner === oldName) g.owner = newName;
  });
  Object.values(users).forEach(o => {
    if (o.blocked) o.blocked = o.blocked.map(swap);
    (o.notifications || []).forEach(n => { if (n.from === oldName) n.from = newName; });
  });
  reports.forEach(r => {
    if (r.reporter === oldName) r.reporter = newName;
    if (r.reported === oldName) r.reported = newName;
    (r.evidence || []).forEach(e => { if (e.sender === oldName) e.sender = newName; });
  });
  for (const s of sessions.values()) if (s.username === oldName) s.username = newName;
  for (const [w, n] of clients.entries()) if (n === oldName) clients.set(w, newName);

  saveUsers();
  saveMessages();
  saveGroups();
  saveReports();
  broadcastAll({ type: 'user_renamed', oldUsername: oldName, username: newName });
  console.log(`[USER] ✏️ ${oldName} is now ${newName}`);
}

// ---------------- Admin bootstrap ----------------
function ensureAdmin() {
  let admin = users[ADMIN_USERNAME];
  if (admin && !admin.isAdmin) {
    destroyAccount(ADMIN_USERNAME); // an old normal user took the reserved name
    admin = null;
  }
  const { salt, hash } = createPasswordRecord(ADMIN_PASSWORD);
  if (!admin) {
    users[ADMIN_USERNAME] = {
      id: crypto.randomUUID(),
      username: ADMIN_USERNAME,
      email: ADMIN_EMAIL,
      salt,
      passwordHash: hash,
      verified: true,
      emailVerified: true,
      isAdmin: true,
      blocked: [],
      notifications: [],
      avatar: '',
      createdAt: Date.now()
    };
  } else {
    // password is re-applied on every start so it always matches ADMIN_PASSWORD
    admin.salt = salt;
    admin.passwordHash = hash;
    admin.email = ADMIN_EMAIL;
    admin.banned = false;
    delete admin.adminChallenge;
  }
  saveUsers();
}

// ---------------- Email ----------------
const transporter = nodemailer
  ? nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465,
      auth: { user: EMAIL_USER, pass: EMAIL_PASS }
    })
  : null;

if (transporter) {
  transporter
    .verify()
    .then(() => console.log('[EMAIL] ✅ Gmail SMTP connection OK'))
    .catch(err => console.error('[EMAIL] ❌ SMTP login failed:', err.message));
}

async function sendVerificationEmail(toEmail, code, username, subjectTitle = 'Verification code') {
  console.log('\n======================================================');
  console.log(`[AUTH] 🔑 ${subjectTitle} for user (${username}): ${code}`);
  console.log(`[AUTH] 📧 Target email: ${toEmail}`);
  console.log('======================================================\n');

  if (!toEmail || !toEmail.includes('@') || !transporter) return false;

  const safeUser = escapeHtmlServer(username);
  const safeTitle = escapeHtmlServer(subjectTitle);

  try {
    const info = await transporter.sendMail({
      from: `"Vaulta Messenger" <${EMAIL_USER}>`,
      to: toEmail,
      subject: `Vaulta - ${subjectTitle}: ${code}`,
      text: `${subjectTitle}: ${code} (valid for 15 minutes)`,
      html: `
        <div style="direction: ltr; font-family: Tahoma, Arial, sans-serif; background: #4c1d95; padding: 25px;">
          <div style="max-width: 480px; margin: 0 auto; background: #ece9d8; border: 3px solid #7c3aed; border-radius: 6px; padding: 24px; text-align: center; color: #1e293b;">
            <div style="background: linear-gradient(90deg, #7c3aed, #a78bfa); color: white; padding: 10px; font-weight: bold; font-size: 16px; border-radius: 4px; margin-bottom: 16px;">
              ⚡ Vaulta Messenger
            </div>
            <p style="font-size: 14px; margin-bottom: 8px;">Hello <b>${safeUser}</b>,</p>
            <p style="font-size: 13px; color: #475569;">${safeTitle} for your account:</p>
            <div style="background: #ffffff; border: 2px solid #7c3aed; color: #7c3aed; font-size: 32px; font-weight: bold; letter-spacing: 8px; padding: 12px 20px; border-radius: 6px; margin: 16px auto; display: inline-block;">
              ${code}
            </div>
            <p style="font-size: 12px; color: #64748b; margin-top: 10px;">This code is valid for 15 minutes.</p>
          </div>
        </div>
      `
    });
    console.log(`[EMAIL] ✅ Email sent successfully to: ${toEmail} (ID: ${info.messageId})`);
    return true;
  } catch (err) {
    console.error('[EMAIL] ❌ Failed to send email:', err.message);
    return false;
  }
}

// ---------------- App setup ----------------
const app = express();
app.set('trust proxy', 1); // behind the ngrok HTTPS tunnel
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));
app.use('/uploads', express.static(UPLOADS_DIR));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// profile photos: images only, max 3 MB
const AVATAR_EXT = ['.png', '.jpg', '.jpeg', '.gif', '.webp'];
const avatarUpload = multer({
  storage,
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (req, file, cb) =>
    cb(null, AVATAR_EXT.includes(path.extname(file.originalname).toLowerCase()) && /^image\//.test(file.mimetype))
});

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - please sign in' });
  }
  const token = authHeader.split(' ')[1];
  const username = verifyToken(token);
  if (!username || !users[username] || users[username].banned) {
    return res.status(401).json({ error: 'Session expired, please sign in again' });
  }
  req.user = users[username];
  req.token = token;
  next();
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admins only' });
    next();
  });
}

// ====================== AUTH ROUTES ======================

app.post('/api/auth/register', async (req, res) => {
  const { username, password, email } = req.body || {};
  if (!username || !password || !email) {
    return res.status(400).json({ error: 'Username, email and password are required' });
  }
  const cleanUser = String(username).trim().toLowerCase();
  const cleanEmail = String(email).trim().toLowerCase();

  if (!/^[a-z0-9_]{3,20}$/.test(cleanUser)) {
    return res.status(400).json({ error: 'Username must be 3-20 characters: English letters, numbers or _' });
  }
  if (RESERVED_NAMES.includes(cleanUser)) return res.status(400).json({ error: 'This name is reserved' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  if (String(password).length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  if (users[cleanUser]) return res.status(400).json({ error: 'Username is already taken' });
  if (Object.values(users).some(u => u.email === cleanEmail)) {
    return res.status(400).json({ error: 'Email is already registered' });
  }

  const { salt, hash } = createPasswordRecord(String(password));
  const code = generate6DigitCode();

  users[cleanUser] = {
    id: crypto.randomUUID(),
    username: cleanUser,
    email: cleanEmail,
    salt,
    passwordHash: hash,
    verified: false,
    emailVerified: false,
    verificationCode: newChallenge(code),
    blocked: [],
    notifications: [],
    avatar: '',
    createdAt: Date.now()
  };
  saveUsers();

  const sent = await sendVerificationEmail(cleanEmail, code, cleanUser, 'Account activation code');
  res.json({
    success: true,
    requireVerification: true,
    emailSent: sent,
    message: sent
      ? 'Account created! A verification code was sent to your email.'
      : 'Account created but the email could not be sent. Click "Resend code".',
    username: cleanUser,
    email: cleanEmail
  });
});

app.post('/api/auth/verify-email', (req, res) => {
  const { username, code } = req.body || {};
  const user = users[String(username || '').trim().toLowerCase()];
  if (!user || !user.verificationCode) return res.status(400).json({ error: 'No active activation request' });

  const result = checkChallenge(user.verificationCode, code);
  if (!result.ok) {
    if (result.expired || result.locked) delete user.verificationCode;
    saveUsers();
    return res.status(400).json({ error: result.error });
  }

  user.verified = true;
  user.emailVerified = true;
  delete user.verificationCode;
  saveUsers();
  broadcastAll({ type: 'user_status_update', username: user.username, online: false });
  res.json({ token: generateToken(user.username), user: publicUser(user) });
});

const lastResend = new Map();
app.post('/api/auth/resend-code', async (req, res) => {
  const user = users[String((req.body || {}).username || '').trim().toLowerCase()];
  if (!user || user.emailVerified) return res.status(400).json({ error: 'No account needs activation' });
  const last = lastResend.get(user.username) || 0;
  if (Date.now() - last < 60 * 1000) return res.status(429).json({ error: 'Wait a minute before requesting a new code' });
  lastResend.set(user.username, Date.now());

  const code = generate6DigitCode();
  user.verificationCode = newChallenge(code);
  saveUsers();
  const sent = await sendVerificationEmail(user.email, code, user.username, 'Account activation code');
  res.json({ success: true, emailSent: sent, message: sent ? 'A new code was sent to your email.' : 'Could not send the email.' });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password, email } = req.body || {};
  const identifier = String(username || email || '').trim().toLowerCase();
  if (!identifier || !password) {
    return res.status(400).json({ error: 'Please enter your username or email and password' });
  }
  if (lockedOut(identifier)) {
    return res.status(429).json({ error: 'Too many attempts. Wait 5 minutes and try again' });
  }

  const user = findUserByIdentifier(identifier);
  if (!user || !verifyPassword(password, user)) {
    console.log(`[AUTH] ❌ Login failed (${identifier}): ${!user ? 'user not found' : 'wrong password'}`);
    addFail(identifier);
    return res.status(401).json({ error: 'Invalid login credentials' });
  }
  fails.delete(identifier);

  if (user.banned) return res.status(403).json({ error: 'This account has been banned by the administration' });

  if (!user.emailVerified && !user.verified) {
    const code = generate6DigitCode();
    user.verificationCode = newChallenge(code);
    saveUsers();
    const sent = await sendVerificationEmail(user.email, code, user.username, 'Account activation code');
    return res.status(403).json({
      requireSignupVerification: true,
      emailSent: sent,
      username: user.username,
      email: user.email,
      message: 'Please enter the 6-digit verification code to activate your account.'
    });
  }

  res.json({ success: true, token: generateToken(user.username), user: publicUser(user) });
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { identifier } = req.body || {};
  if (!identifier) return res.status(400).json({ error: 'Please enter your username or email' });

  const user = findUserByIdentifier(identifier);
  if (!user) return res.status(404).json({ error: 'No account found with this username or email' });
  if (user.isAdmin) return res.status(400).json({ error: 'The admin password is changed in the server settings (ADMIN_PASSWORD)' });

  const code = generate6DigitCode();
  user.loginChallenge = newChallenge(code);
  saveUsers();
  const sent = await sendVerificationEmail(user.email, code, user.username, 'Password reset code');
  res.json({
    success: true,
    emailSent: sent,
    message: sent ? 'A verification code was sent to your email.' : 'Could not send the email, please try again.',
    username: user.username
  });
});

app.post('/api/auth/reset-password', (req, res) => {
  const { username, code, newPassword } = req.body || {};
  if (!username || !code || !newPassword) return res.status(400).json({ error: 'All fields are required' });
  if (String(newPassword).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const user = findUserByIdentifier(username);
  if (!user || user.isAdmin || !user.loginChallenge) {
    return res.status(400).json({ error: 'No active password reset request' });
  }

  const result = checkChallenge(user.loginChallenge, code);
  if (!result.ok) {
    if (result.expired || result.locked) delete user.loginChallenge;
    saveUsers();
    return res.status(400).json({ error: result.error });
  }

  const { salt, hash } = createPasswordRecord(String(newPassword));
  user.salt = salt;
  user.passwordHash = hash;
  delete user.loginChallenge;
  saveUsers();
  dropSessions(user.username);
  res.json({ success: true, message: 'Password reset successfully! You can now sign in.' });
});

// ====================== USER ROUTES ======================

app.get('/api/user/me', requireAuth, (req, res) => res.json(publicUser(req.user)));

// --- change email (code is sent to the NEW email) ---
app.post('/api/user/change-email/request', requireAuth, async (req, res) => {
  const user = req.user;
  if (user.isAdmin) return res.status(400).json({ error: 'The admin email cannot be changed from here' });
  const { newEmail, password } = req.body || {};
  const clean = String(newEmail || '').trim().toLowerCase();
  if (!verifyPassword(password || '', user)) return res.status(401).json({ error: 'Incorrect password' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) return res.status(400).json({ error: 'Invalid email address' });
  if (clean === user.email) return res.status(400).json({ error: 'This is already your current email' });
  if (Object.values(users).some(u => u.email === clean)) return res.status(400).json({ error: 'Email is used by another account' });

  const code = generate6DigitCode();
  user.emailChange = { newEmail: clean, challenge: newChallenge(code) };
  saveUsers();
  const sent = await sendVerificationEmail(clean, code, user.username, 'New email confirmation code');
  res.json({ success: true, emailSent: sent, message: sent ? 'A code was sent to the new email.' : 'Could not send the email.' });
});

app.post('/api/user/change-email/confirm', requireAuth, (req, res) => {
  const user = req.user;
  if (!user.emailChange) return res.status(400).json({ error: 'No active email change request' });
  const result = checkChallenge(user.emailChange.challenge, (req.body || {}).code);
  if (!result.ok) {
    if (result.expired || result.locked) delete user.emailChange;
    saveUsers();
    return res.status(400).json({ error: result.error });
  }
  if (Object.values(users).some(u => u !== user && u.email === user.emailChange.newEmail)) {
    delete user.emailChange;
    saveUsers();
    return res.status(400).json({ error: 'Email is now used by another account' });
  }
  user.email = user.emailChange.newEmail;
  delete user.emailChange;
  saveUsers();
  res.json({ success: true, user: publicUser(user) });
});

// --- destroy account ---
app.post('/api/user/destroy', requireAuth, (req, res) => {
  const user = req.user;
  if (user.isAdmin) return res.status(400).json({ error: 'The admin account cannot be deleted' });
  if (!verifyPassword((req.body || {}).password || '', user)) {
    return res.status(401).json({ error: 'Incorrect password' });
  }
  destroyAccount(user.username);
  res.json({ success: true });
});

// --- change password ---
app.post('/api/user/change-password', requireAuth, (req, res) => {
  const user = req.user;
  if (user.isAdmin) return res.status(400).json({ error: 'The admin password is changed in the server settings (ADMIN_PASSWORD)' });
  const { currentPassword, newPassword } = req.body || {};
  if (!verifyPassword(currentPassword || '', user)) return res.status(401).json({ error: 'Incorrect current password' });
  if (String(newPassword || '').length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const { salt, hash } = createPasswordRecord(String(newPassword));
  user.salt = salt;
  user.passwordHash = hash;
  saveUsers();
  // sign out every other device, keep this one
  for (const [t, s] of sessions.entries()) if (s.username === user.username && t !== req.token) sessions.delete(t);
  res.json({ success: true });
});

// --- change username ---
app.post('/api/user/change-username', requireAuth, (req, res) => {
  const user = req.user;
  if (user.isAdmin) return res.status(400).json({ error: 'The admin username cannot be changed' });
  const { newUsername, password } = req.body || {};
  const clean = String(newUsername || '').trim().toLowerCase();
  if (!verifyPassword(password || '', user)) return res.status(401).json({ error: 'Incorrect password' });
  if (!/^[a-z0-9_]{3,20}$/.test(clean)) return res.status(400).json({ error: 'Username must be 3-20 characters: English letters, numbers or _' });
  if (RESERVED_NAMES.includes(clean)) return res.status(400).json({ error: 'This name is reserved' });
  if (clean === user.username) return res.status(400).json({ error: 'This is already your username' });
  if (users[clean]) return res.status(400).json({ error: 'Username is already taken' });
  if (userCall(user.username)) return res.status(400).json({ error: 'Finish your call first' });
  renameUser(user.username, clean);
  res.json({ success: true, user: publicUser(users[clean]) });
});

// --- profile photo ---
app.post('/api/user/avatar', requireAuth, (req, res) => {
  avatarUpload.single('file')(req, res, err => {
    if (err) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Image is too large (max 3 MB)' : 'Upload failed' });
    if (!req.file) return res.status(400).json({ error: 'Choose a PNG, JPG, GIF or WEBP image' });
    removeAvatarFile(req.user);
    req.user.avatar = '/uploads/' + req.file.filename;
    saveUsers();
    broadcastStatus(req.user.username, isUserOnline(req.user.username)); // makes everyone refresh contacts
    res.json({ success: true, user: publicUser(req.user) });
  });
});

app.post('/api/user/avatar/remove', requireAuth, (req, res) => {
  removeAvatarFile(req.user);
  req.user.avatar = '';
  saveUsers();
  broadcastStatus(req.user.username, isUserOnline(req.user.username));
  res.json({ success: true, user: publicUser(req.user) });
});

// --- contacts / blocking ---
app.get('/api/contacts', requireAuth, (req, res) => {
  const me = req.user;
  const list = Object.values(users)
    .filter(u => u.username !== me.username && u.emailVerified && !u.banned)
    .map(u => ({
      username: u.username,
      avatar: u.avatar,
      isAdmin: !!u.isAdmin,
      online: isUserOnline(u.username),
      blocked: (me.blocked || []).includes(u.username)
    }))
    .sort((a, b) => (b.isAdmin - a.isAdmin) || a.username.localeCompare(b.username));
  res.json({ contacts: list });
});

app.post('/api/block', requireAuth, (req, res) => {
  const target = String((req.body || {}).username || '').trim().toLowerCase();
  const t = users[target];
  if (!t || target === req.user.username) return res.status(400).json({ error: 'Invalid user' });
  if (t.isAdmin) return res.status(400).json({ error: 'Support cannot be blocked' });
  req.user.blocked = req.user.blocked || [];
  if (!req.user.blocked.includes(target)) req.user.blocked.push(target);
  saveUsers();
  res.json({ success: true });
});

app.post('/api/unblock', requireAuth, (req, res) => {
  const target = String((req.body || {}).username || '').trim().toLowerCase();
  req.user.blocked = (req.user.blocked || []).filter(n => n !== target);
  saveUsers();
  res.json({ success: true });
});

// --- report ---
app.post('/api/report', requireAuth, (req, res) => {
  const me = req.user.username;
  const target = String((req.body || {}).username || '').trim().toLowerCase();
  const reason = String((req.body || {}).reason || '').trim().slice(0, 500);
  const t = users[target];
  if (!t || target === me) return res.status(400).json({ error: 'Invalid user' });
  if (t.isAdmin) return res.status(400).json({ error: 'Support cannot be reported' });
  if (reason.length < 3) return res.status(400).json({ error: 'Please write a reason for the report' });
  if (reports.some(r => r.status === 'open' && r.reporter === me && r.reported === target)) {
    return res.status(400).json({ error: 'You already have an open report about this user' });
  }

  const evidence = messages
    .filter(m => !m.groupId && ((m.sender === me && m.receiver === target) || (m.sender === target && m.receiver === me)))
    .slice(-10)
    .map(m => ({ sender: m.sender, text: m.text || '[' + m.messageType + ']', timestamp: m.timestamp }));

  const report = {
    id: crypto.randomUUID(),
    reporter: me,
    reported: target,
    reason,
    evidence,
    status: 'open',
    createdAt: Date.now()
  };
  reports.push(report);
  saveReports();

  // also appears in the support chat, like a normal message to "support"
  const note = {
    id: crypto.randomUUID(),
    sender: me,
    receiver: ADMIN_USERNAME,
    messageType: 'text',
    text: '🚩 Report about @' + target + ': ' + reason,
    fileInfo: null,
    timestamp: Date.now()
  };
  messages.push(note);
  saveMessages();
  sendTo([me, ADMIN_USERNAME], { type: 'new_message', message: note });

  res.json({ success: true, message: 'Report sent to support. Thank you.' });
});

// --- messages ---
app.get('/api/messages/:otherUser', requireAuth, (req, res) => {
  const me = req.user.username;
  const other = req.params.otherUser.trim().toLowerCase();
  res.json({
    messages: messages
      .filter(m => !m.groupId && ((m.sender === me && m.receiver === other) || (m.sender === other && m.receiver === me)))
      .filter(m => !isHiddenFor(m, me))
      .map(publicMsg)
  });
});

// Delete for me: hides one message only on my side
app.post('/api/messages/:id/hide', requireAuth, (req, res) => {
  const me = req.user.username;
  const m = messages.find(x => x.id === req.params.id);
  const g = m && m.groupId ? groups[m.groupId] : null;
  const involved = m && (m.groupId ? g && g.members.includes(me) : m.sender === me || m.receiver === me);
  if (!involved) return res.status(404).json({ error: 'Message not found' });
  if (markHidden(m, me)) messages = messages.filter(x => x.id !== m.id);
  saveMessages();
  sendTo([me], { type: 'message_hidden', messageId: req.params.id });
  res.json({ success: true });
});

// Clear chat: hides every message of one chat only on my side
app.post('/api/chats/clear', requireAuth, (req, res) => {
  const me = req.user.username;
  const body = req.body || {};
  let list, chatType, chatId;
  if (body.groupId) {
    const g = groups[body.groupId];
    if (!g || !g.members.includes(me)) return res.status(404).json({ error: 'Group not found' });
    list = messages.filter(m => m.groupId === g.id);
    chatType = 'group';
    chatId = g.id;
  } else {
    const other = String(body.username || '').trim().toLowerCase();
    if (!other) return res.status(400).json({ error: 'Invalid user' });
    list = messages.filter(
      m => !m.groupId && ((m.sender === me && m.receiver === other) || (m.sender === other && m.receiver === me))
    );
    chatType = 'dm';
    chatId = other;
  }
  const gone = new Set();
  list.forEach(m => {
    if (markHidden(m, me)) gone.add(m.id);
  });
  if (gone.size) messages = messages.filter(m => !gone.has(m.id));
  saveMessages();
  sendTo([me], { type: 'chat_cleared', chatType, chatId });
  res.json({ success: true, cleared: list.length });
});

app.delete('/api/messages/:id', requireAuth, (req, res) => {
  if (!unsendMessageById(req.user.username, req.params.id)) return res.status(404).json({ error: 'Message not found' });
  res.json({ success: true, messageId: req.params.id });
});

app.post('/api/upload', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file selected' });
  res.json({
    url: `/uploads/${req.file.filename}`,
    fileName: req.file.originalname,
    fileSize: req.file.size,
    mimeType: req.file.mimetype
  });
});

// ====================== GROUPS & NOTIFICATIONS ======================

function inviteToGroup(g, inviter, target) {
  const t = users[target];
  if (!t || !t.emailVerified || t.banned || t.isAdmin || target === inviter) return 'invalid';
  if (g.members.includes(target)) return 'member';
  if (isBlocked(target, inviter) || isBlocked(inviter, target)) return 'blocked';
  t.notifications = t.notifications || [];
  if (t.notifications.some(n => n.type === 'group_invite' && n.groupId === g.id)) return 'pending';
  t.notifications.push({
    id: crypto.randomUUID(),
    type: 'group_invite',
    groupId: g.id,
    groupName: g.name,
    from: inviter,
    createdAt: Date.now()
  });
  sendTo([target], { type: 'notification' });
  return 'ok';
}

app.get('/api/groups', requireAuth, (req, res) => {
  const me = req.user.username;
  res.json({
    groups: Object.values(groups)
      .filter(g => g.members.includes(me))
      .map(g => ({ id: g.id, name: g.name, owner: g.owner, members: g.members }))
  });
});

app.post('/api/groups', requireAuth, (req, res) => {
  const me = req.user.username;
  const name = String((req.body || {}).name || '').trim().slice(0, 40);
  const invitees = Array.isArray((req.body || {}).members) ? req.body.members.slice(0, 30) : [];
  if (!name) return res.status(400).json({ error: 'Enter a group name' });

  const g = { id: crypto.randomUUID(), name, owner: me, members: [me], createdAt: Date.now() };
  groups[g.id] = g;
  let invited = 0;
  invitees.forEach(n => {
    if (inviteToGroup(g, me, String(n).trim().toLowerCase()) === 'ok') invited++;
  });
  saveGroups();
  saveUsers();
  res.json({ success: true, group: { id: g.id, name: g.name, owner: g.owner, members: g.members }, invited });
});

app.post('/api/groups/:id/invite', requireAuth, (req, res) => {
  const me = req.user.username;
  const g = groups[req.params.id];
  if (!g || !g.members.includes(me)) return res.status(404).json({ error: 'Group not found' });
  if (g.members.length >= 100) return res.status(400).json({ error: 'Group is full' });
  const r = inviteToGroup(g, me, String((req.body || {}).username || '').trim().toLowerCase());
  saveUsers();
  const msgs = {
    ok: 'Invitation sent.',
    member: 'User is already a member.',
    pending: 'Invitation already sent.',
    blocked: 'Could not send the invitation to this user.',
    invalid: 'Invalid user.'
  };
  res.status(r === 'ok' ? 200 : 400).json(r === 'ok' ? { success: true, message: msgs[r] } : { error: msgs[r] });
});

app.get('/api/groups/:id/messages', requireAuth, (req, res) => {
  const g = groups[req.params.id];
  if (!g || !g.members.includes(req.user.username)) return res.status(404).json({ error: 'Group not found' });
  res.json({ messages: messages.filter(m => m.groupId === g.id && !isHiddenFor(m, req.user.username)).map(publicMsg) });
});

app.post('/api/groups/:id/leave', requireAuth, (req, res) => {
  const me = req.user.username;
  const g = groups[req.params.id];
  if (!g || !g.members.includes(me)) return res.status(404).json({ error: 'Group not found' });
  const old = g.members.slice();
  g.members = g.members.filter(n => n !== me);
  if (!g.members.length) {
    messages.filter(m => m.groupId === g.id).forEach(removeMessageFiles);
    messages = messages.filter(m => m.groupId !== g.id);
    delete groups[g.id];
    saveMessages();
  } else if (g.owner === me) {
    g.owner = g.members[0];
  }
  saveGroups();
  sendTo(old, { type: 'groups_changed' });
  res.json({ success: true });
});

app.delete('/api/groups/:id', requireAuth, (req, res) => {
  const me = req.user.username;
  const g = groups[req.params.id];
  if (!g || g.owner !== me) return res.status(403).json({ error: 'Only the group owner can delete it' });
  messages.filter(m => m.groupId === g.id).forEach(removeMessageFiles);
  messages = messages.filter(m => m.groupId !== g.id);
  Object.values(users).forEach(u => {
    if (u.notifications) u.notifications = u.notifications.filter(n => n.groupId !== g.id);
  });
  const members = g.members.slice();
  delete groups[g.id];
  saveGroups();
  saveMessages();
  saveUsers();
  sendTo(members, { type: 'groups_changed' });
  res.json({ success: true });
});

app.get('/api/notifications', requireAuth, (req, res) => {
  res.json({ notifications: (req.user.notifications || []).slice().sort((a, b) => b.createdAt - a.createdAt) });
});

app.post('/api/notifications/:id/accept', requireAuth, (req, res) => {
  const me = req.user;
  const list = me.notifications || [];
  const n = list.find(x => x.id === req.params.id && x.type === 'group_invite');
  if (!n) return res.status(404).json({ error: 'Notification not found' });
  me.notifications = list.filter(x => x.id !== n.id);
  const g = groups[n.groupId];
  if (!g) {
    saveUsers();
    return res.status(404).json({ error: 'The group no longer exists' });
  }
  if (!g.members.includes(me.username)) g.members.push(me.username);
  saveUsers();
  saveGroups();
  sendTo(g.members, { type: 'groups_changed' });
  res.json({ success: true, groupId: g.id });
});

app.post('/api/notifications/:id/decline', requireAuth, (req, res) => {
  req.user.notifications = (req.user.notifications || []).filter(x => x.id !== req.params.id);
  saveUsers();
  res.json({ success: true });
});

// ====================== ADMIN ROUTES ======================

app.get('/api/admin/users', requireAdmin, (req, res) => {
  res.json({
    users: Object.values(users).map(u => ({
      username: u.username,
      email: u.email,
      emailVerified: !!u.emailVerified,
      banned: !!u.banned,
      isAdmin: !!u.isAdmin,
      online: isUserOnline(u.username),
      createdAt: u.createdAt
    }))
  });
});

app.delete('/api/admin/users/:username', requireAdmin, (req, res) => {
  const name = req.params.username.toLowerCase();
  if (!users[name]) return res.status(404).json({ error: 'User not found' });
  if (users[name].isAdmin) return res.status(400).json({ error: 'The admin account cannot be deleted' });
  destroyAccount(name);
  res.json({ success: true });
});

app.post('/api/admin/users/:username/ban', requireAdmin, (req, res) => {
  const name = req.params.username.toLowerCase();
  const u = users[name];
  if (!u) return res.status(404).json({ error: 'User not found' });
  if (u.isAdmin) return res.status(400).json({ error: 'The admin account cannot be banned' });
  u.banned = !u.banned;
  saveUsers();
  if (u.banned) {
    dropSessions(name);
    for (const [w, n] of clients.entries()) {
      if (n === name) {
        clients.delete(w);
        try { w.close(); } catch (e) {}
      }
    }
    broadcastAll({ type: 'user_status_update', username: name, online: false });
  }
  res.json({ success: true, banned: u.banned });
});

app.post('/api/admin/purge-unverified', requireAdmin, (req, res) => {
  const list = Object.values(users).filter(u => !u.isAdmin && !u.emailVerified).map(u => u.username);
  list.forEach(destroyAccount);
  res.json({ success: true, deleted: list.length });
});

app.post('/api/admin/purge-all', requireAdmin, (req, res) => {
  if ((req.body || {}).confirm !== 'DELETE') return res.status(400).json({ error: 'Type DELETE to confirm' });
  const list = Object.values(users).filter(u => !u.isAdmin).map(u => u.username);
  list.forEach(destroyAccount);
  res.json({ success: true, deleted: list.length });
});

app.get('/api/admin/reports', requireAdmin, (req, res) => {
  res.json({ reports: reports.slice().sort((a, b) => b.createdAt - a.createdAt) });
});

app.post('/api/admin/reports/:id', requireAdmin, (req, res) => {
  const r = reports.find(x => x.id === req.params.id);
  if (!r) return res.status(404).json({ error: 'Report not found' });
  const action = (req.body || {}).action;
  const target = users[r.reported];
  if (action === 'ban' && target && !target.isAdmin) {
    target.banned = true;
    dropSessions(target.username);
    for (const [w, n] of clients.entries()) {
      if (n === target.username) {
        clients.delete(w);
        try { w.close(); } catch (e) {}
      }
    }
    saveUsers();
  } else if (action === 'delete' && target && !target.isAdmin) {
    destroyAccount(target.username);
  } else if (action !== 'dismiss' && action !== 'ban' && action !== 'delete') {
    return res.status(400).json({ error: 'Invalid action' });
  }
  r.status = 'resolved';
  r.action = action;
  r.resolvedAt = Date.now();
  saveReports();
  res.json({ success: true });
});

// ---------------- ICE servers for calls ----------------
// STUN works for most networks. For strict NATs / mobile data add a TURN server:
//   TURN_URL="turn:your.server:3478" TURN_USER="user" TURN_PASS="pass"
const ICE_SERVERS = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }];
if (process.env.TURN_URL) {
  ICE_SERVERS.push({
    urls: process.env.TURN_URL.split(','),
    username: process.env.TURN_USER || '',
    credential: process.env.TURN_PASS || ''
  });
}
app.get('/api/ice', requireAuth, (req, res) => res.json({ iceServers: ICE_SERVERS }));

// ====================== WEBSOCKET ======================

wss.on('connection', ws => {
  ws.on('message', data => {
    try {
      const msg = JSON.parse(data.toString());

      if (msg.type === 'auth') {
        const username = verifyToken(msg.token);
        if (username && users[username] && !users[username].banned) {
          clients.set(ws, username);
          broadcastStatus(username, true);
        }
        return;
      }

      const sender = clients.get(ws);
      if (!sender || !users[sender]) return;
      const err = text => ws.send(JSON.stringify({ type: 'error', message: text }));

      if (msg.type === 'send_message') {
        const text = typeof msg.text === 'string' ? msg.text.slice(0, 5000) : '';
        let fileInfo = null;
        if (msg.fileInfo && typeof msg.fileInfo === 'object' && String(msg.fileInfo.url || '').startsWith('/uploads/')) {
          fileInfo = {
            url: String(msg.fileInfo.url),
            fileName: String(msg.fileInfo.fileName || 'file').slice(0, 200),
            fileSize: Number(msg.fileInfo.fileSize) || 0,
            mimeType: String(msg.fileInfo.mimeType || '').slice(0, 100)
          };
        }
        if (!text && !fileInfo) return;

        const newMsg = {
          id: crypto.randomUUID(),
          sender,
          messageType: ['text', 'image', 'file', 'voice'].includes(msg.messageType) ? msg.messageType : 'text',
          text,
          fileInfo,
          timestamp: Date.now()
        };
        let recipients;

        if (msg.groupId) {
          const g = groups[msg.groupId];
          if (!g || !g.members.includes(sender)) return err('You are not a member of this group');
          newMsg.groupId = g.id;
          newMsg.receiver = null;
          recipients = g.members;
        } else {
          if (typeof msg.to !== 'string') return;
          const receiver = msg.to.trim().toLowerCase();
          const r = users[receiver];
          if (!r || !r.emailVerified || r.banned || receiver === sender) return;
          if (isBlocked(receiver, sender)) return err('You cannot message this user');
          if (isBlocked(sender, receiver)) return err('You blocked this user. Unblock them first');
          newMsg.receiver = receiver;
          recipients = [sender, receiver];
        }

        messages.push(newMsg);
        saveMessages();
        sendTo(recipients, { type: 'new_message', message: newMsg });
      } else if (msg.type === 'unsend_message') {
        unsendMessageById(sender, msg.messageId);
      } else if (typeof msg.type === 'string' && msg.type.indexOf('call_') === 0) {
        handleCallMessage(ws, sender, msg);
      }
    } catch (e) {
      console.error('[WS] message error:', e.message);
    }
  });

  ws.on('close', () => {
    const username = clients.get(ws);
    if (username) {
      clients.delete(ws);
      const activeCall = userCall(username);
      if (activeCall && activeCall.sockets.get(username) === ws) leaveCall(username);
      if (!isUserOnline(username)) broadcastStatus(username, false);
    }
  });
});

function broadcastStatus(username, online) {
  broadcastAll({ type: 'user_status_update', username, online });
}

// ====================== WEB CLIENT ======================
app.use((req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(getEmbeddedClientHTML());
});

function getEmbeddedClientHTML() {
  return `<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <title>Vaulta Messenger</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Tahoma, Arial, sans-serif; }
    body { background: #4c1d95; height: 100vh; display: flex; flex-direction: column; overflow: hidden; color: #1e293b; }
    .xp-window { display: flex; flex-direction: column; height: 100vh; background: #ece9d8; border: 3px solid #7c3aed; }
    .xp-titlebar { background: linear-gradient(90deg, #7c3aed 0%, #a78bfa 100%); color: white; padding: 6px 12px; display: flex; align-items: center; justify-content: space-between; font-weight: bold; font-size: 13px; text-shadow: 1px 1px 1px #2e1065; gap: 6px; }
    .xp-main { display: flex; flex: 1; overflow: hidden; background: #fff; }
    .xp-sidebar { width: 280px; border-right: 2px solid #d4d0c8; background: #f7f6f0; display: flex; flex-direction: column; }
    .xp-chat-panel { flex: 1; display: flex; flex-direction: column; background: #ffffff; min-width: 0; }
    .xp-user-bar { padding: 10px; background: #ece9d8; border-bottom: 1px solid #d4d0c8; display: flex; align-items: center; gap: 10px; }
    .xp-avatar { width: 40px; height: 40px; border-radius: 50%; border: 2px solid #7c3aed; object-fit: cover; background: #7c3aed; display: flex; align-items: center; justify-content: center; font-weight: bold; color: #fff; flex-shrink: 0; overflow: hidden; }
    .xp-user-info { flex: 1; min-width: 0; }
    .xp-user-name { font-weight: bold; font-size: 14px; }
    .status-dot { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; display: inline-block; }
    .status-dot.offline { background: #94a3b8; }
    .xp-contacts-header { padding: 8px 12px; font-size: 12px; font-weight: bold; color: #475569; background: #e5e2d5; border-bottom: 1px solid #d4d0c8; display: flex; justify-content: space-between; align-items: center; }
    .xp-contacts-list { flex: 1; overflow-y: auto; }
    .xp-contact-item { display: flex; align-items: center; gap: 10px; padding: 10px; cursor: pointer; border-bottom: 1px solid #f0eee5; }
    .xp-contact-item:hover { background: #f5f3ff; }
    .xp-contact-item.active { background: #ede9fe; border-left: 4px solid #7c3aed; }
    .xp-chat-header { padding: 10px 14px; background: #f1f5f9; border-bottom: 1px solid #e2e8f0; display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; }
    .xp-messages-container { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 10px; background: #fafafa; }
    .xp-msg { max-width: 75%; padding: 8px 12px; border-radius: 8px; font-size: 13px; line-height: 1.4; word-break: break-word; position: relative; }
    .xp-msg.sent { align-self: flex-end; background: #dcf8c6; border: 1px solid #b2d89b; }
    .xp-msg.received { align-self: flex-start; background: #ffffff; border: 1px solid #e2e8f0; }
    .xp-msg audio { max-width: 100%; }
    .xp-msg-from { font-size: 11px; font-weight: bold; color: #7c3aed; margin-bottom: 2px; }
    .xp-msg-meta { font-size: 10px; color: #64748b; margin-top: 4px; text-align: left; display: flex; align-items: center; gap: 6px; }
    .xp-chat-input-bar { padding: 10px; background: #ece9d8; border-top: 1px solid #d4d0c8; display: flex; align-items: center; gap: 8px; }
    .xp-input { flex: 1; padding: 8px 12px; border: 2px solid #9f8bd1; border-radius: 4px; outline: none; font-size: 14px; }
    .xp-btn { background: #ece9d8; border: 2px outset #ffffff; padding: 6px 14px; font-size: 13px; cursor: pointer; font-weight: bold; border-radius: 3px; }
    .xp-btn-primary { background: #7c3aed; color: white; border-color: #a78bfa; }
    .xp-btn-danger { background: #dc2626; color: white; border-color: #f87171; }
    .xp-btn-sm { padding: 2px 8px; font-size: 11px; }
    .xp-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 100; }
    .xp-modal { width: 90%; max-width: 400px; background: #ece9d8; border: 3px solid #7c3aed; border-radius: 4px; }
    .xp-modal-body { padding: 20px; }
    .xp-form-group { margin-bottom: 12px; }
    .xp-form-group label { display: block; font-size: 12px; font-weight: bold; margin-bottom: 4px; }
    .xp-form-input { width: 100%; padding: 8px; border: 2px solid #9f8bd1; border-radius: 3px; font-size: 14px; }
    .xp-badge { background: #ef4444; color: #fff; border-radius: 10px; padding: 0 6px; font-size: 10px; margin-right: 4px; }
    .xp-table { width: 100%; border-collapse: collapse; font-size: 12px; background: #fff; }
    .xp-table th, .xp-table td { border: 1px solid #d4d0c8; padding: 4px 6px; text-align: left; }
    .xp-table th { background: #e5e2d5; }
    .xp-card { background: #fff; border: 1px solid #d4d0c8; border-radius: 4px; padding: 8px; margin-bottom: 8px; font-size: 12px; }
    .xp-sep { border-top: 1px solid #d4d0c8; margin: 14px 0; }
    .mobile-only { display: none; }

    /* ================= Mobile layout (desktop is unchanged) ================= */
    @media (max-width: 768px) {
      body, .xp-window { height: 100vh; height: 100dvh; }
      .xp-window { border-width: 0; }
      .xp-titlebar { padding: 8px 10px; padding-top: calc(8px + env(safe-area-inset-top)); font-size: 14px; }
      .lbl { display: none; }
      .mobile-only { display: inline-block; }

      /* one screen at a time: contacts list OR the chat */
      .xp-sidebar { width: 100%; border-right: none; }
      .xp-chat-panel { display: none; width: 100%; }
      body.show-chat .xp-sidebar { display: none; }
      body.show-chat .xp-chat-panel { display: flex; }

      .xp-btn { padding: 8px 12px; min-height: 38px; }
      .xp-btn-sm { padding: 6px 10px; font-size: 13px; min-height: 34px; }
      .xp-input, .xp-form-input { font-size: 16px; }

      .xp-user-bar { padding: 12px; }
      .xp-contact-item { padding: 12px 12px; }
      .xp-contacts-header { padding: 10px 12px; }

      .xp-chat-header { padding: 8px 10px; gap: 6px; }
      #activeChatName { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 55vw; }
      #chatActions { gap: 4px; }

      .xp-messages-container { padding: 10px; gap: 8px; -webkit-overflow-scrolling: touch; }
      .xp-msg { max-width: 88%; font-size: 14px; }
      .xp-msg img { max-width: 100%; height: auto; }
      .xp-msg-meta button { padding: 4px 2px !important; font-size: 12px !important; }

      .xp-chat-input-bar { padding: 8px; gap: 6px; padding-bottom: calc(8px + env(safe-area-inset-bottom)); }
      .xp-chat-input-bar .xp-btn { padding: 8px 10px; }
      .xp-input { padding: 10px 12px; min-width: 0; }

      /* dialogs & login: fit the screen and scroll */
      .xp-overlay { align-items: flex-start; overflow-y: auto; padding: 10px 0; }
      .xp-modal { width: 96%; max-width: 96% !important; margin: 0 auto; }
      .xp-modal-body { padding: 14px; }
      #dlgBody { max-height: calc(100dvh - 110px) !important; }
      .xp-table { font-size: 11px; }
      .xp-table th, .xp-table td { padding: 4px 4px; }
    }
  </style>
</head>
<body>
  <div class="xp-window">
    <div class="xp-titlebar">
      <div>⚡ Vaulta Messenger</div>
      <div style="display:flex; gap:6px; align-items:center;">
        <button class="xp-btn xp-btn-sm" id="btnNotif">🔔 <span id="notifBadge" class="xp-badge" style="display:none;">0</span></button>
        <button class="xp-btn xp-btn-sm" id="btnAdmin" style="display:none;">🛡️<span class="lbl"> Admin</span></button>
        <button class="xp-btn xp-btn-sm" id="btnSettings">⚙️<span class="lbl"> Settings</span></button>
        <button class="xp-btn xp-btn-sm" id="btnLogout">Logout</button>
      </div>
    </div>

    <div class="xp-main">
      <div class="xp-sidebar">
        <div class="xp-user-bar">
          <div id="myAvatarPlaceholder" class="xp-avatar">U</div>
          <div class="xp-user-info">
            <div id="myUsername" class="xp-user-name">...</div>
            <div style="font-size: 11px; color: #22c55e;"><span class="status-dot"></span> Online</div>
          </div>
        </div>
        <div class="xp-contacts-header">Contacts</div>
        <div class="xp-contacts-list" id="contactsList"></div>
        <div class="xp-contacts-header">
          <span>Groups</span>
          <button class="xp-btn xp-btn-sm" id="btnNewGroup">+ Group</button>
        </div>
        <div class="xp-contacts-list" id="groupsList" style="flex:none; max-height:32%;"></div>
      </div>

      <div class="xp-chat-panel">
        <div class="xp-chat-header">
          <div style="display:flex; align-items:center; gap:8px; min-width:0;">
            <button class="xp-btn xp-btn-sm mobile-only" id="btnBack">← Back</button>
            <div id="activeChatName" style="font-weight:bold; font-size:14px;">Select a chat to start</div>
          </div>
          <div id="chatActions" style="display:flex; gap:6px; flex-wrap:wrap;"></div>
        </div>
        <div class="xp-messages-container" id="messagesBox">
          <div style="text-align: center; color: #94a3b8; font-size: 13px; margin: auto;">Select a friend or group to start chatting</div>
        </div>
        <div class="xp-chat-input-bar">
          <input type="file" id="fileInput" style="display: none;" />
          <button class="xp-btn" id="btnAttach">📎<span class="lbl"> File/Image</span></button>
          <button class="xp-btn" id="btnVoice" title="Voice message">🎤</button>
          <button class="xp-btn xp-btn-danger" id="btnVoiceCancel" style="display:none;" title="Cancel">✕</button>
          <input type="text" class="xp-input" id="messageInput" dir="auto" placeholder="Type your message..." />
          <button class="xp-btn xp-btn-primary" id="btnSend">Send</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Generic dialog -->
  <div class="xp-overlay" id="dlg" style="display:none; z-index:90;">
    <div class="xp-modal" style="max-width:560px;">
      <div class="xp-titlebar"><span id="dlgTitle"></span><button class="xp-btn xp-btn-sm" id="dlgClose">✕</button></div>
      <div class="xp-modal-body" id="dlgBody" style="max-height:70vh; overflow:auto;"></div>
    </div>
  </div>

  <!-- Call screens -->
  <div class="xp-overlay" id="callOverlay" style="display:none; z-index:120;">
    <div class="xp-modal" style="max-width:360px;">
      <div class="xp-titlebar"><span id="callTitle">Call</span></div>
      <div class="xp-modal-body" style="text-align:center;">
        <div id="callStatus" style="font-size:14px; margin-bottom:6px;">Calling...</div>
        <div id="callTimer" style="font-size:24px; font-weight:bold; margin-bottom:10px;">00:00</div>
        <div id="callPeers" style="text-align:left; margin-bottom:14px;"></div>
        <div style="display:flex; gap:8px; justify-content:center;">
          <button class="xp-btn" id="btnCallMute">🎤 Mute</button>
          <button class="xp-btn xp-btn-danger" id="btnCallHang">📵 Hang up</button>
        </div>
      </div>
    </div>
  </div>
  <div class="xp-overlay" id="incomingOverlay" style="display:none; z-index:130;">
    <div class="xp-modal" style="max-width:340px;">
      <div class="xp-titlebar"><span>📞 Incoming call</span></div>
      <div class="xp-modal-body" style="text-align:center;">
        <div id="incomingText" style="font-size:15px; font-weight:bold; margin-bottom:14px;"></div>
        <div style="display:flex; gap:8px; justify-content:center;">
          <button class="xp-btn xp-btn-primary" id="btnAcceptCall">✅ Accept</button>
          <button class="xp-btn xp-btn-danger" id="btnDeclineCall">❌ Decline</button>
        </div>
      </div>
    </div>
  </div>
  <div id="callAudio" style="position:fixed; left:-9999px; top:0; width:1px; height:1px; overflow:hidden;"></div>

  <!-- Auth -->
  <div class="xp-overlay" id="authModal" style="display: flex;">
    <div class="xp-modal">
      <div class="xp-titlebar"><span>Sign in / New account · Vaulta</span></div>
      <div class="xp-modal-body">
        <div style="display: flex; gap: 8px; margin-bottom: 14px;">
          <button class="xp-btn xp-btn-primary" id="tabLogin" style="flex:1;">Sign in</button>
          <button class="xp-btn" id="tabRegister" style="flex:1;">New account</button>
        </div>

        <div id="authAlert" style="display: none; padding: 8px; margin-bottom: 12px; font-size: 12px; border-radius: 4px;"></div>

        <form id="mainAuthForm">
          <div class="xp-form-group">
            <label id="lblUsername">Username or email</label>
            <input type="text" class="xp-form-input" id="authUsername" required placeholder="Username or email" />
          </div>
          <div class="xp-form-group" id="groupEmail" style="display: none;">
            <label>Email</label>
            <input type="email" class="xp-form-input" id="authEmail" placeholder="name@example.com" />
          </div>
          <div class="xp-form-group">
            <label>Password</label>
            <input type="password" class="xp-form-input" id="authPassword" required placeholder="••••••" />
          </div>
          <div style="display: flex; justify-content: flex-end; margin-bottom: 8px;">
            <button type="button" id="btnGoForgot" style="background: none; border: none; color: #7c3aed; font-size: 11px; cursor: pointer; text-decoration: underline;">Forgot password?</button>
          </div>
          <button type="submit" class="xp-btn xp-btn-primary" id="authSubmitBtn" style="width: 100%; padding: 8px;">Sign in</button>
        </form>

        <div id="verifyScreen" style="display: none; text-align: center;">
          <h4 id="verifyTitle" style="margin-bottom: 6px; font-size: 14px;">Account activation code (6 digits)</h4>
          <p id="verifyHint" style="font-size: 12px; color: #64748b; margin-bottom: 12px;">A verification code was sent to your email</p>
          <input type="text" maxlength="6" inputmode="numeric" id="inputVerifyCode" class="xp-form-input" style="font-size: 24px; text-align: center; letter-spacing: 6px; font-weight: bold; width: 180px; margin: 0 auto 12px;" placeholder="000000" />
          <button class="xp-btn xp-btn-primary" id="btnSubmitCode" style="width: 100%; padding: 8px;">Confirm and sign in</button>
          <button class="xp-btn" id="btnResendCode" style="width: 100%; margin-top: 6px;">Resend code</button>
          <button class="xp-btn" id="btnCancelVerify" style="width: 100%; margin-top: 6px;">Cancel and go back</button>
        </div>

        <div id="forgotScreen" style="display: none;">
          <h4 style="margin-bottom: 6px; font-size: 14px; text-align: center;">Password recovery</h4>
          <p style="font-size: 12px; color: #64748b; margin-bottom: 12px; text-align: center;">Enter your registered username or email to receive a verification code</p>
          <div class="xp-form-group">
            <label>Username or email</label>
            <input type="text" class="xp-form-input" id="forgotIdentifier" placeholder="Username or email" />
          </div>
          <button class="xp-btn xp-btn-primary" id="btnSendForgotCode" style="width: 100%; padding: 8px;">Send verification code by email</button>
          <button class="xp-btn" id="btnCancelForgot" style="width: 100%; margin-top: 6px;">Back to sign in</button>
        </div>

        <div id="resetScreen" style="display: none;">
          <h4 style="margin-bottom: 6px; font-size: 14px; text-align: center;">Set new password</h4>
          <p style="font-size: 12px; color: #64748b; margin-bottom: 12px; text-align: center;">Enter the verification code (6 digits) and your new password</p>
          <div class="xp-form-group">
            <label>Verification code (6 digits)</label>
            <input type="text" maxlength="6" inputmode="numeric" id="resetCodeInput" class="xp-form-input" style="font-size: 20px; text-align: center; letter-spacing: 4px; font-weight: bold;" placeholder="000000" />
          </div>
          <div class="xp-form-group">
            <label>New password</label>
            <input type="password" id="resetNewPassInput" class="xp-form-input" placeholder="••••••" />
          </div>
          <button class="xp-btn xp-btn-primary" id="btnSubmitResetPass" style="width: 100%; padding: 8px;">Save and confirm</button>
          <button class="xp-btn" id="btnCancelReset" style="width: 100%; margin-top: 6px;">Cancel and go back</button>
        </div>
      </div>
    </div>
  </div>

  <script>
    var currentUser = null;
    var token = localStorage.getItem('vaulta_token') || '';
    var activeChat = null; // {type:'dm'|'group', id:string}
    var ws = null;
    var isRegisterMode = false;
    var pendingVerify = null; // {username, admin}
    var pendingResetUser = '';
    var contactsCache = [];
    var groupsCache = [];
    var blockedSet = {};

    // ---------- helpers ----------
    function escapeHtml(str) {
      return String(str == null ? '' : str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function safeUrl(u) { u = String(u || ''); return u.indexOf('/uploads/') === 0 ? u : ''; }

    function h(tag, props, kids) {
      var e = document.createElement(tag);
      props = props || {};
      for (var k in props) {
        if (k === 'text') e.textContent = props[k];
        else if (k === 'style') e.style.cssText = props[k];
        else if (k.slice(0, 2) === 'on') e[k] = props[k];
        else e.setAttribute(k, props[k]);
      }
      (kids || []).forEach(function (c) {
        if (c != null) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
      });
      return e;
    }

    // shows the profile photo inside an avatar circle (or the first letter)
    function paintAvatar(el, url, name) {
      el.innerHTML = '';
      var u = safeUrl(url);
      if (u) el.appendChild(h('img', { src: u, style: 'width:100%; height:100%; border-radius:50%; object-fit:cover;' }));
      else el.textContent = String(name || '?')[0].toUpperCase();
    }

    async function api(method, url, body) {
      var opt = { method: method, headers: { 'Authorization': 'Bearer ' + token } };
      if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
      var res = await fetch(url, opt);
      var data = await res.json().catch(function () { return {}; });
      if (res.status === 401 && token) { localStorage.removeItem('vaulta_token'); location.reload(); }
      if (!res.ok) throw new Error(data.error || 'An error occurred');
      return data;
    }

    async function postJSON(url, body) {
      var res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      var data = await res.json().catch(function () { return {}; });
      return { res: res, data: data };
    }

    function showAlert(msg, isErr) {
      var box = document.getElementById('authAlert');
      if (!msg) { box.style.display = 'none'; return; }
      box.style.display = 'block';
      box.style.background = isErr ? '#ffe4e6' : '#dcfce7';
      box.style.color = isErr ? '#9f1239' : '#166534';
      box.textContent = msg;
    }

    function setMsg(el, text, isErr) {
      el.textContent = text || '';
      el.style.color = isErr ? '#9f1239' : '#166534';
    }

    function openDlg(title, nodes) {
      document.getElementById('dlgTitle').textContent = title;
      var body = document.getElementById('dlgBody');
      body.innerHTML = '';
      nodes.forEach(function (n) { body.appendChild(n); });
      document.getElementById('dlg').style.display = 'flex';
    }
    function closeDlg() { document.getElementById('dlg').style.display = 'none'; }
    document.getElementById('dlgClose').onclick = closeDlg;

    // ---------- auto login ----------
    if (token) {
      fetch('/api/user/me', { headers: { 'Authorization': 'Bearer ' + token } })
        .then(function (r) { return r.ok ? r.json() : Promise.reject(); })
        .then(function (u) { currentUser = u; onLoginSuccess(); })
        .catch(function () {
          localStorage.removeItem('vaulta_token');
          token = '';
          document.getElementById('authModal').style.display = 'flex';
        });
    }

    // ---------- auth UI ----------
    document.getElementById('tabLogin').onclick = function () {
      isRegisterMode = false;
      document.getElementById('tabLogin').classList.add('xp-btn-primary');
      document.getElementById('tabRegister').classList.remove('xp-btn-primary');
      document.getElementById('groupEmail').style.display = 'none';
      document.getElementById('authSubmitBtn').textContent = 'Sign in';
      document.getElementById('btnGoForgot').style.display = 'inline-block';
      showAlert('', false);
    };
    document.getElementById('tabRegister').onclick = function () {
      isRegisterMode = true;
      document.getElementById('tabRegister').classList.add('xp-btn-primary');
      document.getElementById('tabLogin').classList.remove('xp-btn-primary');
      document.getElementById('groupEmail').style.display = 'block';
      document.getElementById('authSubmitBtn').textContent = 'Create account and activate';
      document.getElementById('btnGoForgot').style.display = 'none';
      showAlert('', false);
    };

    document.getElementById('btnGoForgot').onclick = function () {
      document.getElementById('mainAuthForm').style.display = 'none';
      document.getElementById('forgotScreen').style.display = 'block';
      showAlert('', false);
    };
    document.getElementById('btnCancelForgot').onclick = function () {
      document.getElementById('forgotScreen').style.display = 'none';
      document.getElementById('mainAuthForm').style.display = 'block';
      showAlert('', false);
    };
    document.getElementById('btnSendForgotCode').onclick = async function () {
      var idVal = document.getElementById('forgotIdentifier').value.trim();
      if (!idVal) return alert('Please enter your username or email');
      showAlert('Sending code...', false);
      try {
        var r = await postJSON('/api/auth/forgot-password', { identifier: idVal });
        if (!r.res.ok) throw new Error(r.data.error || 'An error occurred');
        pendingResetUser = r.data.username;
        document.getElementById('forgotScreen').style.display = 'none';
        document.getElementById('resetScreen').style.display = 'block';
        showAlert(r.data.message || 'Code sent', !r.data.emailSent);
      } catch (e) { showAlert(e.message, true); }
    };
    document.getElementById('btnCancelReset').onclick = function () {
      document.getElementById('resetScreen').style.display = 'none';
      document.getElementById('mainAuthForm').style.display = 'block';
      showAlert('', false);
    };
    document.getElementById('btnSubmitResetPass').onclick = async function () {
      var code = document.getElementById('resetCodeInput').value.trim();
      var newPassword = document.getElementById('resetNewPassInput').value;
      if (code.length !== 6) return alert('Please enter the 6-digit verification code');
      if (newPassword.length < 6) return alert('Password must be at least 6 characters');
      showAlert('Saving...', false);
      try {
        var r = await postJSON('/api/auth/reset-password', { username: pendingResetUser, code: code, newPassword: newPassword });
        if (!r.res.ok) throw new Error(r.data.error || 'An error occurred');
        document.getElementById('resetScreen').style.display = 'none';
        document.getElementById('mainAuthForm').style.display = 'block';
        showAlert('Password changed successfully! You can now sign in.', false);
      } catch (e) { showAlert(e.message, true); }
    };

    document.getElementById('mainAuthForm').onsubmit = async function (e) {
      e.preventDefault();
      var u = document.getElementById('authUsername').value.trim();
      var p = document.getElementById('authPassword').value;
      var em = document.getElementById('authEmail').value.trim();
      showAlert('', false);
      try {
        if (isRegisterMode) {
          var r = await postJSON('/api/auth/register', { username: u, email: em, password: p });
          if (!r.res.ok) throw new Error(r.data.error || 'An error occurred');
          showVerifyScreen(r.data.username || u, false);
          showAlert(r.data.message, !r.data.emailSent);
        } else {
          var r2 = await postJSON('/api/auth/login', { username: u, password: p });
          if (!r2.res.ok) {
            if (r2.data.requireAdminCode) {
              showVerifyScreen(r2.data.username || u, true);
              showAlert(r2.data.message, !r2.data.emailSent);
              return;
            }
            if (r2.data.requireSignupVerification) {
              showVerifyScreen(r2.data.username || u, false);
              showAlert(r2.data.message, !r2.data.emailSent);
              return;
            }
            throw new Error(r2.data.error || 'An error occurred');
          }
          finishLogin(r2.data);
        }
      } catch (err) { showAlert(err.message, true); }
    };

    function finishLogin(data) {
      token = data.token;
      localStorage.setItem('vaulta_token', token);
      currentUser = data.user;
      onLoginSuccess();
    }

    function showVerifyScreen(username, admin) {
      pendingVerify = { username: username, admin: admin };
      document.getElementById('mainAuthForm').style.display = 'none';
      document.getElementById('verifyScreen').style.display = 'block';
      document.getElementById('verifyTitle').textContent = admin ? 'Admin sign-in code (6 digits)' : 'Account activation code (6 digits)';
      document.getElementById('verifyHint').textContent = admin ? 'Code sent to the admin email' : 'A verification code was sent to your email';
      document.getElementById('btnResendCode').style.display = admin ? 'none' : 'block';
      document.getElementById('inputVerifyCode').value = '';
      document.getElementById('inputVerifyCode').focus();
    }

    document.getElementById('btnCancelVerify').onclick = function () {
      document.getElementById('verifyScreen').style.display = 'none';
      document.getElementById('mainAuthForm').style.display = 'block';
      pendingVerify = null;
      showAlert('', false);
    };
    document.getElementById('btnResendCode').onclick = async function () {
      if (!pendingVerify) return;
      try {
        var r = await postJSON('/api/auth/resend-code', { username: pendingVerify.username });
        if (!r.res.ok) throw new Error(r.data.error || 'An error occurred');
        showAlert(r.data.message, !r.data.emailSent);
      } catch (err) { showAlert(err.message, true); }
    };
    document.getElementById('btnSubmitCode').onclick = async function () {
      if (!pendingVerify) return;
      var code = document.getElementById('inputVerifyCode').value.trim();
      if (code.length !== 6) return alert('Please enter the 6-digit verification code');
      try {
        var url = pendingVerify.admin ? '/api/auth/verify-admin' : '/api/auth/verify-email';
        var r = await postJSON(url, { username: pendingVerify.username, code: code });
        if (!r.res.ok) throw new Error(r.data.error || 'An error occurred');
        finishLogin(r.data);
      } catch (err) { showAlert(err.message, true); }
    };

    // ---------- after login ----------
    function onLoginSuccess() {
      document.getElementById('authModal').style.display = 'none';
      document.getElementById('myUsername').textContent = currentUser.username + (currentUser.isAdmin ? ' 🛡️' : '');
      paintAvatar(document.getElementById('myAvatarPlaceholder'), currentUser.avatar, currentUser.username);
      document.getElementById('btnAdmin').style.display = currentUser.isAdmin ? 'inline-block' : 'none';
      initWebSocket();
      loadContacts();
      loadGroups();
      loadNotifBadge();
    }

    function initWebSocket() {
      var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(proto + '//' + location.host);
      ws.onopen = function () { ws.send(JSON.stringify({ type: 'auth', token: token })); };
      ws.onclose = function () { cleanupCall(); hideIncoming(); };
      ws.onmessage = function (event) {
        var data = JSON.parse(event.data);
        if (data.type === 'user_status_update') loadContacts();
        else if (data.type === 'new_message') { if (belongsToActive(data.message)) appendMessage(data.message); }
        else if (data.type === 'message_unsent') {
          var el = document.getElementById('msg-' + data.messageId);
          if (el) el.remove();
        }
        else if (data.type === 'message_hidden') removeMessageEl(data.messageId);
        else if (data.type === 'chat_cleared') {
          if (activeChat && activeChat.type === data.chatType && activeChat.id === data.chatId) document.getElementById('messagesBox').innerHTML = '';
        }
        else if (data.type === 'notification') loadNotifBadge();
        else if (data.type === 'groups_changed') loadGroups();
        else if (data.type === 'user_removed') {
          if (activeChat && activeChat.type === 'dm' && activeChat.id === data.username) resetChat();
          loadContacts();
        }
        else if (data.type === 'user_renamed') {
          if (currentUser && data.oldUsername === currentUser.username) currentUser.username = data.username;
          if (activeChat && activeChat.type === 'dm' && activeChat.id === data.oldUsername) activeChat.id = data.username;
          loadContacts(); loadGroups();
          if (activeChat) loadMessages();
        }
        else if (data.type === 'error') alert(data.message);
        else if (typeof data.type === 'string' && data.type.indexOf('call_') === 0) handleCallEvent(data);
      };
    }

    function belongsToActive(m) {
      if (!activeChat) return false;
      if (activeChat.type === 'group') return m.groupId === activeChat.id;
      return !m.groupId && (m.sender === activeChat.id || m.receiver === activeChat.id);
    }

    // ---------- contacts & groups ----------
    async function loadContacts() {
      try {
        var data = await api('GET', '/api/contacts');
        contactsCache = data.contacts || [];
        blockedSet = {};
        contactsCache.forEach(function (c) { if (c.blocked) blockedSet[c.username] = true; });
        var listEl = document.getElementById('contactsList');
        listEl.innerHTML = '';
        if (!contactsCache.length) {
          listEl.innerHTML = '<div style="padding:16px; text-align:center; color:#94a3b8; font-size:12px;">No other users yet.</div>';
        }
        contactsCache.forEach(function (c) {
          var active = activeChat && activeChat.type === 'dm' && activeChat.id === c.username;
          var item = h('div', { class: 'xp-contact-item' + (active ? ' active' : '') });
          var av = h('div', { class: 'xp-avatar', style: 'width:34px; height:34px; font-size:12px;' });
          paintAvatar(av, c.avatar, c.username);
          item.appendChild(av);
          var info = h('div', { style: 'flex:1; min-width:0;' });
          info.appendChild(h('div', { style: 'font-weight:bold; font-size:13px;', text: c.username + (c.isAdmin ? ' 🛡️' : '') + (c.blocked ? ' 🚫' : '') }));
          var st = h('div', { style: 'font-size:11px; color:#64748b;' });
          st.appendChild(h('span', { class: 'status-dot' + (c.online ? '' : ' offline') }));
          st.appendChild(document.createTextNode(' ' + (c.online ? 'Online' : 'Offline')));
          info.appendChild(st);
          item.appendChild(info);
          item.addEventListener('click', function () { selectDM(c.username); });
          listEl.appendChild(item);
        });
        renderChatHeader();
      } catch (e) {}
    }

    async function loadGroups() {
      try {
        var data = await api('GET', '/api/groups');
        groupsCache = data.groups || [];
        if (activeChat && activeChat.type === 'group' && !groupsCache.some(function (g) { return g.id === activeChat.id; })) resetChat();
        var listEl = document.getElementById('groupsList');
        listEl.innerHTML = '';
        if (!groupsCache.length) {
          listEl.innerHTML = '<div style="padding:10px; text-align:center; color:#94a3b8; font-size:12px;">No groups.</div>';
        }
        groupsCache.forEach(function (g) {
          var active = activeChat && activeChat.type === 'group' && activeChat.id === g.id;
          var item = h('div', { class: 'xp-contact-item' + (active ? ' active' : '') });
          item.appendChild(h('div', { class: 'xp-avatar', style: 'width:34px; height:34px; font-size:14px; border-radius:8px;', text: '👥' }));
          var info = h('div', { style: 'flex:1; min-width:0;' });
          info.appendChild(h('div', { style: 'font-weight:bold; font-size:13px;', text: g.name }));
          info.appendChild(h('div', { style: 'font-size:11px; color:#64748b;', text: g.members.length + ' members' }));
          item.appendChild(info);
          item.addEventListener('click', function () { selectGroup(g.id); });
          listEl.appendChild(item);
        });
        renderChatHeader();
      } catch (e) {}
    }

    function resetChat() {
      activeChat = null;
      closeChatView();
      document.getElementById('messagesBox').innerHTML = '<div style="text-align: center; color: #94a3b8; font-size: 13px; margin: auto;">Select a friend or group to start chatting</div>';
      renderChatHeader();
      loadContacts();
    }

    function selectDM(username) { activeChat = { type: 'dm', id: username }; openChatView(); loadContacts(); loadGroups(); loadMessages(); }
    function selectGroup(id) { activeChat = { type: 'group', id: id }; openChatView(); loadContacts(); loadGroups(); loadMessages(); }

    // ---------- mobile navigation (list <-> chat) ----------
    function isMobile() { return window.matchMedia('(max-width: 768px)').matches; }
    function openChatView() {
      if (!isMobile()) return;
      if (!document.body.classList.contains('show-chat')) {
        history.pushState({ chat: 1 }, '');
        document.body.classList.add('show-chat');
      }
    }
    function closeChatView() {
      if (document.body.classList.contains('show-chat')) {
        document.body.classList.remove('show-chat');
        if (history.state && history.state.chat) history.back();
      }
    }
    window.addEventListener('popstate', function () { document.body.classList.remove('show-chat'); });
    document.getElementById('btnBack').onclick = function () {
      activeChat = null;
      closeChatView();
      renderChatHeader();
      loadContacts();
      loadGroups();
    };

    function renderChatHeader() {
      var nameEl = document.getElementById('activeChatName');
      var actions = document.getElementById('chatActions');
      actions.innerHTML = '';
      if (!activeChat) { nameEl.textContent = 'Select a chat to start'; return; }

      if (activeChat.type === 'dm') {
        var c = contactsCache.filter(function (x) { return x.username === activeChat.id; })[0];
        nameEl.textContent = activeChat.id + (c && c.isAdmin ? ' 🛡️ (Support)' : '');
        actions.appendChild(h('button', { class: 'xp-btn xp-btn-sm', text: '🧹 Clear chat', onclick: function () { clearChat({ type: 'dm', id: activeChat.id }); } }));
        if (c && !c.blocked) {
          actions.appendChild(h('button', { class: 'xp-btn xp-btn-sm', text: '📞 Call', onclick: function () { startCall({ to: c.username }, c.username); } }));
        }
        if (c && !c.isAdmin) {
          actions.appendChild(h('button', {
            class: 'xp-btn xp-btn-sm', text: c.blocked ? '✅ Unblock' : '🚫 Block',
            onclick: async function () {
              try {
                if (c.blocked) await api('POST', '/api/unblock', { username: c.username });
                else { if (!confirm('Block ' + c.username + '?')) return; await api('POST', '/api/block', { username: c.username }); }
                loadContacts();
              } catch (e) { alert(e.message); }
            }
          }));
          actions.appendChild(h('button', { class: 'xp-btn xp-btn-sm', text: '🚩 Report', onclick: function () { openReport(c.username); } }));
        }
      } else {
        var g = groupsCache.filter(function (x) { return x.id === activeChat.id; })[0];
        if (!g) return;
        nameEl.textContent = '👥 ' + g.name + ' (' + g.members.length + ')';
        actions.appendChild(h('button', { class: 'xp-btn xp-btn-sm', text: '📞 Call', onclick: function () { startCall({ groupId: g.id }, g.name); } }));
        actions.appendChild(h('button', { class: 'xp-btn xp-btn-sm', text: '🧹 Clear chat', onclick: function () { clearChat({ type: 'group', id: g.id }); } }));
        actions.appendChild(h('button', { class: 'xp-btn xp-btn-sm', text: '👤 Members', onclick: function () { alert('Members: ' + g.members.join(', ') + '\\nOwner: ' + g.owner); } }));
        actions.appendChild(h('button', { class: 'xp-btn xp-btn-sm', text: '➕ Invite', onclick: function () { openInvite(g.id); } }));
        actions.appendChild(h('button', {
          class: 'xp-btn xp-btn-sm', text: '🚪 Leave',
          onclick: async function () {
            if (!confirm('Leave this group?')) return;
            try { await api('POST', '/api/groups/' + g.id + '/leave'); resetChat(); loadGroups(); } catch (e) { alert(e.message); }
          }
        }));
        if (g.owner === currentUser.username) {
          actions.appendChild(h('button', {
            class: 'xp-btn xp-btn-sm xp-btn-danger', text: '🗑️ Delete group',
            onclick: async function () {
              if (!confirm('The group and all its messages will be deleted for everyone. Are you sure?')) return;
              try { await api('DELETE', '/api/groups/' + g.id); resetChat(); loadGroups(); } catch (e) { alert(e.message); }
            }
          }));
        }
      }
    }

    // ---------- messages ----------
    async function loadMessages() {
      if (!activeChat) return;
      var box = document.getElementById('messagesBox');
      box.innerHTML = '';
      renderChatHeader();
      try {
        var url = activeChat.type === 'group'
          ? '/api/groups/' + encodeURIComponent(activeChat.id) + '/messages'
          : '/api/messages/' + encodeURIComponent(activeChat.id);
        var data = await api('GET', url);
        (data.messages || []).forEach(function (m) { appendMessage(m); });
      } catch (e) {}
    }

    function appendMessage(m) {
      var box = document.getElementById('messagesBox');
      if (document.getElementById('msg-' + m.id)) return;
      if (m.groupId && blockedSet[m.sender]) return;
      var isMe = m.sender === currentUser.username;
      var msgDiv = document.createElement('div');
      msgDiv.id = 'msg-' + m.id;
      msgDiv.className = 'xp-msg ' + (isMe ? 'sent' : 'received');

      var content = '';
      if (m.groupId && !isMe) content += '<div class="xp-msg-from">' + escapeHtml(m.sender) + '</div>';
      var url = m.fileInfo ? safeUrl(m.fileInfo.url) : '';
      if (m.messageType === 'image' && url) {
        content += '<img src="' + escapeHtml(url) + '" style="max-width:200px; border-radius:4px; cursor:pointer;" onclick="window.open(this.src)" />';
      } else if (m.messageType === 'file' && url) {
        content += '<a href="' + escapeHtml(url) + '" download="' + escapeHtml(m.fileInfo.fileName) + '" style="color:#7c3aed; font-weight:bold;">📁 ' + escapeHtml(m.fileInfo.fileName) + '</a>';
      }
      if (m.messageType === 'voice' && url) {
        content += '<audio controls preload="metadata" src="' + escapeHtml(url) + '" style="width:220px;"></audio>';
      }
      if (m.text) content += '<div dir="auto">' + escapeHtml(m.text) + '</div>';

      var time = new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      msgDiv.innerHTML = content + '<div class="xp-msg-meta"><span>' + time + '</span>' + (isMe ? '<span>✓</span>' : '') + '</div>';

      var btn = h('button', {
        text: '🗑️ Delete', title: 'Delete message',
        style: 'background:none; border:none; color:#64748b; font-size:11px; cursor:pointer; font-weight:bold; padding:0;'
      });
      btn.addEventListener('click', function () { openDeleteMenu(m, isMe); });
      msgDiv.querySelector('.xp-msg-meta').appendChild(btn);
      box.appendChild(msgDiv);
      box.scrollTop = box.scrollHeight;
    }

    function removeMessageEl(id) {
      var el = document.getElementById('msg-' + id);
      if (el) el.remove();
    }

    // WhatsApp style: Delete for me / Delete for everyone (own messages only)
    function openDeleteMenu(m, isMe) {
      var info = h('div', { style: 'font-size:12px; color:#64748b; margin-bottom:10px;', text: isMe
        ? 'Delete for me removes it only from your side. Delete for everyone removes it for all members of this chat.'
        : 'Delete for me removes it only from your side. The sender and others keep it.' });
      var items = [info];
      items.push(h('button', {
        class: 'xp-btn', style: 'width:100%; margin-bottom:6px;', text: '🗑️ Delete for me',
        onclick: async function () {
          try { await api('POST', '/api/messages/' + m.id + '/hide'); removeMessageEl(m.id); closeDlg(); }
          catch (e) { alert(e.message); }
        }
      }));
      if (isMe) {
        items.push(h('button', {
          class: 'xp-btn xp-btn-danger', style: 'width:100%; margin-bottom:6px;', text: '🗑️ Delete for everyone',
          onclick: function () { ws.send(JSON.stringify({ type: 'unsend_message', messageId: m.id })); closeDlg(); }
        }));
      }
      items.push(h('button', { class: 'xp-btn', style: 'width:100%;', text: 'Cancel', onclick: closeDlg }));
      openDlg('Delete message', items);
    }

    // Clear chat: only on my side, the other side keeps everything
    async function clearChat(chat) {
      if (!confirm('Clear this chat? Messages will be deleted only for you. Other people keep them.')) return;
      try {
        await api('POST', '/api/chats/clear', chat.type === 'group' ? { groupId: chat.id } : { username: chat.id });
        if (activeChat && activeChat.type === chat.type && activeChat.id === chat.id) {
          document.getElementById('messagesBox').innerHTML = '';
        }
      } catch (e) { alert(e.message); }
    }

    function unsendMessage(messageId) {
      if (!confirm('Unsend this message for everyone?')) return;
      ws.send(JSON.stringify({ type: 'unsend_message', messageId: messageId }));
    }

    function sendPayload(extra) {
      if (!activeChat) return;
      var p = { type: 'send_message' };
      if (activeChat.type === 'group') p.groupId = activeChat.id; else p.to = activeChat.id;
      for (var k in extra) p[k] = extra[k];
      ws.send(JSON.stringify(p));
    }

    document.getElementById('btnSend').onclick = sendMessage;
    document.getElementById('messageInput').onkeydown = function (e) { if (e.key === 'Enter') sendMessage(); };
    function sendMessage() {
      var input = document.getElementById('messageInput');
      var text = input.value.trim();
      if (!text || !activeChat) return;
      sendPayload({ messageType: 'text', text: text });
      input.value = '';
    }

    document.getElementById('btnAttach').onclick = function () { document.getElementById('fileInput').click(); };
    document.getElementById('fileInput').onchange = async function (e) {
      var file = e.target.files[0];
      if (!file || !activeChat) return;
      var fd = new FormData();
      fd.append('file', file);
      try {
        var res = await fetch('/api/upload', { method: 'POST', headers: { 'Authorization': 'Bearer ' + token }, body: fd });
        var d = await res.json();
        if (!res.ok) throw new Error(d.error || 'File upload failed');
        sendPayload({ messageType: file.type.indexOf('image/') === 0 ? 'image' : 'file', fileInfo: d });
      } catch (err) { alert(err.message); }
      e.target.value = '';
    };

    // ---------- notifications ----------
    async function loadNotifBadge() {
      try {
        var d = await api('GET', '/api/notifications');
        var n = (d.notifications || []).length;
        var b = document.getElementById('notifBadge');
        b.textContent = n;
        b.style.display = n ? 'inline' : 'none';
      } catch (e) {}
    }

    document.getElementById('btnNotif').onclick = async function () {
      var wrap = h('div');
      openDlg('🔔 Notifications', [wrap]);
      async function render() {
        wrap.innerHTML = '';
        try {
          var d = await api('GET', '/api/notifications');
          if (!d.notifications.length) wrap.appendChild(h('div', { text: 'No notifications.', style: 'color:#64748b; text-align:center;' }));
          d.notifications.forEach(function (n) {
            var card = h('div', { class: 'xp-card' });
            card.appendChild(h('div', { style: 'margin-bottom:6px;', text: '@' + n.from + ' invited you to join the group: ' + n.groupName }));
            var row = h('div', { style: 'display:flex; gap:6px;' });
            row.appendChild(h('button', {
              class: 'xp-btn xp-btn-primary xp-btn-sm', text: '✅ Accept',
              onclick: async function () {
                try { await api('POST', '/api/notifications/' + n.id + '/accept'); await loadGroups(); loadNotifBadge(); render(); } catch (e) { alert(e.message); render(); loadNotifBadge(); }
              }
            }));
            row.appendChild(h('button', {
              class: 'xp-btn xp-btn-sm', text: '❌ Decline',
              onclick: async function () {
                try { await api('POST', '/api/notifications/' + n.id + '/decline'); loadNotifBadge(); render(); } catch (e) { alert(e.message); }
              }
            }));
            card.appendChild(row);
            wrap.appendChild(card);
          });
        } catch (e) { wrap.appendChild(h('div', { text: e.message })); }
      }
      render();
    };

    // ---------- groups dialogs ----------
    document.getElementById('btnNewGroup').onclick = function () {
      var name = h('input', { type: 'text', class: 'xp-form-input', dir: 'auto', placeholder: 'Group name', maxlength: '40' });
      var list = h('div', { style: 'max-height:200px; overflow:auto; background:#fff; border:1px solid #d4d0c8; padding:6px; margin:8px 0;' });
      var boxes = [];
      contactsCache.filter(function (c) { return !c.isAdmin; }).forEach(function (c) {
        var cb = h('input', { type: 'checkbox' });
        cb.value = c.username;
        boxes.push(cb);
        list.appendChild(h('label', { style: 'display:block; font-size:13px; padding:2px 0;' }, [cb, ' ' + c.username]));
      });
      if (!boxes.length) list.appendChild(h('div', { text: 'No users to invite.', style: 'color:#64748b; font-size:12px;' }));
      var msg = h('div', { style: 'font-size:12px; margin-bottom:6px;' });
      var btn = h('button', {
        class: 'xp-btn xp-btn-primary', text: 'Create and send invitations', style: 'width:100%;',
        onclick: async function () {
          try {
            var members = boxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
            var r = await api('POST', '/api/groups', { name: name.value, members: members });
            closeDlg();
            await loadGroups();
            selectGroup(r.group.id);
          } catch (e) { setMsg(msg, e.message, true); }
        }
      });
      openDlg('👥 New group', [h('div', { text: 'Invited users will get a notification and can accept or decline.', style: 'font-size:12px; color:#64748b; margin-bottom:8px;' }), name, list, msg, btn]);
    };

    function openInvite(groupId) {
      var g = groupsCache.filter(function (x) { return x.id === groupId; })[0];
      var sel = h('select', { class: 'xp-form-input' });
      contactsCache.filter(function (c) { return !c.isAdmin && g.members.indexOf(c.username) === -1; }).forEach(function (c) {
        sel.appendChild(h('option', { value: c.username, text: c.username }));
      });
      var msg = h('div', { style: 'font-size:12px; margin:8px 0;' });
      var btn = h('button', {
        class: 'xp-btn xp-btn-primary', text: 'Send invitation', style: 'width:100%;',
        onclick: async function () {
          if (!sel.value) return;
          try { var r = await api('POST', '/api/groups/' + groupId + '/invite', { username: sel.value }); setMsg(msg, r.message, false); } catch (e) { setMsg(msg, e.message, true); }
        }
      });
      openDlg('➕ Invite to ' + g.name, [sel, msg, btn]);
    }

    // ---------- report ----------
    function openReport(username) {
      var ta = h('textarea', { class: 'xp-form-input', rows: '4', maxlength: '500', dir: 'auto', placeholder: 'Explain the reason for the report...' });
      var msg = h('div', { style: 'font-size:12px; margin:8px 0;' });
      var btn = h('button', {
        class: 'xp-btn xp-btn-danger', text: 'Send report to support', style: 'width:100%;',
        onclick: async function () {
          try { var r = await api('POST', '/api/report', { username: username, reason: ta.value }); setMsg(msg, r.message, false); btn.disabled = true; } catch (e) { setMsg(msg, e.message, true); }
        }
      });
      openDlg('🚩 Report @' + username, [h('div', { text: 'The support team will see your report and the last 10 messages between you.', style: 'font-size:12px; color:#64748b; margin-bottom:8px;' }), ta, msg, btn]);
    }

    // ---------- settings ----------
    document.getElementById('btnSettings').onclick = function () {
      if (currentUser.isAdmin) {
        openDlg('⚙️ Settings', [h('p', { text: 'Admin account: the password and email are changed from the server settings (ADMIN_PASSWORD / ADMIN_EMAIL).', style: 'font-size:13px;' })]);
        return;
      }
      var cur = h('div', { style: 'margin-bottom:10px; font-size:13px;' }, [h('b', { text: 'Current email: ' }), h('span', { text: currentUser.email })]);
      var newEmail = h('input', { type: 'email', class: 'xp-form-input', placeholder: 'New email' });
      var pass1 = h('input', { type: 'password', class: 'xp-form-input', placeholder: 'Current password', style: 'margin-top:6px;' });
      var code = h('input', { type: 'text', maxlength: '6', inputmode: 'numeric', class: 'xp-form-input', placeholder: 'Verification code (6 digits)', style: 'display:none; margin-top:6px; text-align:center; letter-spacing:4px;' });
      var msg1 = h('div', { style: 'font-size:12px; margin:6px 0;' });
      var btnConfirm = h('button', {
        class: 'xp-btn xp-btn-primary', text: 'Confirm code', style: 'display:none; width:100%; margin-top:6px;',
        onclick: async function () {
          try {
            var r = await api('POST', '/api/user/change-email/confirm', { code: code.value });
            currentUser = r.user;
            setMsg(msg1, 'Email changed successfully ✅', false);
            cur.lastChild.textContent = currentUser.email;
            code.style.display = 'none'; btnConfirm.style.display = 'none';
          } catch (e) { setMsg(msg1, e.message, true); }
        }
      });
      var btnReq = h('button', {
        class: 'xp-btn xp-btn-primary', text: 'Send code to the new email', style: 'width:100%; margin-top:6px;',
        onclick: async function () {
          try {
            var r = await api('POST', '/api/user/change-email/request', { newEmail: newEmail.value, password: pass1.value });
            setMsg(msg1, r.message, !r.emailSent);
            code.style.display = 'block'; btnConfirm.style.display = 'block';
          } catch (e) { setMsg(msg1, e.message, true); }
        }
      });

      var pass2 = h('input', { type: 'password', class: 'xp-form-input', placeholder: 'Password to confirm deletion' });
      var msg2 = h('div', { style: 'font-size:12px; margin:6px 0;' });
      var btnDestroy = h('button', {
        class: 'xp-btn xp-btn-danger', text: '💣 Delete account permanently', style: 'width:100%; margin-top:6px;',
        onclick: async function () {
          if (!confirm('Warning: your account and all your messages will be deleted (and unsent for everyone). This cannot be undone. Are you sure?')) return;
          try {
            await api('POST', '/api/user/destroy', { password: pass2.value });
            localStorage.removeItem('vaulta_token');
            alert('Your account has been deleted. You can create a new one at any time.');
            location.reload();
          } catch (e) { setMsg(msg2, e.message, true); }
        }
      });

      // ----- profile photo -----
      var avatarPrev = h('div', { class: 'xp-avatar', style: 'width:64px; height:64px; font-size:22px;' });
      paintAvatar(avatarPrev, currentUser.avatar, currentUser.username);
      var avatarFile = h('input', { type: 'file', accept: 'image/png,image/jpeg,image/gif,image/webp', style: 'display:none;' });
      var msgA = h('div', { style: 'font-size:12px; margin:6px 0;' });
      function refreshAvatars() {
        paintAvatar(avatarPrev, currentUser.avatar, currentUser.username);
        paintAvatar(document.getElementById('myAvatarPlaceholder'), currentUser.avatar, currentUser.username);
      }
      avatarFile.onchange = async function () {
        var f = avatarFile.files[0];
        if (!f) return;
        var fd = new FormData();
        fd.append('file', f);
        try {
          var res = await fetch('/api/user/avatar', { method: 'POST', headers: { 'Authorization': 'Bearer ' + token }, body: fd });
          var d = await res.json().catch(function () { return {}; });
          if (!res.ok) throw new Error(d.error || 'Upload failed');
          currentUser = d.user;
          refreshAvatars();
          setMsg(msgA, 'Photo updated ✅', false);
        } catch (e) { setMsg(msgA, e.message, true); }
        avatarFile.value = '';
      };
      var btnPhoto = h('button', { class: 'xp-btn xp-btn-sm', text: '📷 Change photo', onclick: function () { avatarFile.click(); } });
      var btnPhotoDel = h('button', {
        class: 'xp-btn xp-btn-sm', text: 'Remove', style: 'margin-left:6px;',
        onclick: async function () {
          try {
            var r = await api('POST', '/api/user/avatar/remove');
            currentUser = r.user;
            refreshAvatars();
            setMsg(msgA, 'Photo removed', false);
          } catch (e) { setMsg(msgA, e.message, true); }
        }
      });
      var photoRow = h('div', { style: 'display:flex; align-items:center; gap:10px;' }, [avatarPrev, h('div', {}, [btnPhoto, btnPhotoDel, avatarFile])]);

      // ----- change username -----
      var curName = h('div', { style: 'margin-bottom:8px; font-size:13px;' }, [h('b', { text: 'Current username: ' }), h('span', { text: currentUser.username })]);
      var newName = h('input', { type: 'text', class: 'xp-form-input', placeholder: 'New username (3-20: a-z, 0-9, _)', maxlength: '20' });
      var passU = h('input', { type: 'password', class: 'xp-form-input', placeholder: 'Current password', style: 'margin-top:6px;' });
      var msgU = h('div', { style: 'font-size:12px; margin:6px 0;' });
      var btnU = h('button', {
        class: 'xp-btn xp-btn-primary', text: 'Change username', style: 'width:100%;',
        onclick: async function () {
          try {
            var r = await api('POST', '/api/user/change-username', { newUsername: newName.value, password: passU.value });
            currentUser = r.user;
            document.getElementById('myUsername').textContent = currentUser.username;
            refreshAvatars();
            curName.lastChild.textContent = currentUser.username;
            setMsg(msgU, 'Username changed successfully ✅', false);
            newName.value = ''; passU.value = '';
            loadContacts(); loadGroups();
          } catch (e) { setMsg(msgU, e.message, true); }
        }
      });

      // ----- change password -----
      var oldP = h('input', { type: 'password', class: 'xp-form-input', placeholder: 'Current password' });
      var newP = h('input', { type: 'password', class: 'xp-form-input', placeholder: 'New password (at least 6 characters)', style: 'margin-top:6px;' });
      var msgP = h('div', { style: 'font-size:12px; margin:6px 0;' });
      var btnP = h('button', {
        class: 'xp-btn xp-btn-primary', text: 'Change password', style: 'width:100%;',
        onclick: async function () {
          try {
            await api('POST', '/api/user/change-password', { currentPassword: oldP.value, newPassword: newP.value });
            setMsg(msgP, 'Password changed successfully ✅ (other devices were signed out)', false);
            oldP.value = ''; newP.value = '';
          } catch (e) { setMsg(msgP, e.message, true); }
        }
      });

      openDlg('⚙️ Settings', [
        h('h4', { text: '🖼️ Profile photo', style: 'margin-bottom:8px;' }),
        photoRow, msgA,
        h('div', { class: 'xp-sep' }),
        h('h4', { text: '👤 Change username', style: 'margin-bottom:8px;' }),
        curName, newName, passU, msgU, btnU,
        h('div', { class: 'xp-sep' }),
        h('h4', { text: '🔑 Change password', style: 'margin-bottom:8px;' }),
        oldP, newP, msgP, btnP,
        h('div', { class: 'xp-sep' }),
        h('h4', { text: '✉️ Change email address', style: 'margin-bottom:8px;' }),
        cur, newEmail, pass1, code, msg1, btnReq, btnConfirm,
        h('div', { class: 'xp-sep' }),
        h('h4', { text: '⚠️ Delete account', style: 'margin-bottom:6px; color:#b91c1c;' }),
        h('p', { text: 'All your messages will be deleted and unsent for everyone, and your account will disappear. You can create a new account later.', style: 'font-size:12px; color:#475569; margin-bottom:8px;' }),
        pass2, msg2, btnDestroy
      ]);
    };

    // ---------- admin panel ----------
    document.getElementById('btnAdmin').onclick = function () {
      var body = h('div');
      openDlg('🛡️ Admin panel', [body]);
      var tab = 'users';

      function fmt(t) { return new Date(t).toLocaleString(); }

      async function renderUsers() {
        var d = await api('GET', '/api/admin/users');
        var bar = h('div', { style: 'display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px;' });
        bar.appendChild(h('button', {
          class: 'xp-btn xp-btn-sm', text: '🧹 Delete unverified accounts',
          onclick: async function () {
            if (!confirm('Delete all accounts that have not verified their email?')) return;
            try { var r = await api('POST', '/api/admin/purge-unverified'); alert('Deleted ' + r.deleted + ' account(s)'); render(); } catch (e) { alert(e.message); }
          }
        }));
        bar.appendChild(h('button', {
          class: 'xp-btn xp-btn-sm xp-btn-danger', text: '💣 Delete all users',
          onclick: async function () {
            var c = prompt('All users and their messages will be deleted. Type DELETE to confirm:');
            if (c !== 'DELETE') return;
            try { var r = await api('POST', '/api/admin/purge-all', { confirm: c }); alert('Deleted ' + r.deleted + ' account(s)'); render(); } catch (e) { alert(e.message); }
          }
        }));
        body.appendChild(bar);

        var table = h('table', { class: 'xp-table' });
        table.appendChild(h('tr', {}, ['User', 'Email', 'Status', 'Actions'].map(function (t) { return h('th', { text: t }); })));
        d.users.forEach(function (u) {
          var status = (u.isAdmin ? 'Admin ' : '') + (u.emailVerified ? 'Verified' : 'Unverified') + (u.banned ? ' • Banned' : '') + (u.online ? ' • Online' : '');
          var actions = h('td');
          if (!u.isAdmin) {
            actions.appendChild(h('button', {
              class: 'xp-btn xp-btn-sm', text: u.banned ? 'Unban' : 'Ban', style: 'margin-left:4px;',
              onclick: async function () { try { await api('POST', '/api/admin/users/' + encodeURIComponent(u.username) + '/ban'); render(); } catch (e) { alert(e.message); } }
            }));
            actions.appendChild(h('button', {
              class: 'xp-btn xp-btn-sm xp-btn-danger', text: 'Delete',
              onclick: async function () {
                if (!confirm('Delete ' + u.username + ' and all their messages permanently?')) return;
                try { await api('DELETE', '/api/admin/users/' + encodeURIComponent(u.username)); render(); } catch (e) { alert(e.message); }
              }
            }));
          }
          table.appendChild(h('tr', {}, [h('td', { text: u.username }), h('td', { text: u.email || '' }), h('td', { text: status }), actions]));
        });
        body.appendChild(h('div', { style: 'overflow-x:auto;' }, [table]));
      }

      async function renderReports() {
        var d = await api('GET', '/api/admin/reports');
        if (!d.reports.length) body.appendChild(h('div', { text: 'No reports.', style: 'text-align:center; color:#64748b;' }));
        d.reports.forEach(function (r) {
          var card = h('div', { class: 'xp-card' });
          card.appendChild(h('div', { style: 'font-weight:bold;', text: '@' + r.reporter + ' ← @' + r.reported + (r.status === 'open' ? ' 🔴' : ' ✅ (' + (r.action || '') + ')') }));
          card.appendChild(h('div', { text: fmt(r.createdAt), style: 'color:#64748b; font-size:11px;' }));
          card.appendChild(h('div', { text: 'Reason: ' + r.reason, style: 'margin:4px 0;' }));
          if (r.evidence && r.evidence.length) {
            var ev = h('div', { style: 'display:none; background:#f8fafc; border:1px solid #e2e8f0; padding:4px; margin:4px 0;' });
            r.evidence.forEach(function (m) { ev.appendChild(h('div', { text: m.sender + ': ' + m.text })); });
            card.appendChild(h('button', { class: 'xp-btn xp-btn-sm', text: 'Show last messages', onclick: function () { ev.style.display = ev.style.display === 'none' ? 'block' : 'none'; } }));
            card.appendChild(ev);
          }
          if (r.status === 'open') {
            var row = h('div', { style: 'display:flex; gap:6px; margin-top:6px; flex-wrap:wrap;' });
            [['dismiss', 'Dismiss', ''], ['ban', 'Ban reported user', ''], ['delete', 'Delete their account', ' xp-btn-danger']].forEach(function (a) {
              row.appendChild(h('button', {
                class: 'xp-btn xp-btn-sm' + a[2], text: a[1],
                onclick: async function () {
                  if (a[0] !== 'dismiss' && !confirm('Confirm: ' + a[1] + '?')) return;
                  try { await api('POST', '/api/admin/reports/' + r.id, { action: a[0] }); render(); } catch (e) { alert(e.message); }
                }
              }));
            });
            card.appendChild(row);
          }
          body.appendChild(card);
        });
      }

      async function render() {
        body.innerHTML = '';
        body.appendChild(h('div', { style: 'display:flex; gap:6px; margin-bottom:10px;' }, [
          h('button', { class: 'xp-btn xp-btn-sm' + (tab === 'users' ? ' xp-btn-primary' : ''), text: 'Users', onclick: function () { tab = 'users'; render(); } }),
          h('button', { class: 'xp-btn xp-btn-sm' + (tab === 'reports' ? ' xp-btn-primary' : ''), text: 'Reports', onclick: function () { tab = 'reports'; render(); } })
        ]));
        try { if (tab === 'users') await renderUsers(); else await renderReports(); }
        catch (e) { body.appendChild(h('div', { text: e.message, style: 'color:#9f1239;' })); }
      }
      render();
    };

    // ---------- voice calls (WebRTC, full mesh) ----------
    var call = null;       // active call state
    var incoming = null;   // ringing call
    var ringCtx = null, ringTimer = null, ringTimeout = null;
    var iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];

    function wsSend(o) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); }
    function pad2(n) { return (n < 10 ? '0' : '') + n; }

    function toast(text) {
      var t = h('div', { style: 'position:fixed; left:50%; bottom:70px; transform:translateX(-50%); background:#1e293b; color:#fff; padding:8px 14px; border-radius:6px; font-size:13px; z-index:200; max-width:90%; text-align:center;', text: text });
      document.body.appendChild(t);
      setTimeout(function () { t.remove(); }, 3500);
    }

    async function loadIce() {
      try {
        var d = await api('GET', '/api/ice');
        if (d.iceServers && d.iceServers.length) iceServers = d.iceServers;
      } catch (e) {}
    }

    async function getMic() {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        alert('Calls need a secure connection (HTTPS or localhost) and a browser with microphone support.');
        return null;
      }
      try {
        return await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true }, video: false });
      } catch (e) {
        alert('Microphone access was denied or is not available.');
        return null;
      }
    }

    function startRing() {
      stopRing();
      try {
        var AC = window.AudioContext || window.webkitAudioContext;
        if (!AC) return;
        var ctx = new AC();
        ringCtx = ctx;
        if (ctx.state === 'suspended' && ctx.resume) ctx.resume().catch(function () {});
        var beep = function () {
          if (ringCtx !== ctx || ctx.state !== 'running') return;
          var o = ctx.createOscillator(), g = ctx.createGain();
          o.frequency.value = 440; g.gain.value = 0.08;
          o.connect(g); g.connect(ctx.destination);
          o.onended = function () { try { o.disconnect(); g.disconnect(); } catch (e) {} };
          o.start(); o.stop(ctx.currentTime + 0.4);
        };
        beep();
        ringTimer = setInterval(beep, 1500);
      } catch (e) {}
    }
    function stopRing() {
      if (ringTimer) { clearInterval(ringTimer); ringTimer = null; }
      if (ringCtx) { var c = ringCtx; ringCtx = null; try { c.close(); } catch (e) {} } // closing kills any queued sound instantly
    }

    function showIncoming(m) {
      incoming = m;
      document.getElementById('incomingText').textContent = m.mode === 'group'
        ? m.from + ' started a group call (' + (m.groupName || 'group') + ')'
        : m.from + ' is calling you';
      document.getElementById('incomingOverlay').style.display = 'flex';
      startRing();
      clearTimeout(ringTimeout);
      ringTimeout = setTimeout(function () { if (incoming && incoming.callId === m.callId) hideIncoming(); }, 45000);
    }
    function hideIncoming() {
      incoming = null;
      stopRing();
      clearTimeout(ringTimeout);
      document.getElementById('incomingOverlay').style.display = 'none';
    }

    function showCallUI(label, status) {
      stopRing();
      document.getElementById('callTitle').textContent = '📞 ' + label;
      document.getElementById('callTimer').textContent = '00:00';
      document.getElementById('btnCallMute').textContent = '🎤 Mute';
      setCallStatus(status);
      document.getElementById('callOverlay').style.display = 'flex';
      renderPeers();
    }
    function setCallStatus(t) { document.getElementById('callStatus').textContent = t; }

    function renderPeers() {
      var box = document.getElementById('callPeers');
      box.innerHTML = '';
      if (!call) return;
      var rows = [{ n: currentUser.username + ' (you)', s: call.muted ? 'muted' : 'live' }];
      Object.keys(call.roster).forEach(function (u) {
        var p = call.peers[u];
        rows.push({ n: u, s: p ? p.state : 'joining' });
      });
      rows.forEach(function (r) {
        box.appendChild(h('div', { style: 'padding:4px 0; font-size:13px; border-bottom:1px solid #d4d0c8;' }, [h('b', { text: r.n }), ' - ' + r.s]));
      });
    }

    function markConnected() {
      var c = call;
      if (!c || c.startedAt) return;
      c.startedAt = Date.now();
      setCallStatus('Connected');
      c.timer = setInterval(function () {
        if (call !== c) return;
        var s = Math.floor((Date.now() - c.startedAt) / 1000);
        document.getElementById('callTimer').textContent = pad2(Math.floor(s / 60)) + ':' + pad2(s % 60);
      }, 1000);
    }

    function newCallState(stream, label) {
      return { id: null, label: label, joined: false, peers: {}, roster: {}, local: stream, muted: false, startedAt: 0, timer: null };
    }

    async function startCall(target, label) {
      if (call || incoming) { toast('You are already in a call'); return; }
      var stream = await getMic();
      if (!stream) return;
      await loadIce();
      call = newCallState(stream, label);
      showCallUI(label, 'Calling...');
      var p = { type: 'call_start' };
      for (var k in target) p[k] = target[k];
      wsSend(p);
    }

    async function acceptIncoming() {
      if (!incoming) return;
      var m = incoming;
      hideIncoming();
      var stream = await getMic();
      if (!stream) { wsSend({ type: 'call_decline', callId: m.callId }); return; }
      await loadIce();
      call = newCallState(stream, m.mode === 'group' ? (m.groupName || 'Group call') : m.from);
      call.id = m.callId;
      showCallUI(call.label, 'Connecting...');
      wsSend({ type: 'call_accept', callId: m.callId });
    }
    function declineIncoming() {
      if (!incoming) return;
      wsSend({ type: 'call_decline', callId: incoming.callId });
      hideIncoming();
    }

    function closePeer(u) {
      if (!call) return;
      var p = call.peers[u];
      if (!p) return;
      try { p.pc.close(); } catch (e) {}
      p.audio.srcObject = null;
      p.audio.remove();
      delete call.peers[u];
    }

    function cleanupCall() {
      if (!call) return;
      Object.keys(call.peers).forEach(closePeer);
      call.local.getTracks().forEach(function (t) { t.stop(); });
      if (call.timer) clearInterval(call.timer);
      call = null;
      document.getElementById('callOverlay').style.display = 'none';
    }

    function hangup() {
      if (!call) return;
      if (call.id) wsSend({ type: 'call_leave', callId: call.id });
      cleanupCall();
    }

    function createPeer(user) {
      var c = call;
      var p = { pc: new RTCPeerConnection({ iceServers: iceServers }), audio: document.createElement('audio'), pending: [], remote: false, state: 'connecting' };
      p.audio.autoplay = true;
      p.audio.setAttribute('playsinline', '');
      document.getElementById('callAudio').appendChild(p.audio);
      c.local.getTracks().forEach(function (t) { p.pc.addTrack(t, c.local); });
      p.pc.onicecandidate = function (e) {
        if (e.candidate && call === c) wsSend({ type: 'call_signal', callId: c.id, to: user, data: { candidate: e.candidate } });
      };
      p.pc.ontrack = function (e) {
        p.audio.srcObject = e.streams[0];
        var pl = p.audio.play();
        if (pl && pl.catch) pl.catch(function () {});
      };
      p.pc.onconnectionstatechange = function () {
        if (call !== c) return;
        p.state = p.pc.connectionState === 'connected' ? 'connected' : p.pc.connectionState;
        renderPeers();
        if (p.pc.connectionState === 'connected') markConnected();
      };
      c.peers[user] = p;
      c.roster[user] = true;
      renderPeers();
      return p;
    }

    async function offerTo(user) {
      if (!call) return;
      var c = call;
      var p = createPeer(user);
      try {
        var offer = await p.pc.createOffer();
        await p.pc.setLocalDescription(offer);
        if (call === c) wsSend({ type: 'call_signal', callId: c.id, to: user, data: { sdp: p.pc.localDescription } });
      } catch (e) { console.error(e); }
    }

    async function flushIce(p) {
      var list = p.pending; p.pending = [];
      for (var i = 0; i < list.length; i++) { try { await p.pc.addIceCandidate(list[i]); } catch (e) {} }
    }

    async function handleSignal(m) {
      if (!call || call.id !== m.callId) return;
      var c = call;
      var p = c.peers[m.from];
      var d = m.data || {};
      try {
        if (d.sdp && d.sdp.type === 'offer') {
          if (!p) p = createPeer(m.from);
          await p.pc.setRemoteDescription(d.sdp);
          p.remote = true;
          await flushIce(p);
          var ans = await p.pc.createAnswer();
          await p.pc.setLocalDescription(ans);
          if (call === c) wsSend({ type: 'call_signal', callId: c.id, to: m.from, data: { sdp: p.pc.localDescription } });
        } else if (d.sdp && d.sdp.type === 'answer' && p) {
          await p.pc.setRemoteDescription(d.sdp);
          p.remote = true;
          await flushIce(p);
        } else if (d.candidate && p) {
          if (p.remote) { try { await p.pc.addIceCandidate(d.candidate); } catch (e) {} }
          else p.pending.push(d.candidate);
        }
      } catch (e) { console.error(e); }
    }

    function handleCallEvent(m) {
      if (m.type === 'call_dismiss') {
        if (incoming && incoming.callId === m.callId) hideIncoming();
        return;
      }
      if (m.type === 'call_incoming') {
        if (call || incoming) { wsSend({ type: 'call_decline', callId: m.callId }); return; }
        showIncoming(m);
      } else if (m.type === 'call_started') {
        if (!call) { wsSend({ type: 'call_leave', callId: m.callId }); return; }
        call.id = m.callId; call.joined = true;
        setCallStatus('Calling...');
      } else if (m.type === 'call_joined') {
        if (!call) { wsSend({ type: 'call_leave', callId: m.callId }); return; }
        call.id = m.callId; call.joined = true;
        setCallStatus('Connecting...');
        m.peers.forEach(function (u) { call.roster[u] = true; });
        renderPeers();
        m.peers.forEach(function (u) { offerTo(u); }); // the one who joins sends the offers
      } else if (m.type === 'call_peer_joined') {
        if (call && call.id === m.callId) {
          call.roster[m.username] = true;
          if (!call.startedAt) setCallStatus('Connecting...');
          renderPeers();
        }
      } else if (m.type === 'call_peer_left') {
        if (call && call.id === m.callId) {
          closePeer(m.username);
          delete call.roster[m.username];
          renderPeers();
          toast(m.username + ' left the call');
        }
      } else if (m.type === 'call_signal') {
        handleSignal(m);
      } else if (m.type === 'call_ended') {
        if (incoming && incoming.callId === m.callId) { hideIncoming(); toast('Missed call'); }
        if (call && call.id === m.callId) {
          cleanupCall();
          var why = { declined: 'Call declined', no_answer: 'No answer', hangup: 'Call ended', ended: 'Call ended' };
          toast(why[m.reason] || 'Call ended');
        }
      } else if (m.type === 'call_busy') {
        if (call && !call.joined) { cleanupCall(); toast('User is busy'); }
      } else if (m.type === 'call_error') {
        if (call && !call.joined) cleanupCall();
        toast(m.message || 'Call error');
      }
    }

    document.getElementById('btnAcceptCall').onclick = acceptIncoming;
    document.getElementById('btnDeclineCall').onclick = declineIncoming;
    document.getElementById('btnCallHang').onclick = hangup;
    document.getElementById('btnCallMute').onclick = function () {
      if (!call) return;
      call.muted = !call.muted;
      call.local.getAudioTracks().forEach(function (t) { t.enabled = !call.muted; });
      this.textContent = call.muted ? '🔇 Unmute' : '🎤 Mute';
      renderPeers();
    };

    // ---------- voice messages (tap 🎤 to record, tap again to send, ✕ to cancel) ----------
    var rec = null; // active recording

    function voiceMime() {
      if (!window.MediaRecorder) return null;
      var list = ['audio/webm;codecs=opus', 'audio/webm', 'audio/mp4', 'audio/ogg;codecs=opus'];
      for (var i = 0; i < list.length; i++) {
        if (MediaRecorder.isTypeSupported && MediaRecorder.isTypeSupported(list[i])) return list[i];
      }
      return '';
    }

    function resetVoiceUI() {
      var b = document.getElementById('btnVoice');
      b.textContent = '🎤';
      b.classList.remove('xp-btn-danger');
      document.getElementById('btnVoiceCancel').style.display = 'none';
    }

    async function startVoice() {
      if (!activeChat) { toast('Select a chat first'); return; }
      var mime = voiceMime();
      if (mime === null) { alert('Voice messages are not supported in this browser.'); return; }
      var stream = await getMic();
      if (!stream) return;
      var mr;
      try { mr = mime ? new MediaRecorder(stream, { mimeType: mime }) : new MediaRecorder(stream); }
      catch (e) {
        stream.getTracks().forEach(function (t) { t.stop(); });
        alert('Could not start recording.');
        return;
      }
      var r = { mr: mr, chunks: [], stream: stream, chat: { type: activeChat.type, id: activeChat.id }, started: Date.now(), cancelled: false, timer: null };
      rec = r;
      mr.ondataavailable = function (e) { if (e.data && e.data.size) r.chunks.push(e.data); };
      mr.onstop = function () { finishVoice(r); };
      mr.start();

      var btn = document.getElementById('btnVoice');
      btn.classList.add('xp-btn-danger');
      btn.textContent = '⏹ 0:00';
      document.getElementById('btnVoiceCancel').style.display = 'inline-block';
      r.timer = setInterval(function () {
        var s = Math.floor((Date.now() - r.started) / 1000);
        btn.textContent = '⏹ ' + Math.floor(s / 60) + ':' + pad2(s % 60);
        if (s >= 300) stopVoice(false); // 5 minutes max
      }, 500);
    }

    function stopVoice(cancel) {
      if (!rec) return;
      rec.cancelled = !!cancel;
      try { rec.mr.stop(); } catch (e) { finishVoice(rec); }
    }

    async function finishVoice(r) {
      clearInterval(r.timer);
      r.stream.getTracks().forEach(function (t) { t.stop(); });
      if (rec === r) rec = null;
      resetVoiceUI();
      if (r.cancelled || !r.chunks.length || Date.now() - r.started < 700) return;

      var type = r.mr.mimeType || 'audio/webm';
      var blob = new Blob(r.chunks, { type: type });
      var ext = type.indexOf('mp4') > -1 ? 'm4a' : (type.indexOf('ogg') > -1 ? 'ogg' : 'webm');
      var fd = new FormData();
      fd.append('file', blob, 'voice-' + Date.now() + '.' + ext);
      try {
        var res = await fetch('/api/upload', { method: 'POST', headers: { 'Authorization': 'Bearer ' + token }, body: fd });
        var d = await res.json().catch(function () { return {}; });
        if (!res.ok) throw new Error(d.error || 'Voice upload failed');
        var p = { type: 'send_message', messageType: 'voice', fileInfo: d };
        if (r.chat.type === 'group') p.groupId = r.chat.id; else p.to = r.chat.id;
        wsSend(p);
      } catch (e) { alert(e.message); }
    }

    document.getElementById('btnVoice').onclick = function () { if (rec) stopVoice(false); else startVoice(); };
    document.getElementById('btnVoiceCancel').onclick = function () { stopVoice(true); };

    document.getElementById('btnLogout').onclick = function () {
      localStorage.removeItem('vaulta_token');
      location.reload();
    };
  </script>
</body>
</html>`;
}

// ====================== NGROK HTTPS TUNNEL ======================
// Browsers only allow microphone access (needed for calls) on HTTPS or localhost.
// ngrok gives this server a public https:// URL (and wss:// for the WebSocket).
//
//   NGROK_AUTHTOKEN=xxxx node server.js          -> uses the @ngrok/ngrok package
//   (no token env var)                           -> uses the ngrok CLI + its saved config
//   NGROK_DOMAIN=my-name.ngrok-free.app          -> optional fixed domain
//   NGROK=0                                      -> disable the tunnel
let ngrokChild = null;

function announceTunnel(url) {
  console.log('\n======================================================');
  console.log(`[VAULTA] 🔒 Public HTTPS link:  ${url}`);
  console.log('[VAULTA] Open THIS link on every device (calls need HTTPS).');
  console.log('======================================================\n');
}

function startNgrokCli() {
  const { spawn, execFile } = require('child_process');
  const args = ['http', String(PORT), '--log=stdout'];
  if (process.env.NGROK_DOMAIN) args.push('--url=' + process.env.NGROK_DOMAIN);

  const launch = () => {
    ngrokChild = spawn('ngrok', args, { stdio: ['ignore', 'ignore', 'pipe'] });
    ngrokChild.on('error', err => {
      console.error('[NGROK] ❌ Could not run the ngrok CLI:', err.message);
      console.error('[NGROK]    Install it from https://ngrok.com/download  or run: npm install @ngrok/ngrok');
    });
    ngrokChild.stderr.on('data', d => {
      const t = String(d).trim();
      if (t) console.error('[NGROK]', t);
    });
    ngrokChild.on('exit', code => {
      if (code) console.error('[NGROK] ngrok exited with code', code);
    });

    // ngrok exposes its local API on 4040 - read the public URL from there
    let tries = 0;
    const poll = setInterval(() => {
      if (++tries > 30) { clearInterval(poll); console.error('[NGROK] ❌ Timed out waiting for the tunnel URL'); return; }
      http.get('http://127.0.0.1:4040/api/tunnels', res => {
        let body = '';
        res.on('data', c => (body += c));
        res.on('end', () => {
          try {
            const t = (JSON.parse(body).tunnels || []).find(x => String(x.public_url).startsWith('https://'));
            if (t) { clearInterval(poll); announceTunnel(t.public_url); }
          } catch (e) {}
        });
      }).on('error', () => {});
    }, 1000);
  };

  if (NGROK_AUTHTOKEN && /^[A-Za-z0-9_]+$/.test(NGROK_AUTHTOKEN)) {
    execFile('ngrok', ['config', 'add-authtoken', NGROK_AUTHTOKEN], () => launch());
  } else {
    launch();
  }
}

async function startNgrok() {
  if (process.env.NGROK === '0') return;

  let sdk = null;
  if (NGROK_AUTHTOKEN) {
    try { sdk = require('@ngrok/ngrok'); } catch (e) { sdk = null; }
    // No SSH? Install the package automatically the first time.
    if (!sdk) {
      console.log('[NGROK] @ngrok/ngrok not found - installing it automatically (one time)...');
      try {
        require('child_process').execSync('npm install @ngrok/ngrok --no-audit --no-fund', { stdio: 'inherit', cwd: __dirname });
        sdk = require('@ngrok/ngrok');
      } catch (e) {
        console.error('[NGROK] ❌ Auto-install failed:', e.message);
      }
    }
  }

  if (sdk) {
    try {
      const opts = { addr: PORT, authtoken: NGROK_AUTHTOKEN };
      if (process.env.NGROK_DOMAIN) opts.domain = process.env.NGROK_DOMAIN;
      const listener = await sdk.forward(opts);
      announceTunnel(listener.url());
      return;
    } catch (err) {
      console.error('[NGROK] ❌ SDK tunnel failed:', err.message, '- trying the ngrok CLI...');
    }
  }
  startNgrokCli();
}

process.on('exit', () => { if (ngrokChild) try { ngrokChild.kill(); } catch (e) {} });
process.on('SIGINT', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));

// ====================== START ======================
ensureAdmin();
console.log(`[ADMIN] Admin account ready ✅  Username: ${ADMIN_USERNAME}  (no verification code)`);

server.listen(PORT, '0.0.0.0', () => {
  console.log('\n======================================================');
  console.log(`[VAULTA] Local server:  http://localhost:${PORT}`);
  console.log(`[VAULTA] Real-time WebSocket active on port: ${PORT}`);
  console.log('======================================================');
  startNgrok();
});
