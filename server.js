/**
 * ============================================================
 *  Chat & Voice Call Server - server.js
 *  Node.js + ws (WebSocket)
 *  - Register / Login with hashed passwords (pbkdf2)
 *  - Persistent accounts stored in users.json
 *  - Persistent private message history stored in history.json
 *  - Online / Offline status management
 *  - Private messages between two users only
 *  - WebRTC Voice Call Signaling (call_offer, call_answer,
 *    call_ice_candidate, call_end, call_reject)
 *  - Ping/Pong every 25 seconds + dead connection cleanup
 * ============================================================
 */

const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---------------------- General settings ----------------------
const PORT = process.env.PORT || 3000; // Render (and most hosts) provide PORT via env var
const USERS_FILE = path.join(__dirname, 'users.json');
const HISTORY_FILE = path.join(__dirname, 'history.json');
const PING_INTERVAL_MS = 25000;
const MESSAGE_TTL_MS = 10 * 60 * 1000; // delete messages after 10 minutes
const CLEANUP_INTERVAL_MS = 1 * 60 * 1000; // run cleanup sweep every 1 minute
const RESET_INTERVAL_MS = 10 * 60 * 1000; // full application data reset every 10 minutes
const RESET_USERS_TOO = false; // Set to true if you also want all user accounts destroyed every 10 minutes
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024; // 15 MB max for images/voice messages

// Create the uploads folder if it doesn't exist
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// ---------------------- Load / save data ----------------------
function loadJSON(file, fallback) {
  try {
    if (fs.existsSync(file)) {
      const raw = fs.readFileSync(file, 'utf8');
      return raw.trim() ? JSON.parse(raw) : fallback;
    }
  } catch (err) {
    console.error(`[ERROR] Failed to load file ${file}:`, err.message);
  }
  return fallback;
}

function saveJSON(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error(`[ERROR] Failed to save file ${file}:`, err.message);
  }
}

// users: { username: { salt, hash } }
let users = loadJSON(USERS_FILE, {});
// history: { "userA|userB": [ {from, to, message, timestamp} ] }
let history = loadJSON(HISTORY_FILE, {});

// ---------------------- Password utilities ----------------------
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function createPasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  return { salt, hash };
}

function verifyPassword(password, record) {
  const hash = hashPassword(password, record.salt);
  return hash === record.hash;
}

// ---------------------- Media file utilities (images / voice messages) ----------------------
function guessExtension(mimeType, originalName) {
  if (originalName && path.extname(originalName)) {
    return path.extname(originalName);
  }
  const map = {
    'image/png': '.png',
    'image/jpeg': '.jpg',
    'image/jpg': '.jpg',
    'image/gif': '.gif',
    'image/webp': '.webp',
    'audio/wav': '.wav',
    'audio/x-wav': '.wav',
    'audio/mpeg': '.mp3',
    'audio/ogg': '.ogg',
  };
  return map[mimeType] || '.bin';
}

// Save a base64-encoded media file to disk, return the stored filename
function saveMediaFile(base64Data, mimeType, originalName) {
  const buffer = Buffer.from(base64Data, 'base64');
  if (buffer.length > MAX_FILE_SIZE_BYTES) {
    throw new Error('File size exceeds the allowed limit (15 MB)');
  }
  const ext = guessExtension(mimeType, originalName);
  const uniqueName = `${Date.now()}_${crypto.randomBytes(6).toString('hex')}${ext}`;
  fs.writeFileSync(path.join(UPLOADS_DIR, uniqueName), buffer);
  return uniqueName;
}

// Read a media file from disk and return it as base64
function loadMediaFile(filename) {
  try {
    const filePath = path.join(UPLOADS_DIR, filename);
    if (!fs.existsSync(filePath)) return null;
    return fs.readFileSync(filePath).toString('base64');
  } catch (err) {
    console.error('[ERROR] Failed to read media file:', err.message);
    return null;
  }
}

// Safely delete a media file from disk
function deleteMediaFile(filename) {
  try {
    const filePath = path.join(UPLOADS_DIR, filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch (err) {
    console.error('[ERROR] Failed to delete media file:', err.message);
  }
}

// ---------------------- Conversation utilities ----------------------
function conversationKey(userA, userB) {
  // Fixed key regardless of the order of the two usernames
  return [userA, userB].sort().join('|');
}

// entry: { from, to, message_type, message, file, file_name, mime_type, timestamp }
function addMessageToHistory(entry) {
  const key = conversationKey(entry.from, entry.to);
  if (!history[key]) history[key] = [];
  history[key].push(entry);
  saveJSON(HISTORY_FILE, history);
  return entry;
}

function getConversationHistory(userA, userB) {
  const key = conversationKey(userA, userB);
  return history[key] || [];
}

// ---------------------- Delete messages older than 10 minutes ----------------------
function cleanupOldMessages() {
  const now = Date.now();
  let changed = false;

  for (const key of Object.keys(history)) {
    const original = history[key];
    const kept = [];

    for (const m of original) {
      if (now - m.timestamp < MESSAGE_TTL_MS) {
        kept.push(m);
      } else {
        changed = true;
        if (m.file) deleteMediaFile(m.file); // also delete the attached media file from disk
      }
    }

    if (kept.length !== original.length) {
      if (kept.length === 0) {
        delete history[key];
      } else {
        history[key] = kept;
      }
    }
  }

  if (changed) {
    saveJSON(HISTORY_FILE, history);
    console.log('[SERVER] Deleted messages older than 10 minutes');
  }
}

// Cleanup on startup, then periodically every minute
cleanupOldMessages();
setInterval(cleanupOldMessages, CLEANUP_INTERVAL_MS);

// ---------------------- 10-Minute Full Application Reset ----------------------
function resetApplicationData() {
  console.log('[SERVER] Triggering 10-minute application reset...');

  // 1. Wipe all conversation history and save empty history.json
  history = {};
  saveJSON(HISTORY_FILE, history);

  // 2. Wipe all media files in the uploads folder
  try {
    if (fs.existsSync(UPLOADS_DIR)) {
      const files = fs.readdirSync(UPLOADS_DIR);
      for (const file of files) {
        try {
          fs.unlinkSync(path.join(UPLOADS_DIR, file));
        } catch (e) {
          console.error('[ERROR] Failed deleting file during reset:', file, e.message);
        }
      }
    }
  } catch (err) {
    console.error('[ERROR] Failed clearing uploads during reset:', err.message);
  }

  // 3. Optional: wipe user accounts if RESET_USERS_TOO is enabled
  if (RESET_USERS_TOO) {
    users = {};
    saveJSON(USERS_FILE, users);
    for (const [uname, ws] of onlineClients.entries()) {
      safeSend(ws, {
        type: 'app_reset',
        message: '10-minute reset: all accounts and data have been wiped.',
        resetUsers: true,
      });
    }
    onlineClients.clear();
    activeCalls.clear();
    console.log('[SERVER] 10-minute reset finished (full wipe including user accounts).');
    return;
  }

  // 4. Notify all connected clients to wipe in-memory chat state
  for (const [uname, ws] of onlineClients.entries()) {
    safeSend(ws, {
      type: 'app_reset',
      message: '10-minute security reset: all chat messages and attachments wiped.',
      resetUsers: false,
    });
  }

  console.log('[SERVER] 10-minute application reset finished (all chats and media purged).');
}

// Schedule application reset every 10 minutes
setInterval(resetApplicationData, RESET_INTERVAL_MS);

// ---------------------- Connected clients management ----------------------
// onlineClients: Map<username, WebSocket>
const onlineClients = new Map();
// activeCalls: Map<username, otherUsername>
const activeCalls = new Map();

const wss = new WebSocket.Server({ port: PORT });

console.log(`[SERVER] Chat server running on port ${PORT}`);

// Safely send JSON to a specific client
function safeSend(ws, data) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify(data));
    } catch (err) {
      console.error('[ERROR] Failed to send message:', err.message);
    }
  }
}

// Build the list of all registered users with their status (online/offline)
function buildUserList() {
  return Object.keys(users).map((username) => ({
    username,
    online: onlineClients.has(username),
  }));
}

// Broadcast the user list and online count to all connected clients
function broadcastUserList() {
  const payload = {
    type: 'user_list',
    users: buildUserList(),
    online_count: onlineClients.size,
  };
  for (const ws of onlineClients.values()) {
    safeSend(ws, payload);
  }
}

// ---------------------- Handle new connections ----------------------
wss.on('connection', (ws) => {
  ws.username = null;
  ws.isAlive = true;

  console.log('[SERVER] New client connected');

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('message', (raw) => {
    let data;
    try {
      data = JSON.parse(raw);
    } catch (err) {
      safeSend(ws, { type: 'error', message: 'Invalid message format (bad JSON)' });
      return;
    }

    try {
      handleMessage(ws, data);
    } catch (err) {
      console.error('[ERROR] Error while handling message:', err.message);
      safeSend(ws, { type: 'error', message: 'An internal server error occurred' });
    }
  });

  ws.on('close', () => {
    handleDisconnect(ws);
  });

  ws.on('error', (err) => {
    console.error('[ERROR] WebSocket connection error:', err.message);
  });
});

// ---------------------- Route messages by type ----------------------
function handleMessage(ws, data) {
  switch (data.type) {
    case 'register':
      handleRegister(ws, data);
      break;
    case 'login':
      handleLogin(ws, data);
      break;
    case 'logout':
      handleLogout(ws);
      break;
    case 'private_message':
      handlePrivateMessage(ws, data);
      break;
    case 'get_history':
      handleGetHistory(ws, data);
      break;
    case 'delete_user':
      handleDeleteUser(ws, data);
      break;

    // --- WebRTC Voice Call Signaling ---
    case 'call_offer':
    case 'call_answer':
    case 'call_ice_candidate':
    case 'call_end':
    case 'call_reject':
      handleCallSignaling(ws, data);
      break;

    default:
      safeSend(ws, { type: 'error', message: `Unknown message type: ${data.type}` });
  }
}

// ---------------------- Register a new account ----------------------
function handleRegister(ws, data) {
  const { username, password } = data;

  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    safeSend(ws, { type: 'register_error', message: 'Username and password are required' });
    return;
  }

  if (users[username]) {
    safeSend(ws, { type: 'register_error', message: 'Username already exists' });
    return;
  }

  users[username] = createPasswordRecord(password);
  saveJSON(USERS_FILE, users);

  console.log(`[SERVER] New account created: ${username}`);
  safeSend(ws, { type: 'register_success', message: 'Account created successfully' });

  // Update the list for everyone online (so the new account shows up as offline)
  broadcastUserList();
}

// ---------------------- Login ----------------------
function handleLogin(ws, data) {
  const { username, password } = data;

  if (!username || !password) {
    safeSend(ws, { type: 'login_error', message: 'Username and password are required' });
    return;
  }

  const record = users[username];
  if (!record || !verifyPassword(password, record)) {
    safeSend(ws, { type: 'login_error', message: 'Invalid username or password' });
    return;
  }

  if (onlineClients.has(username)) {
    // If already connected from an old session, disconnect it and replace with the new one
    const oldWs = onlineClients.get(username);
    safeSend(oldWs, { type: 'error', message: 'Logged in from another device' });
    oldWs.close();
  }

  ws.username = username;
  onlineClients.set(username, ws);

  console.log(`[SERVER] Login: ${username} | Online now: ${onlineClients.size}`);

  safeSend(ws, { type: 'login_success', username });

  // Send the user list and online count to everyone
  broadcastUserList();
}

// ---------------------- Logout ----------------------
function handleLogout(ws) {
  if (ws.username) {
    console.log(`[SERVER] Logout: ${ws.username}`);
  }
  handleDisconnect(ws);
  safeSend(ws, { type: 'logout_success' });
}

// ---------------------- On disconnect (close or logout) ----------------------
function handleDisconnect(ws) {
  if (ws.username) {
    const user = ws.username;

    // Terminate any ongoing call involving this user
    if (activeCalls.has(user)) {
      const partner = activeCalls.get(user);
      activeCalls.delete(user);
      activeCalls.delete(partner);
      const partnerWs = onlineClients.get(partner);
      if (partnerWs) {
        safeSend(partnerWs, {
          type: 'call_end',
          from: user,
          to: partner,
          reason: 'User disconnected',
        });
      }
    }

    if (onlineClients.get(user) === ws) {
      onlineClients.delete(user);
      console.log(`[SERVER] ${user} went offline | Online now: ${onlineClients.size}`);
      ws.username = null;
      broadcastUserList();
    }
  }
}

// ---------------------- WebRTC Voice Call Signaling ----------------------
function handleCallSignaling(ws, data) {
  if (!ws.username) {
    safeSend(ws, { type: 'error', message: 'You must be logged in first' });
    return;
  }

  const { to, type } = data;
  if (!to) {
    safeSend(ws, { type: 'error', message: 'Recipient is required for call signaling' });
    return;
  }

  const caller = ws.username;
  const targetWs = onlineClients.get(to);

  // Recipient offline check
  if (!targetWs) {
    if (type === 'call_offer') {
      safeSend(ws, {
        type: 'call_end',
        from: to,
        to: caller,
        reason: 'User is currently offline',
      });
    }
    return;
  }

  if (type === 'call_offer') {
    // Check if recipient is already in another call
    if (activeCalls.has(to)) {
      safeSend(ws, {
        type: 'call_end',
        from: to,
        to: caller,
        reason: 'User is currently in another call',
      });
      return;
    }
    activeCalls.set(caller, to);
    activeCalls.set(to, caller);
  } else if (type === 'call_end' || type === 'call_reject') {
    activeCalls.delete(caller);
    activeCalls.delete(to);
  }

  // Forward the signaling event directly to the recipient with sender's username
  safeSend(targetWs, {
    ...data,
    from: caller,
  });

  console.log(`[CALL] ${type}: ${caller} -> ${to}`);
}

// ---------------------- Private messages (text / image / voice) ----------------------
function handlePrivateMessage(ws, data) {
  if (!ws.username) {
    safeSend(ws, { type: 'error', message: 'You must be logged in first' });
    return;
  }

  const { to, message, file_data, file_name, mime_type } = data;
  const messageType = data.message_type || 'text';

  if (!to || !users[to]) {
    safeSend(ws, { type: 'error', message: 'Recipient user does not exist' });
    return;
  }

  if (messageType === 'text') {
    if (!message) {
      safeSend(ws, { type: 'error', message: 'Message text is required' });
      return;
    }
  } else if (messageType === 'image' || messageType === 'voice') {
    if (!file_data) {
      safeSend(ws, { type: 'error', message: 'File data is required' });
      return;
    }
  } else {
    safeSend(ws, { type: 'error', message: `Unsupported message type: ${messageType}` });
    return;
  }

  // Save the file to disk if this is a media message
  let storedFile = null;
  if (messageType !== 'text') {
    try {
      storedFile = saveMediaFile(file_data, mime_type, file_name);
    } catch (err) {
      console.error('[ERROR] Failed to save media file:', err.message);
      safeSend(ws, { type: 'error', message: err.message || 'Failed to save the file' });
      return;
    }
  }

  const entry = addMessageToHistory({
    from: ws.username,
    to,
    message_type: messageType,
    message: messageType === 'text' ? message : message || null, // optional caption for an image, for example
    file: storedFile,
    file_name: file_name || null,
    mime_type: mime_type || null,
    timestamp: Date.now(),
  });

  const payload = {
    type: 'private_message',
    from: entry.from,
    to: entry.to,
    message_type: entry.message_type,
    message: entry.message,
    // resend the same base64 data we received directly (no need to re-read it from disk)
    file_data: messageType !== 'text' ? file_data : null,
    file_name: entry.file_name,
    mime_type: entry.mime_type,
    timestamp: entry.timestamp,
  };

  // Send a copy to the recipient if they're online
  const targetWs = onlineClients.get(to);
  if (targetWs) {
    safeSend(targetWs, payload);
  }

  // Send a confirmation copy back to the sender (so it shows up in their UI)
  safeSend(ws, payload);

  console.log(`[SERVER] Message (${messageType}): ${ws.username} -> ${to}`);
}

// ---------------------- Request previous conversation history ----------------------
function handleGetHistory(ws, data) {
  if (!ws.username) {
    safeSend(ws, { type: 'error', message: 'You must be logged in first' });
    return;
  }

  const withUser = data.with;
  if (!withUser) {
    safeSend(ws, { type: 'error', message: 'The "with" field is required' });
    return;
  }

  const rawMessages = getConversationHistory(ws.username, withUser);

  // Attach base64 data for each media message by reading it from disk
  const messages = rawMessages.map((m) => {
    if (m.message_type && m.message_type !== 'text' && m.file) {
      return { ...m, file_data: loadMediaFile(m.file) };
    }
    return { ...m, file_data: null };
  });

  safeSend(ws, { type: 'history', with: withUser, messages });
}

// ---------------------- Delete user (own account only) ----------------------
function handleDeleteUser(ws, data) {
  if (!ws.username) {
    safeSend(ws, { type: 'error', message: 'You must be logged in first' });
    return;
  }

  // Only allow deleting the caller's own account (no deleting other accounts)
  const target = ws.username;

  if (!users[target]) {
    safeSend(ws, { type: 'delete_user_error', message: 'User not found' });
    return;
  }

  // Remove the account from the users file
  delete users[target];
  saveJSON(USERS_FILE, users);

  // Disconnect the current connection (the client will be informed via delete_user_success below)
  onlineClients.delete(target);
  ws.username = null;

  // Delete all conversations linked to this user (and their media files)
  for (const key of Object.keys(history)) {
    if (key.split('|').includes(target)) {
      for (const m of history[key]) {
        if (m.file) deleteMediaFile(m.file);
      }
      delete history[key];
    }
  }
  saveJSON(HISTORY_FILE, history);

  console.log(`[SERVER] User "${target}" deleted their own account`);

  safeSend(ws, { type: 'delete_user_success', username: target });

  // Update the list for everyone
  broadcastUserList();
}

// ---------------------- Ping / Pong to prevent connection drops ----------------------
const pingInterval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      console.log(`[SERVER] Terminating dead connection${ws.username ? ' - ' + ws.username : ''}`);
      handleDisconnect(ws);
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, PING_INTERVAL_MS);

wss.on('close', () => {
  clearInterval(pingInterval);
});

// ---------------------- Global error handling without crashing the server ----------------------
process.on('uncaughtException', (err) => {
  console.error('[FATAL-CAUGHT] Uncaught exception:', err);
});

process.on('unhandledRejection', (reason) => {
  console.error('[FATAL-CAUGHT] Unhandled promise rejection:', reason);
});
