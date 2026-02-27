/**
 * WhatsApp CRM - Backend Server
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const http = require('http');
const path = require('path');
const fs = require('fs');

const session = require('express-session');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');

// WhatsApp Web.js
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const qrcodeLib = require('qrcode');

const app = express();
const server = http.createServer(app);

// WebSocket for real-time updates
const WebSocketServer = require('ws').Server;
const wss = new WebSocketServer({ noServer: true });

const SESSION_SECRET = process.env.SESSION_SECRET || 'change_this_secret';
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

const sessionParser = session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true }
});

app.use(cors());
app.use(express.json());
app.use(sessionParser);
app.use(express.static(path.join(__dirname, 'public')));

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ==========================================
// DATABASE (SQLite)
// ==========================================
const DB_PATH = path.join(__dirname, 'crm.db');
const LEGACY_DB_FILE = path.join(__dirname, 'customers.json');
let db;

async function initDb() {
  db = await open({ filename: DB_PATH, driver: sqlite3.Database });
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS customers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone TEXT NOT NULL,
      name TEXT NOT NULL,
      address TEXT,
      note TEXT,
      items_json TEXT,
      time TEXT,
      lastMessage TEXT,
      lastMessageTime TEXT,
      messageCount INTEGER,
      isNew INTEGER,
      contacted INTEGER,
      source TEXT,
      assigned_user_id INTEGER,
      FOREIGN KEY(assigned_user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS custom_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  await ensureAdminUser();
  await ensureDefaultSettings();
  await importLegacyIfNeeded();
}

async function ensureAdminUser() {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
  const existing = await db.get('SELECT id FROM users WHERE email = ?', [adminEmail]);
  if (!existing) {
    const hash = bcrypt.hashSync(adminPassword, 10);
    await db.run(
      'INSERT INTO users (email, name, password_hash, role, active, created_at) VALUES (?, ?, ?, ?, 1, ?)',
      [adminEmail, 'Admin', hash, 'admin', new Date().toISOString()]
    );
    console.log('[INIT] Admin user created:', adminEmail);
  }
}

async function ensureDefaultSettings() {
  const rule = await getSetting('assignment_rule', null);
  if (!rule) {
    await setSetting('assignment_rule', 'manual');
  }
}

async function importLegacyIfNeeded() {
  if (!fs.existsSync(LEGACY_DB_FILE)) return;
  const count = await db.get('SELECT COUNT(*) AS cnt FROM customers');
  if (count && count.cnt > 0) return;

  try {
    const data = JSON.parse(fs.readFileSync(LEGACY_DB_FILE, 'utf8'));
    const customers = Array.isArray(data.customers) ? data.customers : [];
    for (const c of customers) {
      await db.run(
        `INSERT INTO customers
         (phone, name, address, note, items_json, time, lastMessage, lastMessageTime, messageCount, isNew, contacted, source, assigned_user_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          c.phone || '',
          c.name || 'Unknown',
          c.address || '',
          c.note || '',
          JSON.stringify(c.items || []),
          c.time || new Date().toLocaleString('hi-IN'),
          c.lastMessage || '',
          c.lastMessageTime || '',
          c.messageCount || 0,
          c.isNew ? 1 : 0,
          c.contacted ? 1 : 0,
          c.source || 'legacy',
          null
        ]
      );
    }
    if (Array.isArray(data.customItems)) {
      for (const item of data.customItems) {
        await db.run('INSERT OR IGNORE INTO custom_items (name) VALUES (?)', [item]);
      }
    }
    console.log('[INIT] Legacy customers.json imported into SQLite.');
  } catch (err) {
    console.error('[INIT] Failed to import legacy JSON:', err.message);
  }
}

async function getSetting(key, defaultValue) {
  const row = await db.get('SELECT value FROM settings WHERE key = ?', [key]);
  if (!row) {
    if (defaultValue !== null && defaultValue !== undefined) {
      await setSetting(key, String(defaultValue));
      return String(defaultValue);
    }
    return null;
  }
  return row.value;
}

async function setSetting(key, value) {
  await db.run(
    'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
    [key, String(value)]
  );
}

function mapCustomer(row) {
  if (!row) return null;
  return {
    id: row.id,
    phone: row.phone,
    name: row.name,
    address: row.address || '',
    note: row.note || '',
    items: row.items_json ? JSON.parse(row.items_json) : [],
    time: row.time || '',
    lastMessage: row.lastMessage || '',
    lastMessageTime: row.lastMessageTime || '',
    messageCount: row.messageCount || 0,
    isNew: !!row.isNew,
    contacted: !!row.contacted,
    source: row.source || '',
    assigned_user_id: row.assigned_user_id
  };
}

async function getCustomersForUser(user) {
  if (user.role === 'admin') {
    const rows = await db.all('SELECT * FROM customers ORDER BY id DESC');
    return rows.map(mapCustomer);
  }
  const rows = await db.all(
    'SELECT * FROM customers WHERE assigned_user_id = ? ORDER BY id DESC',
    [user.id]
  );
  return rows.map(mapCustomer);
}

async function getCustomItems() {
  const rows = await db.all('SELECT name FROM custom_items ORDER BY name ASC');
  return rows.map(r => r.name);
}

async function getActiveAgents() {
  return db.all(
    "SELECT id, name, email FROM users WHERE role = 'agent' AND active = 1 ORDER BY id ASC"
  );
}

async function pickAssignee(rule) {
  if (rule === 'manual') return null;
  const agents = await getActiveAgents();
  if (agents.length === 0) return null;

  if (rule === 'random') {
    return agents[Math.floor(Math.random() * agents.length)].id;
  }

  // auto (round-robin)
  const last = await getSetting('last_assigned_user_id', '');
  const lastId = parseInt(last || '0', 10);
  let next = agents.find(a => a.id > lastId);
  if (!next) next = agents[0];
  await setSetting('last_assigned_user_id', String(next.id));
  return next.id;
}

// ==========================================
// AUTH HELPERS
// ==========================================
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

function canUserSeeCustomer(user, customerRowOrObj) {
  if (!user || !customerRowOrObj) return false;
  if (user.role === 'admin') return true;
  return customerRowOrObj.assigned_user_id === user.id;
}

function sendWS(ws, payload) {
  if (ws.readyState === 1) {
    ws.send(JSON.stringify(payload));
  }
}

function broadcastAdmin(payload) {
  wss.clients.forEach(ws => {
    if (ws.user && ws.user.role === 'admin') {
      sendWS(ws, payload);
    }
  });
}

function broadcastCustomerNew(customer) {
  wss.clients.forEach(ws => {
    if (canUserSeeCustomer(ws.user, customer)) {
      sendWS(ws, { type: 'new_customer', customer });
    }
  });
}

function broadcastCustomerUpdate(customer, prevAssignedId) {
  wss.clients.forEach(ws => {
    const user = ws.user;
    if (!user) return;
    const canSee = canUserSeeCustomer(user, customer);
    const couldSee = user.role === 'admin' || (prevAssignedId && user.id === prevAssignedId);
    if (canSee) {
      sendWS(ws, { type: 'update_customer', customer });
    } else if (couldSee) {
      sendWS(ws, { type: 'delete_customer', id: customer.id });
    }
  });
}

function broadcastCustomerDelete(customerId, prevAssignedId) {
  wss.clients.forEach(ws => {
    const user = ws.user;
    if (!user) return;
    const couldSee = user.role === 'admin' || (prevAssignedId && user.id === prevAssignedId);
    if (couldSee) {
      sendWS(ws, { type: 'delete_customer', id: customerId });
    }
  });
}

// ==========================================
// WEBSOCKET AUTH
// ==========================================
server.on('upgrade', (req, socket, head) => {
  sessionParser(req, {}, () => {
    if (!req.session.user) {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, ws => {
      ws.user = req.session.user;
      wss.emit('connection', ws, req);
    });
  });
});

wss.on('connection', async (ws, req) => {
  const user = req.session.user;
  ws.user = user;
  console.log('[WS] Connected:', user.email, user.role);
  const customers = await getCustomersForUser(user);
  const customItems = await getCustomItems();
  sendWS(ws, { type: 'init', customers, customItems, user });

  ws.on('message', msg => {
    try {
      const data = JSON.parse(msg);
      if (data.type === 'get_qr' && user.role === 'admin' && qrCodeData) {
        sendWS(ws, { type: 'qr', qr: qrCodeData });
      }
      if (data.type === 'get_status' && user.role === 'admin') {
        sendWS(ws, { type: 'ready', message: isReady ? 'ready' : 'not_ready' });
      }
    } catch (e) {
      // ignore
    }
  });
});

// ==========================================
// WHATSAPP CLIENT
// ==========================================
let qrCodeData = null;
let isReady = false;

const client = new Client({
  authStrategy: new LocalAuth({ dataPath: './whatsapp-session' }),
  puppeteer: { headless: true }
});

client.on('qr', (qr) => {
  console.log('\n[WA] QR Code ready');
  qrcode.generate(qr, { small: true });
  qrCodeData = qr;
  isReady = false;
  broadcastAdmin({ type: 'qr', qr });
});

client.on('ready', () => {
  console.log('[WA] Connected');
  isReady = true;
  qrCodeData = null;
  broadcastAdmin({ type: 'ready', message: 'WhatsApp connected' });
});

client.on('auth_failure', () => {
  console.log('[WA] Auth failure');
  broadcastAdmin({ type: 'auth_failure' });
});

client.on('disconnected', (reason) => {
  console.log('[WA] Disconnected:', reason);
  isReady = false;
  broadcastAdmin({ type: 'disconnected', reason });
});

client.on('message', async (msg) => {
  try {
    if (msg.from.includes('@g.us')) return;
    if (msg.type !== 'chat' && msg.type !== 'text') return;

    const phone = msg.from.replace('@c.us', '');
    const messageText = msg.body;
    const time = new Date().toLocaleString('hi-IN');

    const existing = await db.get('SELECT * FROM customers WHERE phone = ?', [phone]);
    const rule = await getSetting('assignment_rule', 'manual');

    if (existing) {
      let assignedId = existing.assigned_user_id;
      const prevAssignedId = existing.assigned_user_id;
      if (!assignedId) {
        assignedId = await pickAssignee(rule);
      }
      const messageCount = (existing.messageCount || 0) + 1;
      await db.run(
        `UPDATE customers
         SET lastMessage = ?, lastMessageTime = ?, messageCount = ?, isNew = 1, assigned_user_id = ?
         WHERE id = ?`,
        [messageText, time, messageCount, assignedId, existing.id]
      );
      const updated = await db.get('SELECT * FROM customers WHERE id = ?', [existing.id]);
      broadcastCustomerUpdate(mapCustomer(updated), prevAssignedId);
    } else {
      const assignedId = await pickAssignee(rule);
      const result = await db.run(
        `INSERT INTO customers
         (phone, name, address, note, items_json, time, lastMessage, lastMessageTime, messageCount, isNew, contacted, source, assigned_user_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          phone,
          'Unknown (WhatsApp)',
          '',
          '',
          JSON.stringify([]),
          time,
          messageText,
          time,
          1,
          1,
          0,
          'whatsapp',
          assignedId
        ]
      );
      const created = await db.get('SELECT * FROM customers WHERE id = ?', [result.lastID]);
      broadcastCustomerNew(mapCustomer(created));
    }
  } catch (err) {
    console.error('[WA] Message error:', err.message);
  }
});

// ==========================================
// AUTH ROUTES
// ==========================================
app.get('/api/auth/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ user: req.session.user });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email/password required' });
  const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
  if (!user || !user.active) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  req.session.user = { id: user.id, email: user.email, name: user.name, role: user.role };
  res.json({ success: true, user: req.session.user });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// ==========================================
// ADMIN ROUTES
// ==========================================
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const users = await db.all(
    'SELECT id, name, email, role, active, created_at FROM users ORDER BY id ASC'
  );
  res.json(users);
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  const userRole = role === 'admin' ? 'admin' : 'agent';
  const hash = bcrypt.hashSync(password, 10);
  try {
    const result = await db.run(
      'INSERT INTO users (email, name, password_hash, role, active, created_at) VALUES (?, ?, ?, ?, 1, ?)',
      [email, name, hash, userRole, new Date().toISOString()]
    );
    res.json({ success: true, id: result.lastID });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const existing = await db.get('SELECT * FROM users WHERE id = ?', [id]);
  if (!existing) return res.status(404).json({ error: 'User not found' });

  const name = req.body.name ?? existing.name;
  const email = req.body.email ?? existing.email;
  const role = req.body.role === 'admin' ? 'admin' : (req.body.role === 'agent' ? 'agent' : existing.role);
  const active = req.body.active !== undefined ? (req.body.active ? 1 : 0) : existing.active;

  if (existing.role === 'admin' && active === 0) {
    const adminCount = await db.get("SELECT COUNT(*) AS cnt FROM users WHERE role = 'admin' AND active = 1");
    if (adminCount.cnt <= 1) return res.status(400).json({ error: 'At least one admin required' });
  }
  if (existing.role === 'admin' && role !== 'admin') {
    const adminCount = await db.get("SELECT COUNT(*) AS cnt FROM users WHERE role = 'admin' AND active = 1");
    if (adminCount.cnt <= 1) return res.status(400).json({ error: 'At least one admin required' });
  }

  await db.run(
    'UPDATE users SET name = ?, email = ?, role = ?, active = ? WHERE id = ?',
    [name, email, role, active, id]
  );

  if (req.body.password) {
    const hash = bcrypt.hashSync(req.body.password, 10);
    await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, id]);
  }

  res.json({ success: true });
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const existing = await db.get('SELECT * FROM users WHERE id = ?', [id]);
  if (!existing) return res.status(404).json({ error: 'User not found' });
  if (existing.role === 'admin') {
    const adminCount = await db.get("SELECT COUNT(*) AS cnt FROM users WHERE role = 'admin' AND active = 1");
    if (adminCount.cnt <= 1) return res.status(400).json({ error: 'At least one admin required' });
  }
  await db.run('UPDATE users SET active = 0 WHERE id = ?', [id]);
  res.json({ success: true });
});

app.get('/api/admin/settings', requireAdmin, async (req, res) => {
  const assignment_rule = await getSetting('assignment_rule', 'manual');
  res.json({ assignment_rule });
});

app.put('/api/admin/settings', requireAdmin, async (req, res) => {
  const rule = req.body.assignment_rule;
  if (!['manual', 'auto', 'random'].includes(rule)) {
    return res.status(400).json({ error: 'Invalid rule' });
  }
  await setSetting('assignment_rule', rule);
  res.json({ success: true });
});

app.post('/api/admin/assign', requireAdmin, async (req, res) => {
  const { customerId, userId } = req.body;
  if (!customerId || !userId) return res.status(400).json({ error: 'Missing fields' });
  const customer = await db.get('SELECT * FROM customers WHERE id = ?', [customerId]);
  if (!customer) return res.status(404).json({ error: 'Customer not found' });
  const user = await db.get('SELECT * FROM users WHERE id = ? AND role = ? AND active = 1', [userId, 'agent']);
  if (!user) return res.status(404).json({ error: 'Agent not found' });

  const prevAssignedId = customer.assigned_user_id;
  await db.run('UPDATE customers SET assigned_user_id = ?, isNew = 1 WHERE id = ?', [userId, customerId]);
  const updated = await db.get('SELECT * FROM customers WHERE id = ?', [customerId]);
  broadcastCustomerUpdate(mapCustomer(updated), prevAssignedId);
  res.json({ success: true });
});

// ==========================================
// CUSTOMER ROUTES
// ==========================================
app.get('/api/customers', requireAuth, async (req, res) => {
  const customers = await getCustomersForUser(req.session.user);
  res.json(customers);
});

app.post('/api/customers', requireAuth, async (req, res) => {
  const body = req.body || {};
  if (!body.phone || !body.name) return res.status(400).json({ error: 'Phone and name required' });

  let assignedUserId = null;
  if (req.session.user.role === 'agent') {
    assignedUserId = req.session.user.id;
  } else if (req.session.user.role === 'admin' && body.assigned_user_id) {
    assignedUserId = body.assigned_user_id;
  }

  const result = await db.run(
    `INSERT INTO customers
     (phone, name, address, note, items_json, time, lastMessage, lastMessageTime, messageCount, isNew, contacted, source, assigned_user_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      body.phone,
      body.name,
      body.address || '',
      body.note || '',
      JSON.stringify(body.items || []),
      new Date().toLocaleString('hi-IN'),
      '',
      '',
      0,
      0,
      0,
      'manual',
      assignedUserId
    ]
  );
  const created = await db.get('SELECT * FROM customers WHERE id = ?', [result.lastID]);
  broadcastCustomerNew(mapCustomer(created));
  res.json({ success: true, customer: mapCustomer(created) });
});

app.put('/api/customers/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const existing = await db.get('SELECT * FROM customers WHERE id = ?', [id]);
  if (!existing) return res.status(404).json({ error: 'Customer not found' });
  if (!canUserSeeCustomer(req.session.user, existing)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const prevAssignedId = existing.assigned_user_id;
  const body = req.body || {};

  const updated = {
    name: body.name ?? existing.name,
    address: body.address ?? existing.address,
    note: body.note ?? existing.note,
    items_json: body.items ? JSON.stringify(body.items) : existing.items_json,
    isNew: body.isNew !== undefined ? (body.isNew ? 1 : 0) : existing.isNew,
    contacted: body.contacted !== undefined ? (body.contacted ? 1 : 0) : existing.contacted,
    lastMessage: body.lastMessage ?? existing.lastMessage,
    lastMessageTime: body.lastMessageTime ?? existing.lastMessageTime,
    messageCount: body.messageCount ?? existing.messageCount,
    assigned_user_id: existing.assigned_user_id
  };

  if (req.session.user.role === 'admin' && body.assigned_user_id !== undefined) {
    updated.assigned_user_id = body.assigned_user_id;
  }

  await db.run(
    `UPDATE customers
     SET name = ?, address = ?, note = ?, items_json = ?, isNew = ?, contacted = ?,
         lastMessage = ?, lastMessageTime = ?, messageCount = ?, assigned_user_id = ?
     WHERE id = ?`,
    [
      updated.name,
      updated.address,
      updated.note,
      updated.items_json,
      updated.isNew,
      updated.contacted,
      updated.lastMessage,
      updated.lastMessageTime,
      updated.messageCount,
      updated.assigned_user_id,
      id
    ]
  );

  const row = await db.get('SELECT * FROM customers WHERE id = ?', [id]);
  broadcastCustomerUpdate(mapCustomer(row), prevAssignedId);
  res.json({ success: true, customer: mapCustomer(row) });
});

app.delete('/api/customers/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const existing = await db.get('SELECT * FROM customers WHERE id = ?', [id]);
  if (!existing) return res.status(404).json({ error: 'Customer not found' });
  if (!canUserSeeCustomer(req.session.user, existing)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  await db.run('DELETE FROM customers WHERE id = ?', [id]);
  broadcastCustomerDelete(id, existing.assigned_user_id);
  res.json({ success: true });
});

app.post('/api/items', requireAuth, async (req, res) => {
  const item = (req.body.item || '').trim();
  if (!item) return res.status(400).json({ error: 'Item required' });
  await db.run('INSERT OR IGNORE INTO custom_items (name) VALUES (?)', [item]);
  const items = await getCustomItems();
  res.json({ success: true, items });
});

// ==========================================
// WHATSAPP ROUTES
// ==========================================
app.get('/api/whatsapp/status', requireAuth, (req, res) => {
  if (req.session.user.role !== 'admin') {
    return res.json({ ready: isReady });
  }
  res.json({ ready: isReady, qr: qrCodeData });
});

app.get('/api/whatsapp/qr-image', requireAuth, async (req, res) => {
  if (req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  if (!qrCodeData) {
    if (isReady) return res.json({ ready: true });
    return res.json({ waiting: true });
  }
  try {
    const dataUrl = await qrcodeLib.toDataURL(qrCodeData, {
      width: 220,
      margin: 2,
      color: { dark: '#075E54', light: '#ffffff' }
    });
    res.json({ dataUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/whatsapp/qr', requireAuth, (req, res) => {
  if (req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  if (qrCodeData) {
    res.json({ qr: qrCodeData });
  } else if (isReady) {
    res.json({ ready: true });
  } else {
    res.json({ waiting: true });
  }
});

app.post('/api/whatsapp/send', requireAuth, async (req, res) => {
  if (!isReady) {
    return res.status(400).json({ error: 'WhatsApp not connected' });
  }
  try {
    const { phone, message } = req.body;
    if (!phone || !message) return res.status(400).json({ error: 'Phone/message required' });
    const chatId = phone.includes('@c.us') ? phone : `${phone}@c.us`;
    await client.sendMessage(chatId, message);

    const customer = await db.get('SELECT * FROM customers WHERE phone = ?', [phone]);
    if (customer) {
      await db.run('UPDATE customers SET contacted = 1, isNew = 0 WHERE id = ?', [customer.id]);
      const updated = await db.get('SELECT * FROM customers WHERE id = ?', [customer.id]);
      broadcastCustomerUpdate(mapCustomer(updated), customer.assigned_user_id);
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// SERVER START
// ==========================================
async function start() {
  await initDb();
  server.listen(PORT, () => {
    console.log('========================================');
    console.log('CRM Server running at http://localhost:' + PORT);
    console.log('========================================');
    console.log('Waiting for WhatsApp QR...');
    client.initialize();
  });
}

start().catch(err => {
  console.error('Server failed to start:', err);
  process.exit(1);
});
