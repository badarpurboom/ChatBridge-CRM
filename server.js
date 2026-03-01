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
      selected_items_json TEXT,
      selection_type TEXT,
      time TEXT,
      lastMessage TEXT,
      lastMessageTime TEXT,
      messageCount INTEGER,
      isNew INTEGER,
      contacted INTEGER,
      source TEXT,
      assigned_user_id INTEGER,
      assigned_at TEXT,
      FOREIGN KEY(assigned_user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS custom_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL
    );

    CREATE TABLE IF NOT EXISTS catalog_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      UNIQUE(name, type)
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS lead_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id INTEGER NOT NULL,
      action TEXT NOT NULL,
      from_user_id INTEGER,
      to_user_id INTEGER,
      actor_user_id INTEGER,
      note TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(customer_id) REFERENCES customers(id)
    );

    CREATE INDEX IF NOT EXISTS idx_customers_phone ON customers(phone);
    CREATE INDEX IF NOT EXISTS idx_catalog_type ON catalog_items(type);
    CREATE INDEX IF NOT EXISTS idx_lead_audit_customer_id ON lead_audit(customer_id);
    CREATE INDEX IF NOT EXISTS idx_lead_audit_created_at ON lead_audit(created_at);
  `);

  await ensureCustomerColumns();
  await ensureColumn('catalog_items', 'price', 'REAL DEFAULT 0');
  await ensureAdminUser();
  await ensureDefaultSettings();
  await importLegacyIfNeeded();
  await migrateCustomerSelections();
  await normalizeAndDedupePhones();
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
  await getSetting('assignment_rule', 'manual');
  await getSetting('company_focus', 'product');
}

async function ensureColumn(table, column, definition) {
  const cols = await db.all(`PRAGMA table_info(${table})`);
  if (!cols.find(c => c.name === column)) {
    await db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

async function ensureCustomerColumns() {
  await ensureColumn('customers', 'selected_items_json', 'TEXT');
  await ensureColumn('customers', 'selection_type', 'TEXT');
  await ensureColumn('customers', 'mature', 'INTEGER DEFAULT 0');
  await ensureColumn('customers', 'mature_at', 'TEXT');
  await ensureColumn('customers', 'assigned_at', 'TEXT');
}

async function migrateCustomerSelections() {
  const focus = await getCompanyFocus();
  await db.run(
    `UPDATE customers
     SET selected_items_json = items_json
     WHERE (selected_items_json IS NULL OR selected_items_json = '')
       AND items_json IS NOT NULL AND items_json != ''`
  );
  await db.run(
    `UPDATE customers
     SET selection_type = ?
     WHERE selection_type IS NULL OR selection_type = ''`,
    [focus]
  );
}

async function importLegacyIfNeeded() {
  if (!fs.existsSync(LEGACY_DB_FILE)) return;
  const count = await db.get('SELECT COUNT(*) AS cnt FROM customers');
  if (count && count.cnt > 0) return;

  try {
    const data = JSON.parse(fs.readFileSync(LEGACY_DB_FILE, 'utf8'));
    const customers = Array.isArray(data.customers) ? data.customers : [];
    const companyFocus = await getCompanyFocus();
    for (const c of customers) {
      const selectedItems = normalizeSelectedItemsInput(c.items || []);
      const selectedItemsJson = JSON.stringify(selectedItems);
      await db.run(
        `INSERT INTO customers
         (phone, name, address, note, items_json, selected_items_json, selection_type,
          time, lastMessage, lastMessageTime, messageCount, isNew, contacted, source, assigned_user_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          normalizePhone(c.phone || ''),
          c.name || 'Unknown',
          c.address || '',
          c.note || '',
          selectedItemsJson,
          selectedItemsJson,
          companyFocus,
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

async function logLeadAssignment({ customerId, action, fromUserId, toUserId, actorUserId, note }) {
  if (!customerId || !action) return;
  await db.run(
    `INSERT INTO lead_audit
     (customer_id, action, from_user_id, to_user_id, actor_user_id, note, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      customerId,
      action,
      fromUserId || null,
      toUserId || null,
      actorUserId || null,
      note || '',
      new Date().toISOString()
    ]
  );
}

async function getCompanyFocus() {
  return getSetting('company_focus', 'product');
}

async function getCatalogItems(type, options = {}) {
  const includeInactive = options.includeInactive === true;
  const sql = includeInactive
    ? 'SELECT id, name, type, active, price FROM catalog_items WHERE type = ? ORDER BY name ASC'
    : 'SELECT id, name, type, active, price FROM catalog_items WHERE type = ? AND active = 1 ORDER BY name ASC';
  return db.all(sql, [type]);
}

async function validateSelectedItems(items, focus) {
  if (!Array.isArray(items) || items.length === 0) return true;
  const catalog = await getCatalogItems(focus);
  const allowedIds = new Set(catalog.map(i => String(i.id)));
  const allowedNames = new Set(catalog.map(i => i.name));
  for (const item of items) {
    if (!item) return false;
    if (item.id !== undefined && item.id !== null) {
      if (!allowedIds.has(String(item.id))) return false;
    } else if (!allowedNames.has(item.name)) {
      return false;
    }
  }
  return true;
}

function normalizePhone(value) {
  if (!value) return '';
  return String(value).replace(/\D/g, '');
}

function normalizeSelectedItems(raw) {
  if (!raw) return [];
  let parsed;
  try {
    parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  if (parsed.length === 0) return [];

  if (typeof parsed[0] === 'string') {
    return parsed
      .map(name => String(name || '').trim())
      .filter(Boolean)
      .map(name => ({ id: null, name, qty: 1 }));
  }

  const normalized = [];
  for (const item of parsed) {
    if (!item || typeof item !== 'object') continue;
    const name = String(item.name || item.label || '').trim();
    if (!name) continue;
    const qtyRaw = Number(item.qty ?? item.quantity ?? 1);
    const qty = Number.isFinite(qtyRaw) && qtyRaw > 0 ? qtyRaw : 1;
    const price = item.price !== undefined ? parseFloat(item.price) : undefined;
    normalized.push({ id: item.id ?? null, name, qty, price });
  }
  return normalized;
}

function normalizeSelectedItemsInput(raw) {
  return normalizeSelectedItems(raw);
}

function getRowItems(row) {
  if (!row) return [];
  return normalizeSelectedItems(row.selected_items_json || row.items_json || '[]');
}

function mergeItems(rows) {
  const map = new Map();
  for (const row of rows) {
    const items = getRowItems(row);
    for (const item of items) {
      const key = item.id ? `id:${item.id}` : `name:${item.name}`;
      const existing = map.get(key);
      if (existing) {
        existing.qty += item.qty || 1;
      } else {
        map.set(key, { id: item.id ?? null, name: item.name, qty: item.qty || 1 });
      }
    }
  }
  return JSON.stringify(Array.from(map.values()));
}

function pickWinnerCustomer(rows) {
  if (!rows || rows.length === 0) return null;
  const withAssigned = rows.filter(r => r.assigned_user_id);
  if (withAssigned.length > 0) {
    return withAssigned.sort((a, b) => b.id - a.id)[0];
  }
  return rows.sort((a, b) => b.id - a.id)[0];
}

function firstNonEmpty(rows, field) {
  for (const row of rows) {
    const val = row[field];
    if (val !== undefined && val !== null && String(val).trim() !== '') {
      return val;
    }
  }
  return '';
}

function pickLatestById(rows, field) {
  const withField = rows.filter(r => r[field]);
  if (withField.length === 0) return '';
  return withField.sort((a, b) => b.id - a.id)[0][field] || '';
}

function pickAssignedUserId(rows, winner) {
  if (winner && winner.assigned_user_id) return winner.assigned_user_id;
  const found = rows.find(r => r.assigned_user_id);
  return found ? found.assigned_user_id : null;
}

async function mergeDuplicateCustomers(rows, normalizedPhone, options = {}) {
  if (!rows || rows.length === 0) return null;
  if (rows.length === 1) {
    const row = rows[0];
    if (normalizedPhone && row.phone !== normalizedPhone) {
      await db.run('UPDATE customers SET phone = ? WHERE id = ?', [normalizedPhone, row.id]);
      row.phone = normalizedPhone;
    }
    return row;
  }

  const winner = pickWinnerCustomer(rows);
  const prevAssignedId = winner.assigned_user_id;

  const merged = {
    phone: normalizedPhone || winner.phone,
    name: winner.name || firstNonEmpty(rows, 'name') || 'Unknown',
    address: winner.address || firstNonEmpty(rows, 'address'),
    note: winner.note || firstNonEmpty(rows, 'note'),
    selected_items_json: mergeItems(rows),
    items_json: mergeItems(rows),
    selection_type: winner.selection_type || firstNonEmpty(rows, 'selection_type'),
    time: pickLatestById(rows, 'time') || winner.time || '',
    lastMessage: pickLatestById(rows, 'lastMessage') || winner.lastMessage || '',
    lastMessageTime: pickLatestById(rows, 'lastMessageTime') || winner.lastMessageTime || '',
    messageCount: Math.max(...rows.map(r => r.messageCount || 0)),
    isNew: rows.some(r => r.isNew) ? 1 : 0,
    contacted: rows.some(r => r.contacted) ? 1 : 0,
    source: winner.source || firstNonEmpty(rows, 'source'),
    assigned_user_id: pickAssignedUserId(rows, winner)
  };

  await db.run(
    `UPDATE customers
     SET phone = ?, name = ?, address = ?, note = ?, items_json = ?, selected_items_json = ?, selection_type = ?,
         time = ?, lastMessage = ?,
         lastMessageTime = ?, messageCount = ?, isNew = ?, contacted = ?, source = ?, assigned_user_id = ?
     WHERE id = ?`,
    [
      merged.phone,
      merged.name,
      merged.address || '',
      merged.note || '',
      merged.items_json,
      merged.selected_items_json,
      merged.selection_type || '',
      merged.time,
      merged.lastMessage,
      merged.lastMessageTime,
      merged.messageCount,
      merged.isNew,
      merged.contacted,
      merged.source || '',
      merged.assigned_user_id,
      winner.id
    ]
  );

  const losers = rows.filter(r => r.id !== winner.id);
  if (losers.length > 0) {
    const loserIds = losers.map(r => r.id);
    await db.run(`DELETE FROM customers WHERE id IN (${loserIds.map(() => '?').join(',')})`, loserIds);
  }

  const updated = await db.get('SELECT * FROM customers WHERE id = ?', [winner.id]);

  const shouldBroadcast = options.broadcast !== false;
  if (shouldBroadcast) {
    if (losers.length > 0) {
      for (const loser of losers) {
        broadcastCustomerDelete(loser.id, loser.assigned_user_id);
      }
    }
    broadcastCustomerUpdate(mapCustomer(updated), prevAssignedId);
  }

  return updated;
}

async function resolveCustomerByPhone(rawPhone, options = {}) {
  const phone = normalizePhone(rawPhone);
  if (!phone) return { phone: '', customer: null };
  const rows = await db.all('SELECT * FROM customers WHERE phone = ?', [phone]);
  if (rows.length === 0) return { phone, customer: null };
  if (rows.length === 1) {
    const row = rows[0];
    if (row.phone !== phone) {
      await db.run('UPDATE customers SET phone = ? WHERE id = ?', [phone, row.id]);
      row.phone = phone;
    }
    return { phone, customer: row };
  }
  const merged = await mergeDuplicateCustomers(rows, phone, options);
  return { phone, customer: merged };
}

async function normalizeAndDedupePhones() {
  const rows = await db.all('SELECT * FROM customers');
  const groups = new Map();
  for (const row of rows) {
    const normalized = normalizePhone(row.phone);
    if (!normalized) continue;
    if (!groups.has(normalized)) groups.set(normalized, []);
    groups.get(normalized).push(row);
  }

  for (const [normalized, group] of groups.entries()) {
    if (group.length === 1) {
      const row = group[0];
      if (row.phone !== normalized) {
        await db.run('UPDATE customers SET phone = ? WHERE id = ?', [normalized, row.id]);
      }
    } else {
      await mergeDuplicateCustomers(group, normalized, { broadcast: false });
    }
  }
}

function mapCustomer(row) {
  if (!row) return null;
  return {
    id: row.id,
    phone: row.phone,
    name: row.name,
    address: row.address || '',
    note: row.note || '',
    items: getRowItems(row),
    selection_type: row.selection_type || '',
    time: row.time || '',
    lastMessage: row.lastMessage || '',
    lastMessageTime: row.lastMessageTime || '',
    messageCount: row.messageCount || 0,
    isNew: !!row.isNew,
    contacted: !!row.contacted,
    source: row.source || '',
    assigned_user_id: row.assigned_user_id,
    assigned_at: row.assigned_at ? new Date(row.assigned_at).toLocaleString('hi-IN') : '',
    mature: !!row.mature,
    mature_at: row.mature_at || ''
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

// Support Pagination Fetch
async function getPaginatedCustomers(user, options = {}) {
  const page = Math.max(1, parseInt(options.page) || 1);
  const limit = Math.max(1, Math.min(100, parseInt(options.limit) || 50));
  const offset = (page - 1) * limit;

  let whereClauses = [];
  let params = [];

  // Agent filtering (Role based)
  if (user.role !== 'admin') {
    whereClauses.push('assigned_user_id = ?');
    params.push(user.id);
  } else if (options.agentId && options.agentId !== 'all') {
    whereClauses.push('assigned_user_id = ?');
    params.push(parseInt(options.agentId));
  }

  // Status filtering
  if (options.status === 'unassigned') {
    whereClauses.push('(assigned_user_id IS NULL OR assigned_user_id = "")');
  } else if (options.status === 'assigned') {
    whereClauses.push('assigned_user_id IS NOT NULL');
    whereClauses.push('(mature IS NULL OR mature = 0)');
  } else if (options.status === 'mature') {
    whereClauses.push('mature = 1');
  }

  // Search filtering
  if (options.search) {
    const searchStr = '%' + String(options.search).trim() + '%';
    whereClauses.push('(name LIKE ? OR phone LIKE ?)');
    params.push(searchStr, searchStr);
  }

  // Date filtering
  if (options.date) {
    // Exact match for the ISO date string format (YYYY-MM-DD or DD/MM/YYYY variation depending on locale usage)
    const dateStr = '%' + String(options.date).trim() + '%';
    whereClauses.push('(assigned_at LIKE ? OR time LIKE ?)');
    params.push(dateStr, dateStr);
  }

  const whereSql = whereClauses.length > 0 ? 'WHERE ' + whereClauses.join(' AND ') : '';

  // Get total count
  const countSql = `SELECT COUNT(*) as total FROM customers ${whereSql}`;
  const countRow = await db.get(countSql, params);
  const total = countRow ? countRow.total : 0;

  // Get paginated rows
  const fetchSql = `SELECT * FROM customers ${whereSql} ORDER BY id DESC LIMIT ? OFFSET ?`;
  const rows = await db.all(fetchSql, [...params, limit, offset]);

  // Aggregate stats (could be optimized with a single query, but doing it simpler here or via separate query)
  // To avoid Heavy querying, we might just return the paginated list and rely on a separate stats endpoint if needed, 
  // but for now let's just return the list.

  return {
    data: rows.map(mapCustomer),
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit)
    }
  };
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

async function broadcastCatalogUpdate() {
  const companyFocus = await getCompanyFocus();
  const catalogItems = await getCatalogItems(companyFocus);
  wss.clients.forEach(ws => {
    if (ws.user) {
      sendWS(ws, { type: 'catalog_update', companyFocus, catalogItems });
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
  // Do NOT send all customers on WS init to save memory/bandwidth. Frontend will fetch via API.
  const companyFocus = await getCompanyFocus();
  const catalogItems = await getCatalogItems(companyFocus);
  sendWS(ws, { type: 'init', catalogItems, companyFocus, user });
  if (user.role === 'admin' && qrCodeData) {
    sendWS(ws, { type: 'qr', qr: qrCodeData });
  }

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

    const rawPhone = msg.from.replace('@c.us', '');
    const { phone, customer: existing } = await resolveCustomerByPhone(rawPhone);
    if (!phone) return;
    const messageText = msg.body;
    const time = new Date().toLocaleString('hi-IN');
    const rule = await getSetting('assignment_rule', 'manual');
    const companyFocus = await getCompanyFocus();

    if (existing) {
      let assignedId = existing.assigned_user_id;
      const prevAssignedId = existing.assigned_user_id;
      if (!assignedId) {
        assignedId = await pickAssignee(rule);
      }
      const assignedChanged = assignedId && assignedId !== prevAssignedId;
      const messageCount = (existing.messageCount || 0) + 1;
      await db.run(
        `UPDATE customers
         SET lastMessage = ?, lastMessageTime = ?, messageCount = ?, isNew = 1, assigned_user_id = ?
    WHERE id = ? `,
        [messageText, time, messageCount, assignedId, existing.id]
      );
      const updated = await db.get('SELECT * FROM customers WHERE id = ?', [existing.id]);
      if (assignedChanged) {
        await logLeadAssignment({
          customerId: existing.id,
          action: 'auto-assign',
          fromUserId: prevAssignedId,
          toUserId: assignedId,
          actorUserId: null,
          note: `rule:${rule} `
        });
      }
      broadcastCustomerUpdate(mapCustomer(updated), prevAssignedId);
    } else {
      const assignedId = await pickAssignee(rule);
      const now = new Date().toISOString();
      const result = await db.run(
        `INSERT INTO customers
    (phone, name, address, note, items_json, selected_items_json, selection_type,
      time, lastMessage, lastMessageTime, messageCount, isNew, contacted, source, assigned_user_id, assigned_at)
  VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          phone,
          'Unknown (WhatsApp)',
          '',
          '',
          JSON.stringify([]),
          JSON.stringify([]),
          companyFocus,
          time,
          messageText,
          time,
          1,
          1,
          0,
          'whatsapp',
          assignedId,
          assignedId ? now : null
        ]
      );
      const created = await db.get('SELECT * FROM customers WHERE id = ?', [result.lastID]);
      if (assignedId) {
        await logLeadAssignment({
          customerId: created.id,
          action: 'auto-assign',
          fromUserId: null,
          toUserId: assignedId,
          actorUserId: null,
          note: `rule:${rule} `
        });
      }
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

app.post('/api/admin/users/:id/toggle', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const existing = await db.get('SELECT * FROM users WHERE id = ?', [id]);
  if (!existing) return res.status(404).json({ error: 'User not found' });

  const nextActive = existing.active ? 0 : 1;
  if (existing.role === 'admin' && nextActive === 0) {
    const adminCount = await db.get("SELECT COUNT(*) AS cnt FROM users WHERE role = 'admin' AND active = 1");
    if (adminCount.cnt <= 1) return res.status(400).json({ error: 'At least one active admin required' });
  }

  await db.run('UPDATE users SET active = ? WHERE id = ?', [nextActive, id]);
  res.json({ success: true, active: nextActive });
});

app.get('/api/admin/settings', requireAdmin, async (req, res) => {
  const assignment_rule = await getSetting('assignment_rule', 'manual');
  const company_focus = await getCompanyFocus();
  res.json({ assignment_rule, company_focus });
});

app.put('/api/admin/settings', requireAdmin, async (req, res) => {
  const rule = req.body.assignment_rule;
  const focus = req.body.company_focus;
  if (rule !== undefined && !['manual', 'auto', 'random'].includes(rule)) {
    return res.status(400).json({ error: 'Invalid rule' });
  }
  if (focus !== undefined && !['product', 'service'].includes(focus)) {
    return res.status(400).json({ error: 'Invalid company focus' });
  }
  if (rule !== undefined) {
    await setSetting('assignment_rule', rule);
  }
  let focusChanged = false;
  if (focus !== undefined) {
    const prev = await getCompanyFocus();
    await setSetting('company_focus', focus);
    focusChanged = prev !== focus;
  }
  if (focusChanged) {
    await broadcastCatalogUpdate();
  }
  res.json({ success: true });
});

app.get('/api/admin/catalog', requireAdmin, async (req, res) => {
  const type = req.query.type || await getCompanyFocus();
  if (!['product', 'service'].includes(type)) {
    return res.status(400).json({ error: 'Invalid type' });
  }
  const items = await getCatalogItems(type, { includeInactive: true });
  res.json(items);
});

app.post('/api/admin/catalog', requireAdmin, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const type = req.body.type || await getCompanyFocus();
  const price = parseFloat(req.body.price) || 0;
  if (!name) return res.status(400).json({ error: 'Name required' });
  if (!['product', 'service'].includes(type)) {
    return res.status(400).json({ error: 'Invalid type' });
  }
  try {
    const result = await db.run(
      'INSERT INTO catalog_items (name, type, active, price, created_at) VALUES (?, ?, 1, ?, ?)',
      [name, type, price, new Date().toISOString()]
    );
    const item = await db.get('SELECT id, name, type, active, price FROM catalog_items WHERE id = ?', [result.lastID]);
    await broadcastCatalogUpdate();
    res.json({ success: true, item });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/admin/catalog/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const existing = await db.get('SELECT * FROM catalog_items WHERE id = ?', [id]);
  if (!existing) return res.status(404).json({ error: 'Item not found' });

  const name = req.body.name !== undefined ? String(req.body.name || '').trim() : existing.name;
  const active = req.body.active !== undefined ? (req.body.active ? 1 : 0) : existing.active;
  const price = req.body.price !== undefined ? (parseFloat(req.body.price) || 0) : existing.price;
  if (!name) return res.status(400).json({ error: 'Name required' });

  try {
    await db.run('UPDATE catalog_items SET name = ?, active = ?, price = ? WHERE id = ?', [name, active, price, id]);
    const item = await db.get('SELECT id, name, type, active, price FROM catalog_items WHERE id = ?', [id]);
    await broadcastCatalogUpdate();
    res.json({ success: true, item });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/admin/catalog/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  try {
    await db.run('DELETE FROM catalog_items WHERE id = ?', [id]);
    await broadcastCatalogUpdate();
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/admin/assign', requireAdmin, async (req, res) => {
  const { customerId, userId } = req.body;
  if (!customerId || !userId) return res.status(400).json({ error: 'Missing fields' });
  const customer = await db.get('SELECT * FROM customers WHERE id = ?', [customerId]);
  if (!customer) return res.status(404).json({ error: 'Customer not found' });
  const user = await db.get('SELECT * FROM users WHERE id = ? AND role = ? AND active = 1', [userId, 'agent']);
  if (!user) return res.status(404).json({ error: 'Agent not found' });

  const prevAssignedId = customer.assigned_user_id;
  const now = new Date().toISOString();
  await db.run('UPDATE customers SET assigned_user_id = ?, isNew = 1, assigned_at = ? WHERE id = ?', [userId, now, customerId]);
  const updated = await db.get('SELECT * FROM customers WHERE id = ?', [customerId]);
  if (prevAssignedId !== userId) {
    await logLeadAssignment({
      customerId,
      action: prevAssignedId ? 'reassign' : 'assign',
      fromUserId: prevAssignedId,
      toUserId: userId,
      actorUserId: req.session.user.id,
      note: 'admin'
    });
  }
  broadcastCustomerUpdate(mapCustomer(updated), prevAssignedId);
  res.json({ success: true });
});

app.post('/api/admin/assign-bulk', requireAdmin, async (req, res) => {
  const { customerIds, userId } = req.body || {};
  if (!Array.isArray(customerIds) || customerIds.length === 0 || !userId) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  const agent = await db.get(
    'SELECT id FROM users WHERE id = ? AND role = ? AND active = 1',
    [userId, 'agent']
  );
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  const ids = customerIds
    .map(id => parseInt(id, 10))
    .filter(id => Number.isInteger(id) && id > 0);
  if (ids.length === 0) return res.status(400).json({ error: 'Invalid customer IDs' });

  const placeholders = ids.map(() => '?').join(',');
  const existing = await db.all(`SELECT * FROM customers WHERE id IN(${placeholders})`, ids);
  if (existing.length === 0) return res.status(404).json({ error: 'Customers not found' });

  const now = new Date().toISOString();
  await db.run(
    `UPDATE customers SET assigned_user_id = ?, isNew = 1, assigned_at = ? WHERE id IN(${placeholders})`,
    [agent.id, now, ...ids]
  );

  const updatedRows = await db.all(`SELECT * FROM customers WHERE id IN(${placeholders})`, ids);
  const updatedMap = new Map(updatedRows.map(r => [r.id, r]));
  for (const row of existing) {
    const updated = updatedMap.get(row.id);
    if (updated) {
      if (row.assigned_user_id !== agent.id) {
        await logLeadAssignment({
          customerId: updated.id,
          action: row.assigned_user_id ? 'reassign' : 'assign',
          fromUserId: row.assigned_user_id,
          toUserId: agent.id,
          actorUserId: req.session.user.id,
          note: 'admin-bulk'
        });
      }
      broadcastCustomerUpdate(mapCustomer(updated), row.assigned_user_id);
    }
  }

  res.json({ success: true, updated: updatedRows.length });
});

app.post('/api/admin/delete-bulk', requireAdmin, async (req, res) => {
  const { customerIds } = req.body;
  if (!Array.isArray(customerIds) || customerIds.length === 0) {
    return res.status(400).json({ error: 'No customers selected' });
  }

  try {
    const placeholders = customerIds.map(() => '?').join(',');
    const leadsToDelete = await db.all(
      `SELECT id, assigned_user_id FROM customers WHERE id IN(${placeholders})`,
      customerIds
    );

    await db.run(
      `DELETE FROM customers WHERE id IN(${placeholders})`,
      customerIds
    );

    for (const lead of leadsToDelete) {
      broadcastCustomerDelete(lead.id, lead.assigned_user_id);
    }

    res.json({ success: true, count: leadsToDelete.length });
  } catch (err) {
    console.error('Bulk delete error:', err);
    res.status(500).json({ error: 'Failed to delete leads' });
  }
});

app.post('/api/admin/unassign', requireAdmin, async (req, res) => {
  const { customerId } = req.body || {};
  if (!customerId) return res.status(400).json({ error: 'Missing fields' });
  const customer = await db.get('SELECT * FROM customers WHERE id = ?', [customerId]);
  if (!customer) return res.status(404).json({ error: 'Customer not found' });

  const prevAssignedId = customer.assigned_user_id;
  if (!prevAssignedId) return res.json({ success: true });

  await db.run('UPDATE customers SET assigned_user_id = NULL WHERE id = ?', [customerId]);
  const updated = await db.get('SELECT * FROM customers WHERE id = ?', [customerId]);

  await logLeadAssignment({
    customerId,
    action: 'unassign',
    fromUserId: prevAssignedId,
    toUserId: null,
    actorUserId: req.session.user.id,
    note: 'admin'
  });

  broadcastCustomerUpdate(mapCustomer(updated), prevAssignedId);
  res.json({ success: true });
});

app.get('/api/admin/lead-audit', requireAdmin, async (req, res) => {
  const customerId = parseInt(req.query.customerId, 10);
  if (!customerId) return res.status(400).json({ error: 'customerId required' });
  const rows = await db.all(
    `SELECT la.*,
    uf.name AS from_name, ut.name AS to_name, ua.name AS actor_name
     FROM lead_audit la
     LEFT JOIN users uf ON uf.id = la.from_user_id
     LEFT JOIN users ut ON ut.id = la.to_user_id
     LEFT JOIN users ua ON ua.id = la.actor_user_id
     WHERE la.customer_id = ?
    ORDER BY la.id DESC`,
    [customerId]
  );
  res.json(rows);
});

app.get('/api/admin/agent-order-stats', requireAdmin, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;

    // Determine date bounds
    const hasDateFilter = !!startDate || !!endDate;
    let startMs = startDate ? new Date(startDate).getTime() : 0;
    let endMs = endDate ? new Date(endDate).getTime() : Infinity;

    // Extend end date to End of Day if no time is provided
    if (endDate && !endDate.includes('T')) {
      endMs += 24 * 60 * 60 * 1000 - 1;
    }

    // 1. Fetch all agents
    const agents = await db.all("SELECT id, name, email, active FROM users WHERE role = 'agent'");
    const statsMap = {};
    for (const agent of agents) {
      statsMap[agent.id] = {
        ...agent,
        assigned_count: 0,
        mature_count: 0,
        total_revenue: 0
      };
    }

    // 2. Fetch all customers assigned to agents
    const customers = await db.all("SELECT assigned_user_id, mature, mature_at, assigned_at, selected_items_json FROM customers WHERE assigned_user_id IS NOT NULL");

    for (const c of customers) {
      if (!statsMap[c.assigned_user_id]) continue;

      const agentStats = statsMap[c.assigned_user_id];

      // Calculate Assigned Count
      if (hasDateFilter && c.assigned_at) {
        const assignedMs = new Date(c.assigned_at).getTime();
        if (assignedMs >= startMs && assignedMs <= endMs) {
          agentStats.assigned_count++;
        }
      } else if (!hasDateFilter) {
        agentStats.assigned_count++;
      }

      // Calculate Mature Count & Revenue
      if (c.mature === 1) {
        let isMatureInRange = false;
        if (hasDateFilter && c.mature_at) {
          const matureMs = new Date(c.mature_at).getTime();
          if (matureMs >= startMs && matureMs <= endMs) {
            isMatureInRange = true;
          }
        } else if (!hasDateFilter) {
          isMatureInRange = true;
        }

        if (isMatureInRange) {
          agentStats.mature_count++;

          let revenue = 0;
          try {
            // Parse JSON directly and calculate totals
            const items = JSON.parse(c.selected_items_json || '[]');
            for (const item of items) {
              const qty = parseInt(item.qty) || 1;
              const price = parseFloat(item.price) || 0;
              revenue += (price * qty);
            }
          } catch (e) { }

          agentStats.total_revenue += revenue;
        }
      }
    }

    const result = Object.values(statsMap);
    result.sort((a, b) => b.mature_count - a.mature_count || b.assigned_count - a.assigned_count || a.id - b.id);

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/cleanup-leads', requireAdmin, async (req, res) => {
  try {
    const allLeads = await db.all('SELECT id, assigned_user_id, time, assigned_at FROM customers');
    const now = new Date();
    const d = now.getDate();
    const m = now.getMonth() + 1;
    const y = now.getFullYear();
    const todayISO = now.toISOString().split('T')[0];

    const leadsToDelete = allLeads.filter(c => {
      let isToday = false;

      if (c.assigned_at && c.assigned_at.includes(todayISO)) {
        isToday = true;
      }

      if (c.time) {
        const timeStr = c.time.split(',')[0];
        const parts = timeStr.split(/[^0-9]/).filter(Boolean).map(Number);
        if (parts.length >= 3) {
          if ((parts[0] === d && parts[1] === m && parts[2] === y) ||
            (parts[2] === d && parts[1] === m && parts[0] === y)) {
            isToday = true;
          }
        }
      }

      if (c.assigned_at) {
        const datePart = c.assigned_at.split(',')[0];
        const parts = datePart.split(/[^0-9]/).filter(Boolean).map(Number);
        if (parts.length >= 3) {
          if ((parts[0] === d && parts[1] === m && parts[2] === y) ||
            (parts[2] === d && parts[1] === m && parts[0] === y)) {
            isToday = true;
          }
        }
      }

      return !isToday;
    });

    if (leadsToDelete.length > 0) {
      const ids = leadsToDelete.map(l => l.id);
      await db.run(`DELETE FROM customers WHERE id IN(${ids.map(() => '?').join(',')})`, ids);

      for (const lead of leadsToDelete) {
        broadcastCustomerDelete(lead.id, lead.assigned_user_id);
      }
    }

    res.json({ success: true, count: leadsToDelete.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// CUSTOMER ROUTES
// ==========================================
app.get('/api/customers', requireAuth, async (req, res) => {
  const customers = await getCustomersForUser(req.session.user);
  res.json(customers);
});

app.get('/api/customers/paginated', requireAuth, async (req, res) => {
  try {
    const result = await getPaginatedCustomers(req.session.user, req.query);
    res.json(result);
  } catch (err) {
    console.error('Pagination error:', err);
    res.status(500).json({ error: 'Failed to fetch paginated customers' });
  }
});

app.post('/api/customers', requireAuth, async (req, res) => {
  const body = req.body || {};
  const phone = normalizePhone(body.phone || '');
  if (!phone || !body.name) return res.status(400).json({ error: 'Phone and name required' });

  const companyFocus = await getCompanyFocus();
  const selectionType = companyFocus;
  const selectedItems = normalizeSelectedItemsInput(body.selected_items ?? body.items ?? []);
  const selectedItemsJson = JSON.stringify(selectedItems);
  const validItems = await validateSelectedItems(selectedItems, companyFocus);
  if (!validItems) {
    return res.status(400).json({ error: 'Invalid items selection' });
  }

  const { customer: existing } = await resolveCustomerByPhone(phone);

  if (existing) {
    const prevAssignedId = existing.assigned_user_id;

    if (req.session.user.role === 'agent') {
      if (existing.assigned_user_id && existing.assigned_user_id !== req.session.user.id) {
        return res.status(403).json({ error: 'Lead already assigned to another agent' });
      }
      const assignedUserId = existing.assigned_user_id || req.session.user.id;
      await db.run(
        `UPDATE customers
         SET name = ?, address = ?, note = ?, items_json = ?, selected_items_json = ?, selection_type = ?, assigned_user_id = ?
    WHERE id = ? `,
        [
          body.name ?? existing.name,
          body.address ?? existing.address,
          body.note ?? existing.note,
          selectedItemsJson || existing.items_json,
          selectedItemsJson || existing.selected_items_json,
          selectionType,
          assignedUserId,
          existing.id
        ]
      );
      const updated = await db.get('SELECT * FROM customers WHERE id = ?', [existing.id]);
      if (prevAssignedId !== assignedUserId) {
        await logLeadAssignment({
          customerId: existing.id,
          action: 'assign',
          fromUserId: prevAssignedId,
          toUserId: assignedUserId,
          actorUserId: req.session.user.id,
          note: 'agent'
        });
      }
      broadcastCustomerUpdate(mapCustomer(updated), prevAssignedId);
      return res.json({ success: true, customer: mapCustomer(updated), existing: true });
    }

    // admin: optional reassignment if provided
    let assignedUserId = existing.assigned_user_id;
    if (body.assigned_user_id !== undefined && body.assigned_user_id !== null && body.assigned_user_id !== '') {
      const agent = await db.get(
        'SELECT id FROM users WHERE id = ? AND role = ? AND active = 1',
        [body.assigned_user_id, 'agent']
      );
      if (!agent) return res.status(400).json({ error: 'Agent not found' });
      assignedUserId = agent.id;
    }

    await db.run(
      `UPDATE customers
       SET name = ?, address = ?, note = ?, items_json = ?, selected_items_json = ?, selection_type = ?, assigned_user_id = ?
    WHERE id = ? `,
      [
        body.name ?? existing.name,
        body.address ?? existing.address,
        body.note ?? existing.note,
        selectedItemsJson || existing.items_json,
        selectedItemsJson || existing.selected_items_json,
        selectionType,
        assignedUserId,
        existing.id
      ]
    );
    const updated = await db.get('SELECT * FROM customers WHERE id = ?', [existing.id]);
    if (prevAssignedId !== assignedUserId) {
      const action = assignedUserId ? (prevAssignedId ? 'reassign' : 'assign') : 'unassign';
      await logLeadAssignment({
        customerId: existing.id,
        action,
        fromUserId: prevAssignedId,
        toUserId: assignedUserId,
        actorUserId: req.session.user.id,
        note: 'admin'
      });
    }
    broadcastCustomerUpdate(mapCustomer(updated), prevAssignedId);
    return res.json({ success: true, customer: mapCustomer(updated), existing: true });
  }

  let assignedUserId = null;
  if (req.session.user.role === 'agent') {
    assignedUserId = req.session.user.id;
  } else if (req.session.user.role === 'admin' && body.assigned_user_id) {
    const agent = await db.get(
      'SELECT id FROM users WHERE id = ? AND role = ? AND active = 1',
      [body.assigned_user_id, 'agent']
    );
    if (!agent) return res.status(400).json({ error: 'Agent not found' });
    assignedUserId = agent.id;
  }

  const now = new Date().toISOString();
  const result = await db.run(
    `INSERT INTO customers
    (phone, name, address, note, items_json, selected_items_json, selection_type,
      time, lastMessage, lastMessageTime, messageCount, isNew, contacted, source, assigned_user_id, assigned_at)
  VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      phone,
      body.name,
      body.address || '',
      body.note || '',
      selectedItemsJson,
      selectedItemsJson,
      selectionType,
      new Date().toLocaleString('hi-IN'),
      '',
      '',
      0,
      0,
      0,
      'manual',
      assignedUserId,
      assignedUserId ? now : null
    ]
  );
  const created = await db.get('SELECT * FROM customers WHERE id = ?', [result.lastID]);
  if (assignedUserId) {
    await logLeadAssignment({
      customerId: created.id,
      action: 'assign',
      fromUserId: null,
      toUserId: assignedUserId,
      actorUserId: req.session.user.id,
      note: req.session.user.role === 'admin' ? 'admin' : 'agent'
    });
  }
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
  const companyFocus = await getCompanyFocus();
  const hasItems = body.selected_items !== undefined || body.items !== undefined;
  const selectedItems = hasItems ? normalizeSelectedItemsInput(body.selected_items ?? body.items ?? []) : null;
  const selectedItemsJson = selectedItems ? JSON.stringify(selectedItems) : null;
  if (hasItems) {
    const validItems = await validateSelectedItems(selectedItems, companyFocus);
    if (!validItems) return res.status(400).json({ error: 'Invalid items selection' });
  }
  let nextSelectionType = existing.selection_type || companyFocus;
  if (req.session.user.role === 'admin' && body.selection_type) {
    if (!['product', 'service'].includes(body.selection_type)) {
      return res.status(400).json({ error: 'Invalid selection type' });
    }
    nextSelectionType = body.selection_type;
  }
  let requestedAssignedId;
  if (req.session.user.role === 'admin' && body.assigned_user_id !== undefined) {
    if (body.assigned_user_id === null || body.assigned_user_id === '') {
      requestedAssignedId = null;
    } else {
      const agent = await db.get(
        'SELECT id FROM users WHERE id = ? AND role = ? AND active = 1',
        [body.assigned_user_id, 'agent']
      );
      if (!agent) return res.status(400).json({ error: 'Agent not found' });
      requestedAssignedId = agent.id;
    }
  }

  const updated = {
    name: body.name ?? existing.name,
    address: body.address ?? existing.address,
    note: body.note ?? existing.note,
    items_json: hasItems ? selectedItemsJson : existing.items_json,
    selected_items_json: hasItems ? selectedItemsJson : existing.selected_items_json,
    selection_type: nextSelectionType,
    isNew: body.isNew !== undefined ? (body.isNew ? 1 : 0) : existing.isNew,
    contacted: body.contacted !== undefined ? (body.contacted ? 1 : 0) : existing.contacted,
    lastMessage: body.lastMessage ?? existing.lastMessage,
    lastMessageTime: body.lastMessageTime ?? existing.lastMessageTime,
    messageCount: body.messageCount ?? existing.messageCount,
    assigned_user_id: existing.assigned_user_id
  };

  if (requestedAssignedId !== undefined) {
    updated.assigned_user_id = requestedAssignedId;
  }

  const now = new Date().toISOString();
  await db.run(
    `UPDATE customers
     SET name = ?, address = ?, note = ?, items_json = ?, selected_items_json = ?, selection_type = ?, isNew = ?, contacted = ?,
    lastMessage = ?, lastMessageTime = ?, messageCount = ?, assigned_user_id = ?,
    assigned_at = CASE WHEN assigned_user_id != ? THEN ? ELSE assigned_at END
     WHERE id = ? `,
    [
      updated.name,
      updated.address,
      updated.note,
      updated.items_json,
      updated.selected_items_json,
      updated.selection_type,
      updated.isNew,
      updated.contacted,
      updated.lastMessage,
      updated.lastMessageTime,
      updated.messageCount,
      updated.assigned_user_id,
      updated.assigned_user_id,
      now,
      id
    ]
  );

  const row = await db.get('SELECT * FROM customers WHERE id = ?', [id]);
  if (requestedAssignedId !== undefined && prevAssignedId !== updated.assigned_user_id) {
    const action = updated.assigned_user_id
      ? (prevAssignedId ? 'reassign' : 'assign')
      : 'unassign';
    await logLeadAssignment({
      customerId: id,
      action,
      fromUserId: prevAssignedId,
      toUserId: updated.assigned_user_id,
      actorUserId: req.session.user.id,
      note: 'admin-update'
    });
  }
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
  return res.status(400).json({ error: 'Use admin catalog' });
});

app.post('/api/customers/:id/mature', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const existing = await db.get('SELECT * FROM customers WHERE id = ?', [id]);
  if (!existing) return res.status(404).json({ error: 'Customer not found' });

  // Only the assigned agent or an admin can mark as mature
  if (!canUserSeeCustomer(req.session.user, existing)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  if (!existing.name || existing.name.toLowerCase().includes('unknown')) {
    return res.status(400).json({ error: 'Customer Name is required before marking as Order Done' });
  }
  if (!existing.address || existing.address.trim() === '') {
    return res.status(400).json({ error: 'Delivery Address is required before marking as Order Done' });
  }

  const items = getRowItems(existing);
  if (!items || items.length === 0) {
    return res.status(400).json({ error: 'At least one Product must be selected before marking as Order Done' });
  }

  // Keep the endpoint idempotent so repeated clicks/retries don't duplicate orders.
  if (existing.mature) {
    return res.json({ success: true, alreadyMature: true, customer: mapCustomer(existing) });
  }

  const now = new Date().toISOString();
  await db.run('UPDATE customers SET mature = 1, mature_at = ? WHERE id = ?', [now, id]);
  const updated = await db.get('SELECT * FROM customers WHERE id = ?', [id]);

  await logLeadAssignment({
    customerId: id,
    action: 'mature',
    fromUserId: existing.assigned_user_id,
    toUserId: existing.assigned_user_id,
    actorUserId: req.session.user.id,
    note: 'order-mature'
  });

  broadcastCustomerUpdate(mapCustomer(updated), existing.assigned_user_id);
  res.json({ success: true, customer: mapCustomer(updated) });
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
    const rawPhone = req.body.phone;
    const message = req.body.message;
    const phone = normalizePhone(rawPhone || '');
    if (!phone || !message) return res.status(400).json({ error: 'Phone/message required' });

    const { customer } = await resolveCustomerByPhone(phone);
    if (customer && !canUserSeeCustomer(req.session.user, customer)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (!customer && req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const chatId = phone.includes('@c.us') ? phone : `${phone} @c.us`;
    await client.sendMessage(chatId, message);
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
