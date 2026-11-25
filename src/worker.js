/* Patch Plan — online projects (Cloudflare Worker + one Durable Object "room" per project).
 *
 *   /            -> the editor (static file in ./public)
 *   /api/p/<id>/info      GET   project exists? + name                (no password)
 *   /api/p/<id>/create    POST  {name, password, viewPassword?, doc} (OWNER) -> {token, ver}
 *   /api/p/<id>/login     POST  {password}             -> {token, name, role}   role = 'edit' | 'view'
 *   /api/p/<id>/doc       GET   (token)                -> {doc, ver, name, role, hasView}
 *   /api/p/<id>/changes   GET   ?since=ver (token)     -> {ver, changes:[{coll,id,after,ver,by}]}
 *   /api/p/<id>/changes   POST  {client, changes:[{coll,id,after}]} (token) -> {ver}
 *   /api/p/<id>/password  POST  {password?, viewPassword?, removeView?, client} (OWNER) -> {token}
 *                         (a new edit password signs out the editors, a new view password the viewers)
 *   /api/p/<id>/delete    POST  (OWNER)                -> {ok}      (removes the online project)
 *   /api/owner/check      GET   (OWNER)                -> {ok}
 *   /api/owner/projects   GET   (OWNER)                -> {projects:[{id,name,created}]}
 *
 * OWNER = request carries the header x-owner-key matching the Worker secret OWNER_KEY.
 * Only the owner can create projects, change their passwords, delete them and list them;
 * the owner can also open any project without its password. Everyone else needs the
 * project password and can only open and edit the plan. A project can also have a second,
 * VIEW-ONLY password: people who log in with it see the plan (live) but every write is refused.
 *   /api/p/<id>/live      WebSocket: first message {type:'hello', token, client, name, color};
 *                         then the room pushes 'changes' / 'poke' / 'presence' / 'sel' messages.
 *
 * Passwords: PBKDF2-SHA256 (100k iterations, random salt), never stored in clear text.
 * Wrong passwords: after 5 misses the project waits 10 s, then 20 s, 40 s … up to 15 min.
 * Sessions: random token, only its SHA-256 is stored; valid 30 days.
 * The plan is stored item by item (device, cable, …); big items are split into chunks.
 * WebSockets use the hibernation API, so an idle room costs (almost) nothing.
 */
import { DurableObject } from 'cloudflare:workers';

const CORS = {
  'access-control-allow-origin': '*',            // the token travels in a header, never in cookies
  'access-control-allow-headers': 'content-type, authorization, x-owner-key',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-max-age': '86400',
};
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...CORS } });
const ID_RX = /^[a-z0-9][a-z0-9-]{2,63}$/;
const COLLS = new Set(['meta', 'layers', 'devices', 'cables', 'annotations', 'backgrounds']);
const CHUNK = 500_000;                 // characters per stored piece
const MAX_PROJECT = 80_000_000;        // ~80 MB per project: warn (protects the free storage quota)
const PUSH_INLINE = 200_000;           // live messages bigger than this become a 'poke' (clients fetch)
const SESSION_DAYS = 30;

/** Owner = the request carries the owner key (Worker secret OWNER_KEY). No secret set = nobody is owner. */
async function isOwner(req, env) {
  const k = req.headers.get('x-owner-key') || '';
  if (!env.OWNER_KEY || !k || k.length > 200) return false;
  const [a, b] = await Promise.all([sha256(k), sha256(env.OWNER_KEY)]);
  return a === b;
}
const registry = env => env.REG.get(env.REG.idFromName('registry'));

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const owner = await isOwner(req, env);
    if (url.pathname === '/api/owner/check') return owner ? json({ ok: true }) : json({ error: 'That is not the owner key' }, 403);
    if (url.pathname === '/api/owner/projects') return owner ? registry(env).fetch('https://reg/list') : json({ error: 'Owner only' }, 403);
    const m = url.pathname.match(/^\/api\/p\/([^/]+)\/(info|create|login|doc|changes|password|delete|live)$/);
    if (!m) return json({ error: 'Not found' }, 404);
    const [, id, action] = m;
    if (!ID_RX.test(id)) return json({ error: 'Invalid project id' }, 400);
    const room = env.ROOMS.get(env.ROOMS.idFromName(id));
    if (action === 'live') return room.fetch(new Request('https://room/live', { headers: req.headers }));
    // the room trusts only this header, which only the Worker can set
    const headers = new Headers(req.headers); headers.delete('x-owner'); if (owner) headers.set('x-owner', '1');
    const res = await room.fetch(new Request(`https://room/${action}${url.search}`, { method: req.method, headers, body: req.method === 'GET' ? null : req.body }));
    if (res.ok && action === 'create') { const r = await res.clone().json(); await registry(env).fetch('https://reg/add', { method: 'POST', body: JSON.stringify({ id, name: r.name }) }); }
    if (res.ok && action === 'delete') await registry(env).fetch('https://reg/remove', { method: 'POST', body: JSON.stringify({ id }) });
    return res;
  },
};

/** List of the online projects (for the owner). */
export class Registry extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec('CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, name TEXT, created TEXT)');
  }
  async fetch(req) {
    const a = new URL(req.url).pathname.slice(1);
    if (a === 'list') return json({ projects: this.sql.exec('SELECT id, name, created FROM projects ORDER BY created DESC').toArray() });
    const b = await req.json();
    if (a === 'add') this.sql.exec('INSERT OR REPLACE INTO projects (id, name, created) VALUES (?, ?, ?)', String(b.id), String(b.name || ''), new Date().toISOString());
    if (a === 'remove') this.sql.exec('DELETE FROM projects WHERE id = ?', String(b.id));
    return json({ ok: true });
  }
}

/* ---------- helpers ---------- */
const enc = new TextEncoder();
const b64 = u8 => btoa(String.fromCharCode(...u8));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
async function pbkdf2(password, salt) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100_000 }, key, 256));
}
const sha256 = async s => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s))));
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  return crypto.subtle.timingSafeEqual ? crypto.subtle.timingSafeEqual(a, b) : a.every((v, i) => v === b[i]);
}
const pwOk = p => typeof p === 'string' && p.length >= 6 && p.length <= 200;
const clean = (s, n) => String(s ?? '').replace(/[\u0000-\u001f]/g, '').slice(0, n);

export class ProjectRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.init();
    // keep-alive pings are answered without waking the room
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }
  /** Tables (again after a delete, which removes everything). */
  init() {
    this.sql.exec('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS ent (coll TEXT, id TEXT, ver INTEGER, del INTEGER, by TEXT, PRIMARY KEY (coll, id))');
    this.sql.exec('CREATE INDEX IF NOT EXISTS ent_ver ON ent (ver)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS chunk (coll TEXT, id TEXT, seq INTEGER, data TEXT, PRIMARY KEY (coll, id, seq))');
    this.sql.exec("CREATE TABLE IF NOT EXISTS sess (tok TEXT PRIMARY KEY, exp INTEGER, role TEXT DEFAULT 'edit')");
    if (!this.sql.exec('PRAGMA table_info(sess)').toArray().some(c => c.name === 'role')) this.sql.exec("ALTER TABLE sess ADD COLUMN role TEXT DEFAULT 'edit'");
  }
  get hasView() { return !!this.get('vhash'); }
  get(k) { return this.sql.exec('SELECT v FROM meta WHERE k = ?', k).toArray()[0]?.v ?? null; }
  set(k, v) { this.sql.exec('INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)', k, String(v)); }
  get exists() { return this.get('hash') != null; }
  get ver() { return +(this.get('ver') || 0); }

  async fetch(req) {
    const url = new URL(req.url), action = url.pathname.slice(1), owner = req.headers.get('x-owner') === '1';
    try {
      if (action === 'live') return this.live(req);
      if (action === 'info') return json({ exists: this.exists, name: this.exists ? this.get('name') : null });
      if (action === 'create' && req.method === 'POST') return owner ? await this.create(await req.json()) : json({ error: 'Only the owner can put projects online' }, 403);
      if (action === 'login' && req.method === 'POST') return await this.login(await req.json(), owner);
      if (!this.exists) return json({ error: 'This online project does not exist' }, 404);
      if (action === 'delete' && req.method === 'POST') return owner ? await this.remove() : json({ error: 'Only the owner can delete a project' }, 403);
      if (action === 'password' && req.method === 'POST') return owner ? await this.changePassword(await req.json()) : json({ error: 'Only the owner can change the project password' }, 403);
      const role = await this.tokenOk((req.headers.get('authorization') || '').replace(/^Bearer\s+/i, ''));
      if (!role) return json({ error: 'Password needed', auth: true }, 401);
      if (action === 'doc' && req.method === 'GET') return json({ doc: this.readDoc(), ver: this.ver, name: this.get('name'), role, hasView: this.hasView });
      if (action === 'changes' && req.method === 'GET') return json({ ...this.since(+url.searchParams.get('since') || 0), role });
      if (action === 'changes' && req.method === 'POST') return role === 'edit' ? this.write(await req.json()) : json({ error: 'View only — you cannot change this project', viewOnly: true }, 403);
      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: 'Server error: ' + (e?.message || e) }, 500);
    }
  }

  /* ----- passwords & sessions ----- */
  /** role 'edit' = the project password, 'view' = the view-only password. Signs out the sessions of that role. */
  async setPassword(password, role = 'edit') {
    const salt = crypto.getRandomValues(new Uint8Array(16)), p = role === 'view' ? 'v' : '';
    this.set(p + 'salt', b64(salt)); this.set(p + 'hash', b64(await pbkdf2(password, salt)));
    this.sql.exec('DELETE FROM sess WHERE role = ?', role);
  }
  async newToken(role = 'edit') {
    const tok = hex(crypto.getRandomValues(new Uint8Array(32)));
    this.sql.exec('INSERT INTO sess (tok, exp, role) VALUES (?, ?, ?)', await sha256(tok), Date.now() + SESSION_DAYS * 864e5, role);
    return tok;
  }
  /** The session's role ('edit' | 'view'), or null when the token is not valid. */
  async tokenOk(tok) {
    if (!/^[0-9a-f]{64}$/.test(tok || '')) return null;
    const h = await sha256(tok), row = this.sql.exec('SELECT exp, role FROM sess WHERE tok = ?', h).toArray()[0];
    if (!row || row.exp < Date.now()) return null;
    if (row.exp - Date.now() < (SESSION_DAYS - 1) * 864e5) this.sql.exec('UPDATE sess SET exp = ? WHERE tok = ?', Date.now() + SESSION_DAYS * 864e5, h);   // sliding expiry
    return row.role === 'view' ? 'view' : 'edit';
  }
  async matches(password, role) {
    const p = role === 'view' ? 'v' : '';
    if (typeof password !== 'string' || !this.get(p + 'hash')) return false;
    return sameBytes(await pbkdf2(password, unb64(this.get(p + 'salt'))), unb64(this.get(p + 'hash')));
  }
  /** Password check with the wrong-password back-off. Returns {role} when ok, else {res: error Response}. */
  async verifyPassword(password) {
    const now = Date.now(), until = +(this.get('lockUntil') || 0);
    if (now < until) return { res: json({ error: 'Too many wrong passwords — try again in a moment', retryAfter: Math.ceil((until - now) / 1000) }, 429) };
    const role = (await this.matches(password, 'edit')) ? 'edit' : this.hasView && (await this.matches(password, 'view')) ? 'view' : null;
    if (!role) {
      const fails = +(this.get('fails') || 0) + 1; this.set('fails', fails);
      if (fails >= 5) { const wait = Math.min(900, 10 * 2 ** (fails - 5)); this.set('lockUntil', now + wait * 1000); return { res: json({ error: `Wrong password — wait ${wait} s before trying again`, retryAfter: wait }, 429) }; }
      return { res: json({ error: 'Wrong password' }, 401) };
    }
    this.set('fails', 0); this.set('lockUntil', 0);
    return { role };
  }
  async create(b) {
    if (this.exists) return json({ error: 'A project with this id already exists' }, 409);
    if (!pwOk(b.password)) return json({ error: 'The password needs at least 6 characters' }, 400);
    if (b.viewPassword && !pwOk(b.viewPassword)) return json({ error: 'The view-only password needs at least 6 characters' }, 400);
    if (b.viewPassword && b.viewPassword === b.password) return json({ error: 'The view-only password must be different from the edit password' }, 400);
    const name = clean(b.name || 'Untitled show', 120);
    await this.setPassword(b.password);
    if (b.viewPassword) await this.setPassword(b.viewPassword, 'view');
    this.set('name', name); this.set('created', new Date().toISOString()); this.set('ver', 0); this.set('fails', 0);
    if (b.doc && typeof b.doc === 'object') {
      const changes = [];
      for (const coll of COLLS) for (const [id, after] of Object.entries(b.doc[coll] || {})) changes.push({ coll, id, after });
      const r = this.apply(changes, 'creator'); if (r.error) { await this.ctx.storage.deleteAll(); this.init(); return json(r, r.status); }
    }
    return json({ token: await this.newToken(), ver: this.ver, name });
  }
  async login(b, owner) {
    if (!this.exists) return json({ error: 'This online project does not exist' }, 404);
    let role = 'edit';   // the owner opens any project, always as editor
    if (!owner) { const v = await this.verifyPassword(b.password); if (v.res) return v.res; role = v.role; }
    this.sql.exec('DELETE FROM sess WHERE exp < ?', Date.now());
    return json({ token: await this.newToken(role), name: this.get('name'), role });
  }
  async changePassword(b) {
    const pw = b.password || '', vpw = b.viewPassword || '';
    if (!pw && !vpw && !b.removeView) return json({ error: 'Nothing to change' }, 400);
    if (pw && !pwOk(pw)) return json({ error: 'The password needs at least 6 characters' }, 400);
    if (vpw && !pwOk(vpw)) return json({ error: 'The view-only password needs at least 6 characters' }, 400);
    if (vpw && (vpw === pw || (!pw && await this.matches(vpw, 'edit')))) return json({ error: 'The view-only password must be different from the edit password' }, 400);
    if (pw && !vpw && !b.removeView && await this.matches(pw, 'view')) return json({ error: 'The edit password must be different from the view-only password' }, 400);
    const out = new Set();
    if (pw) { await this.setPassword(pw, 'edit'); out.add('edit'); }
    if (vpw) { await this.setPassword(vpw, 'view'); out.add('view'); }
    else if (b.removeView && this.hasView) { this.set('vhash', ''); this.set('vsalt', ''); this.sql.exec("DELETE FROM sess WHERE role = 'view'"); out.add('view'); }
    const client = clean(b.client, 40);
    for (const ws of this.ctx.getWebSockets()) { const a = ws.deserializeAttachment(); if (a?.client !== client && out.has(a?.role || 'edit')) try { ws.close(4001, 'Password changed'); } catch {} }
    return json({ token: await this.newToken('edit'), hasView: this.hasView });
  }
  async remove() {
    for (const ws of this.ctx.getWebSockets()) try { ws.close(4004, 'Project deleted'); } catch {}
    await this.ctx.storage.deleteAll(); this.init();
    return json({ ok: true });
  }

  /* ----- the plan, item by item ----- */
  readItem(coll, id) {
    const parts = this.sql.exec('SELECT data FROM chunk WHERE coll = ? AND id = ? ORDER BY seq', coll, id).toArray();
    return parts.length ? JSON.parse(parts.map(p => p.data).join('')) : null;
  }
  readDoc() {
    const doc = {}; for (const c of COLLS) doc[c] = {};
    for (const r of this.sql.exec('SELECT coll, id FROM ent WHERE del = 0').toArray()) { const v = this.readItem(r.coll, r.id); if (v != null) doc[r.coll][r.id] = v; }
    return doc;
  }
  since(v) {
    const rows = this.sql.exec('SELECT coll, id, ver, del, by FROM ent WHERE ver > ? ORDER BY ver', v).toArray();
    return { ver: this.ver, changes: rows.map(r => ({ coll: r.coll, id: r.id, ver: r.ver, by: r.by, after: r.del ? null : this.readItem(r.coll, r.id) })) };
  }
  write(b) {
    const by = clean(b.client, 40), changes = Array.isArray(b.changes) ? b.changes : [];
    const r = this.apply(changes, by);
    if (r.error) return json(r, r.status);
    // tell everyone who is connected; big payloads (images) only as a 'poke' so they fetch it
    const msg = { type: 'changes', base: r.ver - 1, ver: r.ver, by, changes: changes.map(c => ({ coll: c.coll, id: c.id, after: c.after ?? null, ver: r.ver, by })) };
    let s = JSON.stringify(msg);
    if (s.length > PUSH_INLINE) s = JSON.stringify({ type: 'poke', base: r.ver - 1, ver: r.ver, by });
    this.broadcast(s);
    return json(r);
  }
  apply(changes, by) {
    for (const c of changes) if (!COLLS.has(c.coll) || typeof c.id !== 'string' || !c.id || c.id.length > 100) return { error: 'Invalid change', status: 400 };
    const ver = this.ver + 1;
    this.ctx.storage.transactionSync(() => {
      for (const c of changes) {
        this.sql.exec('DELETE FROM chunk WHERE coll = ? AND id = ?', c.coll, c.id);
        if (c.after == null) { this.sql.exec('INSERT OR REPLACE INTO ent (coll, id, ver, del, by) VALUES (?, ?, ?, 1, ?)', c.coll, c.id, ver, by); continue; }
        const s = JSON.stringify(c.after);
        for (let i = 0, seq = 0; i < s.length; i += CHUNK, seq++) this.sql.exec('INSERT INTO chunk (coll, id, seq, data) VALUES (?, ?, ?, ?)', c.coll, c.id, seq, s.slice(i, i + CHUNK));
        this.sql.exec('INSERT OR REPLACE INTO ent (coll, id, ver, del, by) VALUES (?, ?, ?, 0, ?)', c.coll, c.id, ver, by);
      }
      this.set('ver', ver);
    });
    const size = this.sql.exec('SELECT COALESCE(SUM(LENGTH(data)), 0) AS n FROM chunk').toArray()[0].n;
    return { ver, size, warn: size > MAX_PROJECT ? 'This project is very large; remove big background images to keep it fast' : undefined };
  }

  /* ----- live connections ----- */
  live(req) {
    if (req.headers.get('upgrade')?.toLowerCase() !== 'websocket') return json({ error: 'WebSocket expected' }, 426);
    const pair = new WebSocketPair(), [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ auth: false });
    if (!this.exists) server.close(4004, 'Project not found');
    return new Response(null, { status: 101, webSocket: client });
  }
  people(except) {
    return this.ctx.getWebSockets().filter(ws => ws !== except).map(ws => ws.deserializeAttachment()).filter(a => a?.auth)
      .map(({ client, name, color, sel, role }) => ({ client, name, color, sel, view: role === 'view' }));
  }
  broadcast(s, except) {
    for (const ws of this.ctx.getWebSockets()) if (ws !== except && ws.deserializeAttachment()?.auth) try { ws.send(s); } catch {}
  }
  async webSocketMessage(ws, data) {
    if (typeof data !== 'string' || data.length > 20_000) return;
    let m; try { m = JSON.parse(data); } catch { return; }
    const a = ws.deserializeAttachment() || {};
    if (!a.auth) {
      const role = m.type === 'hello' && this.exists ? await this.tokenOk(m.token) : null;
      if (!role) { try { ws.close(this.exists ? 4001 : 4004, 'Password needed'); } catch {} return; }
      const me = { auth: true, role, client: clean(m.client, 40), name: clean(m.name, 40) || 'Guest', color: /^#[0-9a-f]{6}$/i.test(m.color) ? m.color : '#888888', sel: [] };
      ws.serializeAttachment(me);
      ws.send(JSON.stringify({ type: 'welcome', ver: this.ver, people: this.people() }));
      this.broadcast(JSON.stringify({ type: 'presence', people: this.people(), joined: me.name }), ws);
      return;
    }
    if (m.type === 'sel') {
      a.sel = (Array.isArray(m.ids) ? m.ids : []).slice(0, 300).map(x => clean(x, 100)); ws.serializeAttachment(a);
      this.broadcast(JSON.stringify({ type: 'sel', client: a.client, ids: a.sel }), ws);
    } else if (m.type === 'name') {
      a.name = clean(m.name, 40) || a.name; if (/^#[0-9a-f]{6}$/i.test(m.color)) a.color = m.color; ws.serializeAttachment(a);
      this.broadcast(JSON.stringify({ type: 'presence', people: this.people() }));
    }
  }
  async webSocketClose(ws) { this.left(ws); }
  async webSocketError(ws) { this.left(ws); }
  left(ws) {
    const a = ws.deserializeAttachment();
    try { ws.close(); } catch {}
    if (a?.auth) this.broadcast(JSON.stringify({ type: 'presence', people: this.people(ws), left: a.name }), ws);
  }
}
