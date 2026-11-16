/* Patch Plan — online projects (Cloudflare Worker + one Durable Object "room" per project).
 *
 *   /            -> the editor (static file in ./public)
 *   /api/p/<id>/info      GET   project exists? + name                (no password)
 *   /api/p/<id>/create    POST  {name, password, doc}  -> {token, ver}
 *   /api/p/<id>/login     POST  {password}             -> {token, name}
 *   /api/p/<id>/doc       GET   (token)                -> {doc, ver, name}
 *   /api/p/<id>/changes   GET   ?since=ver (token)     -> {ver, changes:[{coll,id,after,ver,by}]}
 *   /api/p/<id>/changes   POST  {client, changes:[{coll,id,after}]} (token) -> {ver}
 *   /api/p/<id>/password  POST  {password} (token)     -> {token}   (signs everyone else out)
 *
 * Passwords: PBKDF2-SHA256 (100k iterations, random salt), never stored in clear text.
 * Wrong passwords: after 5 misses the project waits 10 s, then 20 s, 40 s … up to 15 min.
 * Sessions: random token, only its SHA-256 is stored; valid 30 days.
 * The plan is stored item by item (device, cable, …) so a save only sends what changed;
 * big items (background images, fonts) are split into chunks.
 */
import { DurableObject } from 'cloudflare:workers';

const CORS = {
  'access-control-allow-origin': '*',            // the token travels in a header, never in cookies
  'access-control-allow-headers': 'content-type, authorization',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-max-age': '86400',
};
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...CORS } });
const ID_RX = /^[a-z0-9][a-z0-9-]{2,63}$/;
const COLLS = new Set(['meta', 'layers', 'devices', 'cables', 'annotations', 'backgrounds']);
const CHUNK = 500_000;                 // characters per stored piece
const MAX_PROJECT = 80_000_000;        // ~80 MB per project, protects the free storage quota
const SESSION_DAYS = 30;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const m = url.pathname.match(/^\/api\/p\/([^/]+)\/(info|create|login|doc|changes|password)$/);
    if (!m) return json({ error: 'Not found' }, 404);
    const [, id, action] = m;
    if (!ID_RX.test(id)) return json({ error: 'Invalid project id' }, 400);
    const room = env.ROOMS.get(env.ROOMS.idFromName(id));
    return room.fetch(new Request(`https://room/${action}${url.search}`, req));
  },
};

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

export class ProjectRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS ent (coll TEXT, id TEXT, ver INTEGER, del INTEGER, by TEXT, PRIMARY KEY (coll, id))');
    this.sql.exec('CREATE INDEX IF NOT EXISTS ent_ver ON ent (ver)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS chunk (coll TEXT, id TEXT, seq INTEGER, data TEXT, PRIMARY KEY (coll, id, seq))');
    this.sql.exec('CREATE TABLE IF NOT EXISTS sess (tok TEXT PRIMARY KEY, exp INTEGER)');
  }
  get(k) { return this.sql.exec('SELECT v FROM meta WHERE k = ?', k).toArray()[0]?.v ?? null; }
  set(k, v) { this.sql.exec('INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)', k, String(v)); }
  get exists() { return this.get('hash') != null; }
  get ver() { return +(this.get('ver') || 0); }

  async fetch(req) {
    const url = new URL(req.url), action = url.pathname.slice(1);
    try {
      if (action === 'info') return json({ exists: this.exists, name: this.exists ? this.get('name') : null });
      if (action === 'create' && req.method === 'POST') return await this.create(await req.json());
      if (action === 'login' && req.method === 'POST') return await this.login(await req.json());
      if (!this.exists) return json({ error: 'This online project does not exist' }, 404);
      if (!(await this.checkToken(req))) return json({ error: 'Password needed', auth: true }, 401);
      if (action === 'doc' && req.method === 'GET') return json({ doc: this.readDoc(), ver: this.ver, name: this.get('name') });
      if (action === 'changes' && req.method === 'GET') return json(this.since(+url.searchParams.get('since') || 0));
      if (action === 'changes' && req.method === 'POST') return this.write(await req.json());
      if (action === 'password' && req.method === 'POST') return await this.changePassword(await req.json());
      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: 'Server error: ' + (e?.message || e) }, 500);
    }
  }

  /* ----- passwords & sessions ----- */
  async setPassword(password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    this.set('salt', b64(salt)); this.set('hash', b64(await pbkdf2(password, salt)));
    this.sql.exec('DELETE FROM sess');
  }
  async newToken() {
    const tok = hex(crypto.getRandomValues(new Uint8Array(32)));
    this.sql.exec('INSERT INTO sess (tok, exp) VALUES (?, ?)', await sha256(tok), Date.now() + SESSION_DAYS * 864e5);
    return tok;
  }
  async checkToken(req) {
    const tok = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
    if (!/^[0-9a-f]{64}$/.test(tok)) return false;
    const h = await sha256(tok), row = this.sql.exec('SELECT exp FROM sess WHERE tok = ?', h).toArray()[0];
    if (!row || row.exp < Date.now()) return false;
    if (row.exp - Date.now() < (SESSION_DAYS - 1) * 864e5) this.sql.exec('UPDATE sess SET exp = ? WHERE tok = ?', Date.now() + SESSION_DAYS * 864e5, h);   // sliding expiry
    return true;
  }
  async create(b) {
    if (this.exists) return json({ error: 'A project with this id already exists' }, 409);
    if (!pwOk(b.password)) return json({ error: 'The password needs at least 6 characters' }, 400);
    const name = String(b.name || 'Untitled show').slice(0, 120);
    await this.setPassword(b.password);
    this.set('name', name); this.set('created', new Date().toISOString()); this.set('ver', 0); this.set('fails', 0);
    if (b.doc && typeof b.doc === 'object') {
      const changes = [];
      for (const coll of COLLS) for (const [id, after] of Object.entries(b.doc[coll] || {})) changes.push({ coll, id, after });
      const r = this.apply(changes, 'creator'); if (r.error) { this.ctx.storage.deleteAll(); return json(r, r.status); }
    }
    return json({ token: await this.newToken(), ver: this.ver, name });
  }
  async login(b) {
    if (!this.exists) return json({ error: 'This online project does not exist' }, 404);
    const now = Date.now(), until = +(this.get('lockUntil') || 0);
    if (now < until) return json({ error: 'Too many wrong passwords — try again in a moment', retryAfter: Math.ceil((until - now) / 1000) }, 429);
    const ok = typeof b.password === 'string' && sameBytes(await pbkdf2(b.password, unb64(this.get('salt'))), unb64(this.get('hash')));
    if (!ok) {
      const fails = +(this.get('fails') || 0) + 1; this.set('fails', fails);
      if (fails >= 5) { const wait = Math.min(900, 10 * 2 ** (fails - 5)); this.set('lockUntil', now + wait * 1000); return json({ error: `Wrong password — wait ${wait} s before trying again`, retryAfter: wait }, 429); }
      return json({ error: 'Wrong password' }, 401);
    }
    this.set('fails', 0); this.set('lockUntil', 0);
    this.sql.exec('DELETE FROM sess WHERE exp < ?', now);
    return json({ token: await this.newToken(), name: this.get('name') });
  }
  async changePassword(b) {
    if (!pwOk(b.password)) return json({ error: 'The password needs at least 6 characters' }, 400);
    await this.setPassword(b.password);
    return json({ token: await this.newToken() });
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
    const r = this.apply(Array.isArray(b.changes) ? b.changes : [], String(b.client || '').slice(0, 40));
    return r.error ? json(r, r.status) : json(r);
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
}
