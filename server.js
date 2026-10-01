// Salah Social — zero-dependency backend (Node 22.13+). Run: node server.js
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const PORT = +process.env.PORT || 3000;
const VERIFY_CODE = process.env.VERIFY_CODE || 'salah2011ss'; // server-side only, set it in .env / host env vars
const DATA = process.env.DATA_DIR || './data';
const PUB = path.resolve('./public');
fs.mkdirSync(path.join(DATA, 'uploads'), { recursive: true });

const db = new DatabaseSync(path.join(DATA, 'salah.db'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE, name TEXT, bio TEXT DEFAULT '', avatar TEXT DEFAULT '', pw TEXT, verified INT DEFAULT 0, created INT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INT, created INT);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, user_id INT, media TEXT, type TEXT, caption TEXT, created INT);
CREATE TABLE IF NOT EXISTS likes(user_id INT, post_id INT, PRIMARY KEY(user_id,post_id));
CREATE TABLE IF NOT EXISTS saves(user_id INT, post_id INT, PRIMARY KEY(user_id,post_id));
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, post_id INT, user_id INT, text TEXT, created INT);
CREATE TABLE IF NOT EXISTS follows(a INT, b INT, PRIMARY KEY(a,b));
CREATE TABLE IF NOT EXISTS stories(id INTEGER PRIMARY KEY, user_id INT, media TEXT, type TEXT, created INT);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, a INT, b INT, text TEXT, created INT);
CREATE TABLE IF NOT EXISTS notifs(id INTEGER PRIMARY KEY, user_id INT, actor INT, type TEXT, post_id INT, created INT, seen INT DEFAULT 0);
CREATE INDEX IF NOT EXISTS i_posts ON posts(user_id,id); CREATE INDEX IF NOT EXISTS i_msg ON messages(a,b);`);

const q = (s, ...p) => db.prepare(s).all(...p);
const one = (s, ...p) => db.prepare(s).get(...p);
const run = (s, ...p) => db.prepare(s).run(...p);
const bad = (s, m) => { throw Object.assign(new Error(m), { status: s }); };
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const pub = u => ({ id: u.id, username: u.username, name: u.name, bio: u.bio, avatar: u.avatar, verified: u.verified });

// ---------- security helpers ----------
const hashPw = pw => { const s = crypto.randomBytes(16); return s.toString('hex') + ':' + crypto.scryptSync(pw, s, 64).toString('hex'); };
const checkPw = (pw, h) => { const [s, k] = h.split(':'); return crypto.timingSafeEqual(crypto.scryptSync(pw, Buffer.from(s, 'hex'), 64), Buffer.from(k, 'hex')); };
const hits = new Map();
const limit = (key, max, ms) => { const n = Date.now(), h = (hits.get(key) || []).filter(t => n - t < ms); h.push(n); hits.set(key, h); if (h.length > max) bad(429, 'محاولات كثيرة، حاول لاحقًا'); };
const ipOf = req => (process.env.TRUST_PROXY && req.headers['x-forwarded-for']?.split(',')[0].trim()) || req.socket.remoteAddress;
function startSession(res, uid) {
  const t = crypto.randomBytes(32).toString('hex');
  run('INSERT INTO sessions VALUES(?,?,?)', sha(t), uid, Date.now());
  res.setHeader('Set-Cookie', `sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
}
const tokenOf = req => /(?:^|; )sid=([a-f0-9]+)/.exec(req.headers.cookie || '')?.[1];
const auth = req => { const t = tokenOf(req); return t ? one('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?', sha(t)) : null; };

// ---------- realtime (SSE) ----------
const streams = new Map();
const push = (uid, ev, data) => streams.get(uid)?.forEach(r => r.write(`event: ${ev}\ndata: ${JSON.stringify(data)}\n\n`));
const notify = (uid, actor, type, postId = null) => {
  if (uid === actor) return;
  run('INSERT INTO notifs(user_id,actor,type,post_id,created) VALUES(?,?,?,?,?)', uid, actor, type, postId, Date.now());
  push(uid, 'notif', {});
};

// ---------- queries ----------
const POST_SQL = `SELECT p.id,p.media,p.type,p.caption,p.created,u.username,u.avatar,u.verified,
 (SELECT COUNT(*) FROM likes WHERE post_id=p.id) likes,(SELECT COUNT(*) FROM comments WHERE post_id=p.id) comments,
 EXISTS(SELECT 1 FROM likes WHERE post_id=p.id AND user_id=?) liked,EXISTS(SELECT 1 FROM saves WHERE post_id=p.id AND user_id=?) saved
 FROM posts p JOIN users u ON u.id=p.user_id `;
const posts = (me, where, ...a) => q(POST_SQL + where, me, me, ...a);
const getPost = (me, id) => posts(me, 'WHERE p.id=?', id)[0] || bad(404, 'غير موجود');
const userByName = n => one('SELECT id,username,name,bio,avatar,verified FROM users WHERE username=?', n) || bad(404, 'المستخدم غير موجود');
const cnt = (s, ...p) => one(s, ...p).c;
const toggle = (table, me, id, notifType, ownerId) => {
  if (one(`SELECT 1 FROM ${table} WHERE user_id=? AND post_id=?`, me.id, id)) run(`DELETE FROM ${table} WHERE user_id=? AND post_id=?`, me.id, id);
  else { run(`INSERT INTO ${table} VALUES(?,?)`, me.id, id); if (notifType) notify(ownerId, me.id, notifType, id); }
  return { post: getPost(me.id, id) };
};

// ---------- routes ----------
const R = [];
const add = (m, p, f) => R.push([m, new RegExp(`^${p}$`), f]);
const MIME = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif', 'video/mp4': 'mp4', 'video/webm': 'webm', 'video/quicktime': 'mov' };
const mediaOk = (u, t) => typeof u === 'string' && /^\/uploads\/[a-f0-9]{32}\.\w+$/.test(u) && ['image', 'video'].includes(t);

add('POST', '/api/register', ({ req, res, body }) => {
  limit(ipOf(req) + 'reg', 10, 600000);
  const u = String(body.username || '').trim().toLowerCase(), pw = String(body.password || '');
  if (!/^[a-z0-9_.]{3,24}$/.test(u)) bad(400, 'اسم المستخدم 3-24 حرفًا إنجليزيًا أو أرقامًا أو _ .');
  if (pw.length < 8 || pw.length > 200) bad(400, 'كلمة المرور 8 أحرف على الأقل');
  if (one('SELECT 1 FROM users WHERE username=?', u)) bad(409, 'اسم المستخدم مستخدم بالفعل');
  const id = run('INSERT INTO users(username,name,pw,created) VALUES(?,?,?,?)', u, String(body.name || u).trim().slice(0, 50) || u, hashPw(pw), Date.now()).lastInsertRowid;
  startSession(res, id); return { ok: 1 };
});
add('POST', '/api/login', ({ req, res, body }) => {
  limit(ipOf(req) + 'login', 10, 600000);
  const u = one('SELECT * FROM users WHERE username=?', String(body.username || '').trim());
  if (!u || !checkPw(String(body.password || ''), u.pw)) bad(401, 'بيانات الدخول غير صحيحة');
  startSession(res, u.id); return { ok: 1 };
});
add('POST', '/api/logout', ({ req, res }) => {
  const t = tokenOf(req); if (t) run('DELETE FROM sessions WHERE token=?', sha(t));
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0'); return { ok: 1 };
});
add('GET', '/api/me', ({ me }) => ({ user: { ...pub(me), unread: cnt('SELECT COUNT(*) c FROM notifs WHERE user_id=? AND seen=0', me.id) } }));
add('PATCH', '/api/me', ({ me, body }) => {
  const avatar = body.avatar === undefined ? me.avatar : (/^\/uploads\/[a-f0-9]{32}\.\w+$/.test(body.avatar) ? body.avatar : bad(400, 'صورة غير صالحة'));
  run('UPDATE users SET name=?,bio=?,avatar=? WHERE id=?', String(body.name ?? me.name).trim().slice(0, 50), String(body.bio ?? '').slice(0, 300), avatar, me.id);
  return { user: pub(one('SELECT * FROM users WHERE id=?', me.id)) };
});
add('POST', '/api/verify', ({ req, me, body }) => {
  limit(ipOf(req) + 'verify' + me.id, 8, 600000);
  const a = Buffer.from(sha(String(body.code || ''))), b = Buffer.from(sha(VERIFY_CODE));
  if (!crypto.timingSafeEqual(a, b)) bad(403, 'كود التوثيق غير صحيح');
  run('UPDATE users SET verified=1 WHERE id=?', me.id);
  return { user: pub(one('SELECT * FROM users WHERE id=?', me.id)) };
});

add('GET', '/api/feed', ({ me }) => ({ posts: posts(me.id, 'WHERE p.user_id=? OR p.user_id IN (SELECT b FROM follows WHERE a=?) ORDER BY p.id DESC LIMIT 50', me.id, me.id) }));
add('GET', '/api/explore', ({ me }) => ({ posts: posts(me.id, 'ORDER BY p.id DESC LIMIT 60') }));
add('GET', '/api/reels', ({ me }) => ({ posts: posts(me.id, "WHERE p.type='video' ORDER BY p.id DESC LIMIT 40") }));
add('GET', '/api/saved', ({ me }) => ({ posts: posts(me.id, 'WHERE p.id IN (SELECT post_id FROM saves WHERE user_id=?) ORDER BY p.id DESC', me.id) }));
add('POST', '/api/posts', ({ me, body }) => {
  if (!mediaOk(body.media, body.type)) bad(400, 'ملف غير صالح');
  const id = run('INSERT INTO posts(user_id,media,type,caption,created) VALUES(?,?,?,?,?)', me.id, body.media, body.type, String(body.caption || '').slice(0, 2000), Date.now()).lastInsertRowid;
  return { post: getPost(me.id, id) };
});
add('GET', '/api/posts/(\\d+)', ({ me, m }) => ({ post: getPost(me.id, +m[1]) }));
add('DELETE', '/api/posts/(\\d+)', ({ me, m }) => {
  const id = +m[1]; if (!one('SELECT 1 FROM posts WHERE id=? AND user_id=?', id, me.id)) bad(403, 'غير مسموح');
  for (const t of ['likes', 'saves', 'comments', 'notifs']) run(`DELETE FROM ${t} WHERE post_id=?`, id);
  run('DELETE FROM posts WHERE id=?', id); return { ok: 1 };
});
add('POST', '/api/posts/(\\d+)/like', ({ me, m }) => toggle('likes', me, +m[1], 'like', getPost(me.id, +m[1]) && one('SELECT user_id FROM posts WHERE id=?', +m[1]).user_id));
add('POST', '/api/posts/(\\d+)/save', ({ me, m }) => (getPost(me.id, +m[1]), toggle('saves', me, +m[1])));
add('GET', '/api/posts/(\\d+)/comments', ({ m }) => ({ comments: q('SELECT c.id,c.text,c.created,u.username,u.avatar,u.verified FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id LIMIT 200', +m[1]) }));
add('POST', '/api/posts/(\\d+)/comments', ({ me, m, body }) => {
  const text = String(body.text || '').trim().slice(0, 500); if (!text) bad(400, 'التعليق فارغ');
  const owner = one('SELECT user_id FROM posts WHERE id=?', +m[1]) || bad(404, 'غير موجود');
  run('INSERT INTO comments(post_id,user_id,text,created) VALUES(?,?,?,?)', +m[1], me.id, text, Date.now());
  notify(owner.user_id, me.id, 'comment', +m[1]); return { ok: 1 };
});

add('GET', '/api/users/([\\w.]+)', ({ me, m }) => {
  const u = userByName(m[1]);
  return { ...u, posts: posts(me.id, 'WHERE p.user_id=? ORDER BY p.id DESC', u.id), postsCount: cnt('SELECT COUNT(*) c FROM posts WHERE user_id=?', u.id),
    followers: cnt('SELECT COUNT(*) c FROM follows WHERE b=?', u.id), following: cnt('SELECT COUNT(*) c FROM follows WHERE a=?', u.id),
    isFollowing: !!one('SELECT 1 FROM follows WHERE a=? AND b=?', me.id, u.id) };
});
add('POST', '/api/users/([\\w.]+)/follow', ({ me, m }) => {
  const u = userByName(m[1]); if (u.id === me.id) bad(400, 'لا يمكنك متابعة نفسك');
  if (one('SELECT 1 FROM follows WHERE a=? AND b=?', me.id, u.id)) run('DELETE FROM follows WHERE a=? AND b=?', me.id, u.id);
  else { run('INSERT INTO follows VALUES(?,?)', me.id, u.id); notify(u.id, me.id, 'follow'); }
  return { ok: 1 };
});
add('GET', '/api/users/([\\w.]+)/follows/(followers|following)', ({ m }) => {
  const u = userByName(m[1]), fr = m[2] === 'followers';
  return { users: q(`SELECT x.id,x.username,x.name,x.avatar,x.verified FROM follows f JOIN users x ON x.id=f.${fr ? 'a' : 'b'} WHERE f.${fr ? 'b' : 'a'}=? LIMIT 200`, u.id) };
});
add('GET', '/api/search', ({ url }) => {
  const s = '%' + (url.searchParams.get('q') || '').replace(/[%_]/g, '').slice(0, 40) + '%';
  return { users: q('SELECT id,username,name,avatar,verified FROM users WHERE username LIKE ? OR name LIKE ? LIMIT 20', s, s) };
});

add('GET', '/api/stories', ({ me }) => ({ stories: q('SELECT s.id,s.media,s.type,s.created,u.username,u.avatar FROM stories s JOIN users u ON u.id=s.user_id WHERE s.created>? AND (s.user_id=? OR s.user_id IN (SELECT b FROM follows WHERE a=?)) ORDER BY s.id', Date.now() - 864e5, me.id, me.id) }));
add('POST', '/api/stories', ({ me, body }) => {
  if (!mediaOk(body.media, body.type)) bad(400, 'ملف غير صالح');
  run('INSERT INTO stories(user_id,media,type,created) VALUES(?,?,?,?)', me.id, body.media, body.type, Date.now()); return { ok: 1 };
});
add('GET', '/api/notifs', ({ me }) => {
  const items = q('SELECT n.type,n.post_id,n.created,u.username,u.avatar FROM notifs n JOIN users u ON u.id=n.actor WHERE n.user_id=? ORDER BY n.id DESC LIMIT 50', me.id);
  run('UPDATE notifs SET seen=1 WHERE user_id=?', me.id); return { items };
});

add('GET', '/api/conversations', ({ me }) => ({ items: q(`SELECT u.username,u.name,u.avatar,u.verified,m.text,m.created FROM messages m
  JOIN users u ON u.id=CASE WHEN m.a=? THEN m.b ELSE m.a END
  WHERE m.id IN (SELECT MAX(id) FROM messages WHERE a=? OR b=? GROUP BY CASE WHEN a=? THEN b ELSE a END) ORDER BY m.id DESC`, me.id, me.id, me.id, me.id) }));
add('GET', '/api/messages/([\\w.]+)', ({ me, m }) => {
  const u = userByName(m[1]);
  return { user: u, items: q('SELECT text,created,a=? mine FROM messages WHERE (a=? AND b=?) OR (a=? AND b=?) ORDER BY id DESC LIMIT 200', me.id, me.id, u.id, u.id, me.id).reverse() };
});
add('POST', '/api/messages/([\\w.]+)', ({ me, m, body }) => {
  const u = userByName(m[1]), text = String(body.text || '').trim().slice(0, 2000); if (!text) bad(400, 'الرسالة فارغة');
  run('INSERT INTO messages(a,b,text,created) VALUES(?,?,?,?)', me.id, u.id, text, Date.now());
  push(u.id, 'msg', { with: me.username, from: me.username }); push(me.id, 'msg', { with: u.username, from: me.username });
  return { ok: 1 };
});

// ---------- http ----------
const readBody = (req, max) => new Promise((ok, no) => {
  let n = 0; const c = [];
  req.on('data', d => { n += d.length; if (n > max) { no(Object.assign(new Error('الملف كبير جدًا'), { status: 413 })); req.destroy(); } else c.push(d); });
  req.on('end', () => ok(Buffer.concat(c))); req.on('error', no);
});
const json = (res, o, s = 200) => { res.writeHead(s, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(o)); };

async function handleApi(req, res, p, url) {
  if (req.method !== 'GET') { const o = req.headers.origin; if (o && new URL(o).host !== req.headers.host) bad(403, 'Forbidden'); }
  const me = auth(req);
  if (!me && !['/api/login', '/api/register'].includes(p)) bad(401, 'سجّل الدخول أولًا');
  if (p === '/api/stream') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' }); res.write(':ok\n\n');
    const s = streams.get(me.id) || new Set(); s.add(res); streams.set(me.id, s);
    const ka = setInterval(() => res.write(':\n\n'), 25000);
    req.on('close', () => { clearInterval(ka); s.delete(res); }); return;
  }
  if (p === '/api/upload' && req.method === 'POST') {
    const ext = MIME[(req.headers['content-type'] || '').split(';')[0]]; if (!ext) bad(415, 'نوع الملف غير مدعوم');
    const buf = await readBody(req, 60e6), name = crypto.randomBytes(16).toString('hex') + '.' + ext;
    fs.writeFileSync(path.join(DATA, 'uploads', name), buf);
    return json(res, { url: '/uploads/' + name, type: ['mp4', 'webm', 'mov'].includes(ext) ? 'video' : 'image' });
  }
  for (const [m, re, f] of R) {
    if (m !== req.method) continue; const mm = re.exec(p); if (!mm) continue;
    const body = m === 'GET' || m === 'DELETE' ? {} : JSON.parse((await readBody(req, 1e6)).toString() || '{}');
    return json(res, await f({ me, body, res, req, m: mm, url }));
  }
  bad(404, 'Not found');
}

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.jpg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.gif': 'image/gif', '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime' };
function serve(req, res, p) {
  const up = p.startsWith('/uploads/');
  const file = up ? path.join(DATA, 'uploads', path.basename(p)) : path.join(PUB, p === '/' ? 'index.html' : p);
  if (!up && !path.resolve(file).startsWith(PUB)) return json(res, { error: 'Forbidden' }, 403);
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) return json(res, { error: 'Not found' }, 404);
  const st = fs.statSync(file), ext = path.extname(file);
  res.setHeader('Content-Type', TYPES[ext] || 'application/octet-stream'); res.setHeader('Accept-Ranges', 'bytes');
  if (up) res.setHeader('Cache-Control', 'public,max-age=31536000,immutable');
  const r = /bytes=(\d*)-(\d*)/.exec(req.headers.range || '');
  if (r) {
    const s = +r[1] || 0, e = r[2] ? Math.min(+r[2], st.size - 1) : st.size - 1;
    res.writeHead(206, { 'Content-Range': `bytes ${s}-${e}/${st.size}`, 'Content-Length': e - s + 1 }); fs.createReadStream(file, { start: s, end: e }).pipe(res);
  } else { res.setHeader('Content-Length', st.size); fs.createReadStream(file).pipe(res); }
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x'), p = decodeURIComponent(url.pathname);
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'");
    if (p.startsWith('/api/')) await handleApi(req, res, p, url); else serve(req, res, p);
  } catch (e) {
    const s = e.status || (e instanceof SyntaxError ? 400 : 500); if (s === 500) console.error(e);
    if (!res.headersSent) json(res, { error: s === 500 ? 'خطأ في الخادم' : e.message }, s);
  }
}).listen(PORT, '0.0.0.0', () => console.log(`Salah Social → http://0.0.0.0:${PORT}`));
