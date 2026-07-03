// ═══════════════════════════════════════════════════════════════
// MeuSacoTools — server.js
// Node 18+ · Express · PostgreSQL (Railway) · B2/R2 via S3 API · Meta Graph API
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const PORT = process.env.PORT || 3000;
const TZ = process.env.TZ || 'America/Sao_Paulo';
const GRAPH = 'https://graph.facebook.com/v19.0';
const APP_URL = (process.env.APP_URL || '').replace(/\/$/, '');

if (!process.env.DATABASE_URL) { console.error('❌ DATABASE_URL não definida'); process.exit(1); }

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes('railway.internal') || process.env.PGSSLMODE === 'disable'
    ? false : { rejectUnauthorized: false }
});
const q = (text, params) => pool.query(text, params);
const uid = () => crypto.randomUUID();
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ─── MIGRAÇÕES (rodam automaticamente no boot) ──────────────────
async function migrate() {
  await q(`CREATE TABLE IF NOT EXISTS users(
    id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
    status TEXT NOT NULL DEFAULT 'active', plan TEXT NOT NULL DEFAULT 'free',
    login_count INT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS sessions(
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL)`);
  await q(`CREATE TABLE IF NOT EXISTS categories(
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL, color TEXT NOT NULL DEFAULT '#7c5cff')`);
  await q(`CREATE TABLE IF NOT EXISTS accounts(
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username TEXT, label TEXT, ig_user_id TEXT, access_token TEXT,
    category_id TEXT, posts_per_day INT NOT NULL DEFAULT 40,
    start_time TEXT NOT NULL DEFAULT '02:00', end_time TEXT NOT NULL DEFAULT '23:00',
    interval_mode TEXT NOT NULL DEFAULT 'inteligente',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS videos(
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    batch_id TEXT, original_name TEXT NOT NULL, key TEXT, b2_url TEXT,
    bytes BIGINT DEFAULT 0, caption TEXT DEFAULT '', hashtags TEXT DEFAULT '',
    cycle INT NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'pendente',
    error_msg TEXT, scheduled_for TIMESTAMPTZ, posted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await q(`CREATE INDEX IF NOT EXISTS idx_videos_due ON videos(status, scheduled_for)`);
  await q(`CREATE TABLE IF NOT EXISTS captions(
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    data JSONB NOT NULL DEFAULT '[]')`);
  await q(`CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)`);
  await q(`CREATE TABLE IF NOT EXISTS activity(
    id BIGSERIAL PRIMARY KEY, user_id TEXT, email TEXT, action TEXT NOT NULL,
    detail TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS oauth_states(
    state TEXT PRIMARY KEY, user_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
}

// ─── HELPERS ────────────────────────────────────────────────────
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

function userJson(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, plan: u.plan, status: u.status };
}

async function logActivity(user, action, detail) {
  try { await q(`INSERT INTO activity(user_id,email,action,detail) VALUES($1,$2,$3,$4)`,
    [user ? user.id : null, user ? user.email : '', action, detail || null]); } catch (e) {}
}

async function getUserByToken(token) {
  if (!token) return null;
  const r = await q(`SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
                     WHERE s.token = $1 AND s.expires_at > now()`, [token]);
  const u = r.rows[0];
  if (!u || u.status === 'suspended') return null;
  return u;
}

function tokenFrom(req) {
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) return h.slice(7);
  return parseCookies(req).ct_token || null;
}

async function auth(req, res, next) {
  try {
    const u = await getUserByToken(tokenFrom(req));
    if (!u) return res.status(401).json({ error: 'Não autenticado' });
    req.user = u; next();
  } catch (e) { res.status(500).json({ error: 'Erro interno' }); }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Apenas administradores' });
  next();
}

async function createSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await q(`INSERT INTO sessions(token,user_id,expires_at) VALUES($1,$2,now() + interval '30 days')`, [token, userId]);
  // Cookie httpOnly em paralelo ao token do localStorage — necessário para o fluxo OAuth da Meta
  res.setHeader('Set-Cookie', `ct_token=${token}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax`);
  return token;
}

async function getSettings() {
  const r = await q(`SELECT key, value FROM settings`);
  const s = {}; r.rows.forEach(row => s[row.key] = row.value);
  return s;
}

function s3From(s) {
  return new S3Client({
    region: 'auto',
    endpoint: s.b2Endpoint,
    forcePathStyle: true,
    credentials: { accessKeyId: s.b2KeyId, secretAccessKey: s.b2AppKey }
  });
}

function baseUrl(req) {
  return APP_URL || `${req.protocol}://${req.get('host')}`;
}

// ─── APP ────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '5mb' }));

// ═══ AUTH ═══════════════════════════════════════════════════════
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) return res.json({ error: 'Preencha todos os campos' });
    if (password.length < 6) return res.json({ error: 'Senha deve ter no mínimo 6 caracteres' });
    const em = String(email).trim().toLowerCase();
    const exists = await q(`SELECT 1 FROM users WHERE email=$1`, [em]);
    if (exists.rows.length) return res.json({ error: 'E-mail já cadastrado' });
    const count = await q(`SELECT count(*)::int AS n FROM users`);
    const role = count.rows[0].n === 0 ? 'admin' : 'user'; // primeiro usuário vira admin
    const id = uid();
    const hash = await bcrypt.hash(password, 10);
    await q(`INSERT INTO users(id,name,email,password_hash,role) VALUES($1,$2,$3,$4,$5)`,
      [id, String(name).trim(), em, hash, role]);
    const u = (await q(`SELECT * FROM users WHERE id=$1`, [id])).rows[0];
    const token = await createSession(res, id);
    await logActivity(u, 'signup');
    res.json({ success: true, token, user: userJson(u) });
  } catch (e) { console.error(e); res.json({ error: 'Erro ao criar conta' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.json({ error: 'Preencha todos os campos' });
    const r = await q(`SELECT * FROM users WHERE email=$1`, [String(email).trim().toLowerCase()]);
    const u = r.rows[0];
    if (!u || !(await bcrypt.compare(password, u.password_hash)))
      return res.json({ error: 'E-mail ou senha incorretos' });
    if (u.status === 'suspended') return res.json({ error: 'Conta suspensa. Fale com o administrador.' });
    await q(`UPDATE users SET login_count = login_count + 1 WHERE id=$1`, [u.id]);
    const token = await createSession(res, u.id);
    await logActivity(u, 'login');
    res.json({ success: true, token, user: userJson(u) });
  } catch (e) { console.error(e); res.json({ error: 'Erro ao entrar' }); }
});

app.post('/api/auth/logout', async (req, res) => {
  const t = tokenFrom(req);
  if (t) await q(`DELETE FROM sessions WHERE token=$1`, [t]).catch(() => {});
  res.setHeader('Set-Cookie', 'ct_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
  res.json({ success: true });
});

app.get('/api/auth/me', async (req, res) => {
  const u = await getUserByToken(tokenFrom(req)).catch(() => null);
  if (!u) return res.json({ user: null });
  res.json({ user: userJson(u) });
});

// ═══ OAUTH META (conectar conta Instagram) ══════════════════════
app.get('/api/auth/facebook', async (req, res) => {
  try {
    const u = await getUserByToken(tokenFrom(req));
    if (!u) return res.json({ error: 'Sessão expirada, faça login novamente' });
    if (!process.env.META_APP_ID || !process.env.META_APP_SECRET)
      return res.json({ error: 'META_APP_ID / META_APP_SECRET não configurados no Railway' });
    const state = crypto.randomBytes(16).toString('hex');
    await q(`DELETE FROM oauth_states WHERE created_at < now() - interval '15 minutes'`);
    await q(`INSERT INTO oauth_states(state,user_id) VALUES($1,$2)`, [state, u.id]);
    const redirect = `${baseUrl(req)}/api/auth/facebook/callback`;
    const scope = 'instagram_basic,instagram_content_publish,pages_show_list,pages_read_engagement,business_management';
    const url = `https://www.facebook.com/v19.0/dialog/oauth?client_id=${process.env.META_APP_ID}` +
      `&redirect_uri=${encodeURIComponent(redirect)}&state=${state}&response_type=code&scope=${encodeURIComponent(scope)}`;
    res.json({ url });
  } catch (e) { console.error(e); res.json({ error: 'Erro ao iniciar conexão' }); }
});

app.get('/api/auth/facebook/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.redirect('/?fb=cancelled');
    const st = await q(`DELETE FROM oauth_states WHERE state=$1 RETURNING user_id`, [state]);
    if (!st.rows.length) return res.redirect('/?fb=invalid_state');
    const userId = st.rows[0].user_id;
    const redirect = `${baseUrl(req)}/api/auth/facebook/callback`;

    // 1. Troca code por token
    let r = await fetch(`${GRAPH}/oauth/access_token?client_id=${process.env.META_APP_ID}` +
      `&redirect_uri=${encodeURIComponent(redirect)}&client_secret=${process.env.META_APP_SECRET}&code=${code}`)
      .then(x => x.json());
    if (r.error) { console.error('FB token:', r.error); return res.redirect('/?fb=token_error'); }

    // 2. Token de longa duração (~60 dias)
    const ll = await fetch(`${GRAPH}/oauth/access_token?grant_type=fb_exchange_token` +
      `&client_id=${process.env.META_APP_ID}&client_secret=${process.env.META_APP_SECRET}` +
      `&fb_exchange_token=${r.access_token}`).then(x => x.json());
    const userToken = ll.access_token || r.access_token;

    // 3. Páginas + contas Instagram Business vinculadas
    const pages = await fetch(`${GRAPH}/me/accounts?fields=id,name,access_token,instagram_business_account{id,username}` +
      `&limit=100&access_token=${userToken}`).then(x => x.json());
    if (pages.error) { console.error('FB pages:', pages.error); return res.redirect('/?fb=pages_error'); }

    let added = 0;
    for (const p of (pages.data || [])) {
      const ig = p.instagram_business_account;
      if (!ig) continue;
      const existing = await q(`SELECT id FROM accounts WHERE user_id=$1 AND ig_user_id=$2`, [userId, ig.id]);
      if (existing.rows.length) {
        await q(`UPDATE accounts SET access_token=$1, username=$2 WHERE id=$3`,
          [p.access_token, ig.username || p.name, existing.rows[0].id]);
      } else {
        await q(`INSERT INTO accounts(id,user_id,username,label,ig_user_id,access_token)
                 VALUES($1,$2,$3,$4,$5,$6)`,
          [uid(), userId, ig.username || p.name, p.name, ig.id, p.access_token]);
      }
      added++;
    }
    res.redirect('/?fb=ok&added=' + added);
  } catch (e) { console.error(e); res.redirect('/?fb=error'); }
});

// ═══ CATEGORIAS ═════════════════════════════════════════════════
app.get('/api/categories', auth, async (req, res) => {
  const r = await q(`SELECT id, name, color FROM categories WHERE user_id=$1 ORDER BY name`, [req.user.id]);
  res.json(r.rows);
});

app.post('/api/categories', auth, async (req, res) => {
  const { name, color } = req.body || {};
  if (!name) return res.json({ error: 'Informe o nome' });
  const id = uid();
  await q(`INSERT INTO categories(id,user_id,name,color) VALUES($1,$2,$3,$4)`,
    [id, req.user.id, String(name).trim(), color || '#7c5cff']);
  res.json({ success: true, id });
});

app.put('/api/categories/:id', auth, async (req, res) => {
  const { name, color } = req.body || {};
  await q(`UPDATE categories SET name=COALESCE($1,name), color=COALESCE($2,color) WHERE id=$3 AND user_id=$4`,
    [name || null, color || null, req.params.id, req.user.id]);
  res.json({ success: true });
});

app.delete('/api/categories/:id', auth, async (req, res) => {
  await q(`UPDATE accounts SET category_id=NULL WHERE category_id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
  await q(`DELETE FROM categories WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
  res.json({ success: true });
});

// ═══ LEGENDAS PRÉ-DEFINIDAS ═════════════════════════════════════
app.get('/api/captions', auth, async (req, res) => {
  const r = await q(`SELECT data FROM captions WHERE user_id=$1`, [req.user.id]);
  res.json(r.rows.length ? r.rows[0].data : []);
});

app.post('/api/captions', auth, async (req, res) => {
  const captions = Array.isArray((req.body || {}).captions) ? req.body.captions : [];
  await q(`INSERT INTO captions(user_id,data) VALUES($1,$2)
           ON CONFLICT (user_id) DO UPDATE SET data=$2`, [req.user.id, JSON.stringify(captions)]);
  res.json({ success: true });
});

// ═══ CONFIGURAÇÕES (storage B2/R2 — admin) ══════════════════════
const SETTING_KEYS = ['b2KeyId', 'b2AppKey', 'b2Bucket', 'b2Endpoint', 'b2PublicUrl'];

app.get('/api/settings', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.json({});
  res.json(await getSettings());
});

app.post('/api/settings', auth, adminOnly, async (req, res) => {
  const body = req.body || {};
  for (const k of SETTING_KEYS) {
    if (body[k] === undefined) continue;
    await q(`INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2`,
      [k, String(body[k])]);
  }
  res.json({ success: true });
});

// ═══ AGENDAMENTO — helpers ══════════════════════════════════════
function parseHM(s, defH, defM) {
  const m = /^(\d{1,2}):(\d{2})$/.exec(s || '');
  return m ? { h: +m[1], m: +m[2] } : { h: defH, m: defM };
}

function intervalMinutes(acc) {
  const st = parseHM(acc.start_time, 2, 0), et = parseHM(acc.end_time, 23, 0);
  const w = Math.max(1, (et.h * 60 + et.m) - (st.h * 60 + st.m));
  const ppd = Math.max(1, acc.posts_per_day || 40);
  return ppd > 1 ? Math.floor(w / (ppd - 1)) : w;
}

// Gera `count` horários dentro da janela da conta, sempre DEPOIS de fromDate
function computeSlots(acc, count, fromDate) {
  const st = parseHM(acc.start_time, 2, 0);
  const ppd = Math.max(1, acc.posts_per_day || 40);
  const iv = intervalMinutes(acc);
  const startMin = st.h * 60 + st.m;
  const slots = [];
  const day = new Date(fromDate);
  day.setHours(0, 0, 0, 0);
  for (let d = 0; d < 730 && slots.length < count; d++) {
    for (let i = 0; i < ppd && slots.length < count; i++) {
      const t = new Date(day);
      t.setMinutes(startMin + i * iv);
      if (t.getTime() > fromDate.getTime()) slots.push(t);
    }
    day.setDate(day.getDate() + 1);
  }
  return slots;
}

function accountJson(a) {
  return {
    id: a.id, username: a.username, label: a.label, categoryId: a.category_id,
    postsPerDay: a.posts_per_day, startTime: a.start_time, endTime: a.end_time,
    intervalMode: a.interval_mode, intervalMinutes: intervalMinutes(a)
  };
}

// ═══ CONTAS ═════════════════════════════════════════════════════
app.get('/api/accounts', auth, async (req, res) => {
  const r = await q(`SELECT * FROM accounts WHERE user_id=$1 ORDER BY created_at`, [req.user.id]);
  res.json(r.rows.map(accountJson));
});

app.get('/api/accounts/stats', auth, async (req, res) => {
  const r = await q(`
    SELECT a.id,
      count(v.id)::int AS todos,
      count(v.id) FILTER (WHERE v.status='postado')::int AS postado,
      count(v.id) FILTER (WHERE v.status='pendente')::int AS pendente,
      count(v.id) FILTER (WHERE v.status='erro')::int AS erro
    FROM accounts a LEFT JOIN videos v ON v.account_id = a.id
    WHERE a.user_id=$1 GROUP BY a.id`, [req.user.id]);
  res.json(r.rows);
});

app.put('/api/accounts/:id', auth, async (req, res) => {
  const { label, startTime, endTime, postsPerDay, categoryId } = req.body || {};
  const r = await q(`UPDATE accounts SET
      label=COALESCE($1,label), start_time=COALESCE($2,start_time), end_time=COALESCE($3,end_time),
      posts_per_day=COALESCE($4,posts_per_day), category_id=$5
    WHERE id=$6 AND user_id=$7 RETURNING id`,
    [label || null, startTime || null, endTime || null, postsPerDay || null,
     categoryId === undefined ? null : (categoryId || null), req.params.id, req.user.id]);
  if (!r.rows.length) return res.json({ error: 'Conta não encontrada' });
  res.json({ success: true });
});

app.delete('/api/accounts/:id', auth, async (req, res) => {
  await q(`DELETE FROM accounts WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
  res.json({ success: true });
});

app.post('/api/accounts/:id/test', auth, async (req, res) => {
  const r = await q(`SELECT * FROM accounts WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
  const a = r.rows[0];
  if (!a) return res.json({ error: 'Conta não encontrada' });
  if (!a.ig_user_id || !a.access_token) return res.json({ error: 'Conta sem credenciais da Meta — reconecte' });
  try {
    const ig = await fetch(`${GRAPH}/${a.ig_user_id}?fields=username&access_token=${a.access_token}`).then(x => x.json());
    if (ig.error) return res.json({ error: ig.error.message || 'Token inválido' });
    if (ig.username && ig.username !== a.username)
      await q(`UPDATE accounts SET username=$1 WHERE id=$2`, [ig.username, a.id]);
    res.json({ success: true, username: ig.username || a.username });
  } catch (e) { res.json({ error: 'Erro de rede ao contatar a Meta' }); }
});

app.post('/api/accounts/:id/reschedule', auth, async (req, res) => {
  try {
    const r = await q(`SELECT * FROM accounts WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
    const a = r.rows[0];
    if (!a) return res.json({ error: 'Conta não encontrada' });
    const { postsPerDay, startTime, endTime } = req.body || {};
    const acc = {
      ...a,
      posts_per_day: postsPerDay || a.posts_per_day,
      start_time: startTime || a.start_time,
      end_time: endTime || a.end_time
    };
    const pend = await q(`SELECT id FROM videos WHERE account_id=$1 AND status='pendente'
                          ORDER BY scheduled_for NULLS LAST, created_at`, [a.id]);
    if (!pend.rows.length) return res.json({ success: true, rescheduled: 0 });
    // Redistribui a partir de amanhã, no início da janela
    const from = new Date(); from.setHours(0, 0, 0, 0); from.setDate(from.getDate() + 1);
    const slots = computeSlots(acc, pend.rows.length, new Date(from.getTime() - 1));
    for (let i = 0; i < pend.rows.length; i++)
      await q(`UPDATE videos SET scheduled_for=$1 WHERE id=$2`, [slots[i], pend.rows[i].id]);
    res.json({ success: true, rescheduled: pend.rows.length });
  } catch (e) { console.error(e); res.json({ error: 'Erro ao reagendar' }); }
});

// ═══ VÍDEOS — upload presign + confirmação ══════════════════════
app.get('/api/videos/presign', auth, async (req, res) => {
  try {
    const s = await getSettings();
    if (!s.b2KeyId || !s.b2AppKey || !s.b2Bucket || !s.b2Endpoint)
      return res.json({ error: 'Storage não configurado — peça ao admin para preencher em Configurações' });
    const filename = String(req.query.filename || 'video.mp4');
    const contentType = String(req.query.contentType || 'video/mp4');
    const safe = filename.replace(/[^\w.\-]/g, '_');
    const key = `videos/${req.user.id}/${Date.now()}_${crypto.randomBytes(4).toString('hex')}_${safe}`;
    const cmd = new PutObjectCommand({ Bucket: s.b2Bucket, Key: key, ContentType: contentType });
    const uploadUrl = await getSignedUrl(s3From(s), cmd, { expiresIn: 3600 });
    const base = (s.b2PublicUrl || '').replace(/\/$/, '');
    res.json({ uploadUrl, key, contentType, publicFileUrl: base ? `${base}/${key}` : null });
  } catch (e) { console.error(e); res.json({ error: 'Erro ao gerar URL de upload' }); }
});

app.post('/api/videos/confirm-batch', auth, async (req, res) => {
  try {
    const { accountId, batchId, cycles, caption, hashtags, videos } = req.body || {};
    if (!Array.isArray(videos) || !videos.length) return res.json({ error: 'Nenhum vídeo enviado' });
    const r = await q(`SELECT * FROM accounts WHERE id=$1 AND user_id=$2`, [accountId, req.user.id]);
    const acc = r.rows[0];
    if (!acc) return res.json({ error: 'Conta não encontrada' });
    // Continua a fila: começa depois do último pendente (ou de agora)
    const last = await q(`SELECT MAX(scheduled_for) AS m FROM videos WHERE account_id=$1 AND status='pendente'`, [acc.id]);
    const from = new Date(Math.max(Date.now(), last.rows[0].m ? new Date(last.rows[0].m).getTime() : 0));
    const cyc = Math.max(1, parseInt(cycles) || 1);
    const slots = computeSlots(acc, videos.length * cyc, from);
    let n = 0;
    for (let c = 1; c <= cyc; c++) {
      for (const v of videos) {
        if (!v.publicFileUrl) continue;
        await q(`INSERT INTO videos(id,user_id,account_id,batch_id,original_name,key,b2_url,bytes,caption,hashtags,cycle,status,scheduled_for)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pendente',$12)`,
          [uid(), req.user.id, acc.id, batchId || null, v.originalName || 'video', v.key || null,
           v.publicFileUrl, v.bytes || 0, caption || '', hashtags || '', c, slots[n]]);
        n++;
      }
    }
    res.json({ success: true, scheduled: n });
  } catch (e) { console.error(e); res.json({ error: 'Erro ao agendar vídeos' }); }
});

// ═══ VÍDEOS — listagem e ações ══════════════════════════════════
function videoJson(v) {
  return {
    id: v.id, originalName: v.original_name, username: v.username || v.label || '?',
    cycle: v.cycle, status: v.status, errorMsg: v.error_msg,
    scheduledFor: v.scheduled_for, postedAt: v.posted_at, b2Url: v.b2_url, batchId: v.batch_id
  };
}

app.get('/api/videos', auth, async (req, res) => {
  try {
    const { status = 'todos', accountId, date } = req.query;
    const limit = Math.min(100000, parseInt(req.query.limit) || 500);
    const params = [req.user.id];
    let where = `v.user_id = $1`;
    if (accountId && accountId !== 'all') { params.push(accountId); where += ` AND v.account_id = $${params.length}`; }
    if (date) { params.push(date); where += ` AND (v.scheduled_for AT TIME ZONE '${TZ}')::date = $${params.length}::date`; }

    const cr = await q(`SELECT v.status, count(*)::int AS n FROM videos v WHERE ${where} GROUP BY v.status`, params);
    const counts = { todos: 0 };
    cr.rows.forEach(r => { counts[r.status] = r.n; counts.todos += r.n; });

    let whereList = where;
    const listParams = [...params];
    if (status && status !== 'todos') { listParams.push(status); whereList += ` AND v.status = $${listParams.length}`; }
    const order = status === 'pendente'
      ? `v.scheduled_for ASC`
      : `COALESCE(v.posted_at, v.scheduled_for, v.created_at) DESC`;
    listParams.push(limit);
    const vr = await q(`SELECT v.*, a.username, a.label FROM videos v
                        LEFT JOIN accounts a ON a.id = v.account_id
                        WHERE ${whereList} ORDER BY ${order} LIMIT $${listParams.length}`, listParams);
    res.json({ videos: vr.rows.map(videoJson), counts });
  } catch (e) { console.error(e); res.json({ videos: [], counts: {} }); }
});

app.post('/api/videos/cancel-pending', auth, async (req, res) => {
  const params = [req.user.id];
  let where = `user_id=$1 AND status='pendente'`;
  if (req.query.accountId) { params.push(req.query.accountId); where += ` AND account_id=$2`; }
  const r = await q(`UPDATE videos SET status='cancelado' WHERE ${where} RETURNING id`, params);
  res.json({ success: true, cancelled: r.rows.length });
});

app.get('/api/videos/:id/status', auth, async (req, res) => {
  const r = await q(`SELECT status, error_msg FROM videos WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
  if (!r.rows.length) return res.json({ error: 'Não encontrado' });
  res.json({ status: r.rows[0].status, errorMsg: r.rows[0].error_msg });
});

app.post('/api/videos/:id/retry', auth, async (req, res) => {
  await q(`UPDATE videos SET status='pendente', error_msg=NULL, scheduled_for=now() + interval '2 minutes'
           WHERE id=$1 AND user_id=$2 AND status IN ('erro','cancelado')`, [req.params.id, req.user.id]);
  res.json({ success: true });
});

app.post('/api/videos/:id/publish-now', auth, async (req, res) => {
  const r = await q(`UPDATE videos SET scheduled_for=now(), status='pendente', error_msg=NULL
                     WHERE id=$1 AND user_id=$2 AND status IN ('pendente','erro','cancelado') RETURNING id`,
    [req.params.id, req.user.id]);
  if (!r.rows.length) return res.json({ error: 'Vídeo não encontrado ou já em processamento' });
  setTimeout(tick, 500); // dispara o worker imediatamente
  res.json({ success: true });
});

app.delete('/api/videos/:id', auth, async (req, res) => {
  await q(`DELETE FROM videos WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
  res.json({ success: true });
});

// ═══ DASHBOARD ══════════════════════════════════════════════════
app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const uidP = [req.user.id];
    const sr = await q(`SELECT
        count(*)::int AS total,
        count(*) FILTER (WHERE status='postado')::int AS postado,
        count(*) FILTER (WHERE status='pendente')::int AS pendente,
        count(*) FILTER (WHERE status='erro')::int AS erro,
        count(*) FILTER (WHERE status='processando')::int AS "activeJobs"
      FROM videos WHERE user_id=$1`, uidP);
    const accCount = await q(`SELECT count(*)::int AS n FROM accounts WHERE user_id=$1`, uidP);
    const today = await q(`SELECT count(*)::int AS n FROM videos
      WHERE user_id=$1 AND status='postado'
      AND (posted_at AT TIME ZONE '${TZ}')::date = (now() AT TIME ZONE '${TZ}')::date`, uidP);

    const accs = await q(`SELECT * FROM accounts WHERE user_id=$1 ORDER BY created_at`, uidP);
    const accStats = [];
    for (const a of accs.rows) {
      const c = await q(`SELECT
          count(*)::int AS todos,
          count(*) FILTER (WHERE status='postado')::int AS postado,
          count(*) FILTER (WHERE status='pendente')::int AS pendente,
          count(*) FILTER (WHERE status='erro')::int AS erro
        FROM videos WHERE account_id=$1`, [a.id]);
      const times = await q(`SELECT
          MIN(scheduled_for) FILTER (WHERE status='pendente' AND scheduled_for > now()) AS next,
          MAX(scheduled_for) FILTER (WHERE status='pendente') AS last_pending,
          MAX(posted_at) FILTER (WHERE status='postado') AS last_posted
        FROM videos WHERE account_id=$1`, [a.id]);
      const daily = await q(`SELECT (scheduled_for AT TIME ZONE '${TZ}')::date::text AS d, count(*)::int AS n
        FROM videos WHERE account_id=$1 AND status='pendente' GROUP BY 1 ORDER BY 1 LIMIT 7`, [a.id]);
      const dailySchedule = {};
      daily.rows.forEach(r => dailySchedule[r.d] = r.n);
      accStats.push({
        ...accountJson(a),
        counts: c.rows[0],
        nextScheduled: times.rows[0].next,
        lastPosted: times.rows[0].last_posted,
        lastPending: times.rows[0].last_pending,
        dailySchedule
      });
    }

    const up = await q(`SELECT v.original_name, v.scheduled_for, a.username, a.label
      FROM videos v LEFT JOIN accounts a ON a.id=v.account_id
      WHERE v.user_id=$1 AND v.status='pendente' ORDER BY v.scheduled_for LIMIT 8`, uidP);

    res.json({
      stats: { ...sr.rows[0], accounts: accCount.rows[0].n },
      todayCount: today.rows[0].n,
      accStats,
      upcoming: up.rows.map(v => ({
        originalName: v.original_name,
        username: v.username || v.label || '?',
        scheduledFor: v.scheduled_for
      }))
    });
  } catch (e) { console.error(e); res.json({ stats: {}, accStats: [], upcoming: [] }); }
});

// ═══ ADMIN ══════════════════════════════════════════════════════
app.get('/api/admin/users-overview', auth, adminOnly, async (req, res) => {
  const r = await q(`SELECT u.id, u.name, u.email, u.role, u.status, u.plan, u.login_count, u.created_at,
      (SELECT count(*) FROM accounts a WHERE a.user_id=u.id)::int AS acc_count,
      (SELECT count(*) FROM videos v WHERE v.user_id=u.id)::int AS v_total,
      (SELECT count(*) FROM videos v WHERE v.user_id=u.id AND v.status='postado')::int AS v_postado,
      (SELECT count(*) FROM videos v WHERE v.user_id=u.id AND v.status='pendente')::int AS v_pendente,
      (SELECT count(*) FROM videos v WHERE v.user_id=u.id AND v.status='erro')::int AS v_erro
    FROM users u ORDER BY u.created_at`);
  res.json(r.rows.map(u => ({
    id: u.id, name: u.name, email: u.email, role: u.role, status: u.status, plan: u.plan,
    loginCount: u.login_count, createdAt: u.created_at, accountCount: u.acc_count,
    videoStats: { total: u.v_total, postado: u.v_postado, pendente: u.v_pendente, erro: u.v_erro }
  })));
});

app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  const r = await q(`SELECT count(*)::int AS total,
      count(*) FILTER (WHERE status='active')::int AS active,
      count(*) FILTER (WHERE role='admin')::int AS admins
    FROM users`);
  const logins = await q(`SELECT count(*)::int AS n FROM activity
    WHERE action='login' AND (created_at AT TIME ZONE '${TZ}')::date = (now() AT TIME ZONE '${TZ}')::date`);
  res.json({ ...r.rows[0], todayLogins: logins.rows[0].n });
});

app.put('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  const { plan, role, status } = req.body || {};
  await q(`UPDATE users SET plan=COALESCE($1,plan), role=COALESCE($2,role), status=COALESCE($3,status) WHERE id=$4`,
    [plan || null, role || null, status || null, req.params.id]);
  await logActivity(req.user, 'admin_update_user', JSON.stringify({ id: req.params.id, plan, role, status }));
  res.json({ success: true });
});

app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  if (req.params.id === req.user.id) return res.json({ error: 'Você não pode deletar a si mesmo' });
  await q(`DELETE FROM users WHERE id=$1`, [req.params.id]);
  await logActivity(req.user, 'admin_delete_user', req.params.id);
  res.json({ success: true });
});

app.get('/api/admin/activity', auth, adminOnly, async (req, res) => {
  const r = await q(`SELECT action, email, detail, created_at FROM activity ORDER BY created_at DESC LIMIT 100`);
  res.json(r.rows);
});

// ═══ WORKER — publica vídeos agendados no Instagram ═════════════
function buildCaption(v) {
  const cap = (v.caption || '').trim();
  const tags = (v.hashtags || '').trim().split(/[\s,]+/).filter(Boolean)
    .map(t => t.startsWith('#') ? t : '#' + t).join(' ');
  return [cap, tags].filter(Boolean).join('\n\n').slice(0, 2200);
}

async function setProgress(id, pct, msg) {
  await q(`UPDATE videos SET error_msg=$2 WHERE id=$1`, [id, `[${pct}%] ${msg}`]).catch(() => {});
}

async function publishVideo(v) {
  try {
    if (!v.ig_user_id || !v.access_token) throw new Error('Conta sem credenciais da Meta — reconecte a conta');
    if (!v.b2_url) throw new Error('Vídeo sem URL pública');

    await setProgress(v.id, 8, 'Criando container na Meta...');
    const create = await fetch(`${GRAPH}/${v.ig_user_id}/media`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        media_type: 'REELS', video_url: v.b2_url,
        caption: buildCaption(v), access_token: v.access_token
      })
    }).then(x => x.json());
    if (create.error) throw new Error(create.error.message || 'Erro ao criar container');

    // Aguarda o Instagram processar o vídeo (até ~3 min)
    let ok = false;
    for (let i = 1; i <= 36; i++) {
      await sleep(5000);
      const st = await fetch(`${GRAPH}/${create.id}?fields=status_code&access_token=${v.access_token}`)
        .then(x => x.json()).catch(() => ({}));
      if (st.status_code === 'FINISHED') { ok = true; break; }
      if (st.status_code === 'ERROR') throw new Error('O Instagram rejeitou o vídeo (formato/duração)');
      await setProgress(v.id, Math.min(90, 10 + Math.round(i / 36 * 78)), `Processando no Instagram (${i}/36)`);
    }
    if (!ok) throw new Error('Timeout: Instagram demorou demais para processar');

    await setProgress(v.id, 95, 'Publicando...');
    const pub = await fetch(`${GRAPH}/${v.ig_user_id}/media_publish`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ creation_id: create.id, access_token: v.access_token })
    }).then(x => x.json());
    if (pub.error) throw new Error(pub.error.message || 'Erro ao publicar');

    await q(`UPDATE videos SET status='postado', posted_at=now(), error_msg=NULL WHERE id=$1`, [v.id]);
    console.log(`✅ Publicado: ${v.original_name} (@${v.username || '?'})`);
  } catch (e) {
    console.error(`❌ Falha ao publicar ${v.id}:`, e.message);
    await q(`UPDATE videos SET status='erro', error_msg=$2 WHERE id=$1`,
      [v.id, String(e.message || 'Erro desconhecido').slice(0, 300)]).catch(() => {});
  }
}

const publishing = new Set();
async function tick() {
  try {
    const due = await q(`SELECT v.*, a.ig_user_id, a.access_token, a.username
      FROM videos v JOIN accounts a ON a.id = v.account_id
      WHERE v.status='pendente' AND v.scheduled_for <= now()
      ORDER BY v.scheduled_for LIMIT 3`);
    for (const v of due.rows) {
      if (publishing.has(v.id)) continue;
      publishing.add(v.id);
      await q(`UPDATE videos SET status='processando', error_msg='[5%] Iniciando...' WHERE id=$1`, [v.id]);
      publishVideo(v).finally(() => publishing.delete(v.id));
    }
  } catch (e) { console.error('tick:', e.message); }
}

// ═══ STATIC + BOOT ══════════════════════════════════════════════
app.use(express.static(__dirname, { index: false }));
app.get(/^\/(?!api\/).*/, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

migrate()
  .then(() => {
    app.listen(PORT, () => console.log(`🚀 MeuSacoTools rodando na porta ${PORT} (TZ: ${TZ})`));
    setInterval(tick, 30000);
    setTimeout(tick, 5000);
  })
  .catch(e => { console.error('Erro nas migrações:', e); process.exit(1); });
