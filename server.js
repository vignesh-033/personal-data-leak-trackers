import express from 'express';
import helmet from 'helmet';
import dotenv from 'dotenv';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA = path.join(__dirname, 'data', 'store.json');
const HIBP = 'https://haveibeenpwned.com/api/v3';
const configuredKey = process.env.APP_ENCRYPTION_KEY || '';
const APP_KEY = configuredKey && !configuredKey.startsWith('replace-this-') ? configuredKey : '';
const blankStore = () => ({ monitors: [], breaches: [], sharing: [], audit: [], alerts: [] });
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(__dirname, 'public')));

async function readStore() {
  try {
    const parsed = JSON.parse(await fs.readFile(DATA, 'utf8'));
    return { ...blankStore(), ...parsed };
  } catch (e) {
    if (e.code !== 'ENOENT') console.error('Store read error:', e.message);
    return blankStore();
  }
}
async function writeStore(store) {
  await fs.mkdir(path.dirname(DATA), { recursive: true });
  const tmp = `${DATA}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(store, null, 2), { mode: 0o600 });
  await fs.rename(tmp, DATA);
}
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const normalizeEmail = email => String(email || '').trim().toLowerCase();
const validEmail = email => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
function encryptEmail(email) {
  if (!APP_KEY) throw new Error('Set APP_ENCRYPTION_KEY in .env before saving monitors.');
  const key = crypto.createHash('sha256').update(APP_KEY).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(email, 'utf8'), cipher.final()]);
  return [iv.toString('base64'), cipher.getAuthTag().toString('base64'), encrypted.toString('base64')].join('.');
}
function decryptEmail(value) {
  const [iv, tag, encrypted] = String(value).split('.');
  const key = crypto.createHash('sha256').update(APP_KEY).digest();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(encrypted, 'base64')), decipher.final()]).toString('utf8');
}
async function audit(store, action, detail) {
  const previous = store.audit.at(-1)?.hash || '0'.repeat(64);
  const timestamp = new Date().toISOString();
  const index = store.audit.length;
  const hash = sha256(`${index}|${previous}|${action}|${detail}|${timestamp}`);
  store.audit.push({ index, action, detail, timestamp, previous, hash });
}
function publicMonitor(m) {
  const { encryptedEmail, ...safe } = m;
  return { ...safe, emailHint: m.emailHint || '••••••••' };
}
async function callHIBP(email) {
  if (!process.env.HIBP_API_KEY) {
    const error = new Error('Live breach checking is not configured yet. Add your Have I Been Pwned API key to the server .env file.');
    error.status = 503; throw error;
  }
  const url = `${HIBP}/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  let response;
  try {
    response = await fetch(url, { signal: controller.signal, headers: { 'hibp-api-key': process.env.HIBP_API_KEY, 'user-agent': process.env.APP_USER_AGENT || 'PersonalDataLeakTracker/2.0' } });
  } catch (e) {
    const err = new Error(e.name === 'AbortError' ? 'The breach service timed out. Please try again.' : 'Could not reach the breach service. Check your internet connection.');
    err.status = 502; throw err;
  } finally { clearTimeout(timeout); }
  if (response.status === 404) return [];
  if (response.status === 429) { const e = new Error('The breach service rate limit was reached. Wait a moment and retry.'); e.status = 429; throw e; }
  if (response.status === 401 || response.status === 403) { const e = new Error('The breach service rejected the API key or subscription. Check your HIBP account and .env configuration.'); e.status = 502; throw e; }
  if (!response.ok) { const e = new Error(`Breach service returned HTTP ${response.status}.`); e.status = 502; throw e; }
  const rows = await response.json();
  return rows.map(b => ({ name: b.Name, title: b.Title, domain: b.Domain, breachDate: b.BreachDate, addedDate: b.AddedDate, pwnCount: Number(b.PwnCount || 0), dataClasses: Array.isArray(b.DataClasses) ? b.DataClasses : [], verified: Boolean(b.IsVerified), sensitive: Boolean(b.IsSensitive) }));
}
function recordAlerts(store, hash, breaches, label) {
  if (breaches.length) store.alerts.unshift({ id: crypto.randomUUID(), type: 'exposure', title: `Exposure found for ${label}`, message: `${breaches.length} breach record(s) returned. Review the affected services and change reused passwords.`, createdAt: new Date().toISOString(), read: false, emailHash: hash });
  store.alerts = store.alerts.slice(0, 200);
}

app.get('/api/health', (_req, res) => res.json({ ok: true, hibpConfigured: Boolean(process.env.HIBP_API_KEY), encryptionConfigured: Boolean(APP_KEY), appName: 'Personal Data Leak Tracker' }));
app.get('/api/state', async (_req, res) => {
  const s = await readStore();
  res.json({ monitors: s.monitors.map(publicMonitor), breaches: s.breaches, sharing: s.sharing, audit: s.audit, alerts: s.alerts });
});
app.post('/api/monitors', async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address, such as you@example.com.' });
    if (!APP_KEY) return res.status(503).json({ error: 'Monitor encryption is not configured. Add APP_ENCRYPTION_KEY to .env and restart the server.' });
    const store = await readStore(); const emailHash = sha256(email);
    if (store.monitors.some(m => m.emailHash === emailHash)) return res.status(409).json({ error: 'This email is already on your monitor list.' });
    const monitor = { id: crypto.randomUUID(), emailHash, encryptedEmail: encryptEmail(email), emailHint: email.replace(/^(.).+(@.*)$/, '$1••••$2'), createdAt: new Date().toISOString(), lastChecked: null, status: 'Not checked yet', breachCount: 0 };
    store.monitors.unshift(monitor); await audit(store, 'MONITOR_CREATED', `emailHash:${emailHash}`); await writeStore(store);
    res.status(201).json(publicMonitor(monitor));
  } catch (e) { next(e); }
});
app.delete('/api/monitors/:id', async (req, res, next) => {
  try {
    const s = await readStore(); const found = s.monitors.find(m => m.id === req.params.id);
    if (!found) return res.status(404).json({ error: 'Monitor not found.' });
    s.monitors = s.monitors.filter(m => m.id !== req.params.id);
    await audit(s, 'MONITOR_REMOVED', `monitorId:${req.params.id};emailHash:${found.emailHash}`); await writeStore(s); res.json({ ok: true });
  } catch (e) { next(e); }
});
async function checkAndSave(email, monitorId = null) {
  const store = await readStore(); const emailHash = sha256(email); const breaches = await callHIBP(email);
  const checkedAt = new Date().toISOString();
  const monitor = monitorId ? store.monitors.find(m => m.id === monitorId) : store.monitors.find(m => m.emailHash === emailHash);
  if (monitor) { monitor.lastChecked = checkedAt; monitor.breachCount = breaches.length; monitor.status = breaches.length ? 'Exposure detected' : 'No exposure found'; }
  const record = { id: crypto.randomUUID(), emailHash, emailHint: email.replace(/^(.).+(@.*)$/, '$1••••$2'), checkedAt, count: breaches.length, results: breaches };
  store.breaches.unshift(record); store.breaches = store.breaches.slice(0, 100);
  recordAlerts(store, emailHash, breaches, record.emailHint);
  await audit(store, 'LIVE_BREACH_CHECK', `emailHash:${emailHash};count:${breaches.length}`);
  await writeStore(store); return { found: breaches.length > 0, breaches, checkedAt, emailHint: record.emailHint };
}
app.post('/api/check-email', async (req, res, next) => {
  try { const email = normalizeEmail(req.body.email); if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' }); res.json(await checkAndSave(email)); }
  catch (e) { next(e); }
});
app.post('/api/monitors/:id/check', async (req, res, next) => {
  try {
    const store = await readStore(); const m = store.monitors.find(x => x.id === req.params.id);
    if (!m) return res.status(404).json({ error: 'Monitor not found.' });
    let email; try { email = decryptEmail(m.encryptedEmail); } catch { return res.status(500).json({ error: 'Could not decrypt this monitor. Check that APP_ENCRYPTION_KEY has not changed.' }); }
    res.json(await checkAndSave(email, m.id));
  } catch (e) { next(e); }
});
app.post('/api/monitors/check-all', async (req, res, next) => {
  try {
    const store = await readStore(); if (!store.monitors.length) return res.status(400).json({ error: 'Add at least one monitor first.' });
    if (!process.env.HIBP_API_KEY) return res.status(503).json({ error: 'Live breach checking is not configured. Add your HIBP API key to .env.' });
    const results = [];
    for (const m of store.monitors) {
      try { const email = decryptEmail(m.encryptedEmail); const result = await checkAndSave(email, m.id); results.push({ id: m.id, emailHint: m.emailHint, ok: true, found: result.found, count: result.breaches.length }); }
      catch (e) { results.push({ id: m.id, emailHint: m.emailHint, ok: false, error: e.message }); }
    }
    res.json({ results });
  } catch (e) { next(e); }
});
app.post('/api/sharing', async (req, res, next) => {
  try {
    const platform = String(req.body.platform || '').trim().slice(0, 120), category = String(req.body.category || '').trim().slice(0, 80), purpose = String(req.body.purpose || '').trim().slice(0, 240);
    if (!platform || !category || !purpose) return res.status(400).json({ error: 'Platform, data category, and purpose are required.' });
    const store = await readStore(); const item = { id: crypto.randomUUID(), platform, category, purpose, consent: req.body.consent === true, createdAt: new Date().toISOString() };
    store.sharing.unshift(item); await audit(store, 'DATA_SHARING_LOGGED', `${platform}|${category}|${purpose}|consent:${item.consent}`); await writeStore(store); res.status(201).json(item);
  } catch (e) { next(e); }
});
app.delete('/api/sharing/:id', async (req, res, next) => {
  try { const s = await readStore(); const item = s.sharing.find(x => x.id === req.params.id); if (!item) return res.status(404).json({ error: 'Sharing record not found.' }); s.sharing = s.sharing.filter(x => x.id !== req.params.id); await audit(s, 'DATA_SHARING_RECORD_REMOVED', `recordId:${item.id};platform:${item.platform}`); await writeStore(s); res.json({ ok: true }); }
  catch (e) { next(e); }
});
app.post('/api/alerts/:id/read', async (req, res, next) => {
  try { const s = await readStore(); const a = s.alerts.find(x => x.id === req.params.id); if (!a) return res.status(404).json({ error: 'Alert not found.' }); a.read = true; await audit(s, 'ALERT_MARKED_READ', a.id); await writeStore(s); res.json({ ok: true }); }
  catch (e) { next(e); }
});
app.post('/api/alerts/read-all', async (_req, res, next) => {
  try { const s = await readStore(); s.alerts.forEach(a => a.read = true); await audit(s, 'ALL_ALERTS_MARKED_READ', `count:${s.alerts.length}`); await writeStore(s); res.json({ ok: true }); }
  catch (e) { next(e); }
});
app.get('/api/audit/verify', async (_req, res, next) => {
  try { const s = await readStore(); let valid = true; let brokenIndex = null;
    for (let i = 0; i < s.audit.length; i++) { const b = s.audit[i]; const expectedPrevious = i ? s.audit[i - 1].hash : '0'.repeat(64); const expectedHash = sha256(`${b.index}|${b.previous}|${b.action}|${b.detail}|${b.timestamp}`); if (b.previous !== expectedPrevious || b.index !== i || expectedHash !== b.hash) { valid = false; brokenIndex = i; break; } }
    res.json({ valid, blocks: s.audit.length, brokenIndex, message: valid ? 'All audit entries match the hash chain.' : `Audit integrity check failed at entry ${brokenIndex}.` });
  } catch (e) { next(e); }
});
app.get('/api/export', async (_req, res, next) => {
  try { const s = await readStore(); res.setHeader('Content-Disposition', 'attachment; filename="personal-data-leak-tracker-report.json"'); res.json({ exportedAt: new Date().toISOString(), monitors: s.monitors.map(publicMonitor), breaches: s.breaches, sharing: s.sharing, audit: s.audit, alerts: s.alerts }); }
  catch (e) { next(e); }
});
app.use((err, _req, res, _next) => { console.error(err.message); res.status(err.status || 500).json({ error: err.status ? err.message : 'Something went wrong on the server. Check the terminal for details.' }); });
app.listen(PORT, () => console.log(`Personal Data Leak Tracker running at http://localhost:${PORT}`));
