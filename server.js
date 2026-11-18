import http from 'node:http';
import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';
import { readFile, writeFile, mkdir, unlink, copyFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const onRender = process.env.RENDER === 'true';
const storeDir = process.env.DATA_DIR || (onRender ? '/var/data' : path.join(root, 'data'));
const storeFile = path.join(storeDir, 'projects.json');
const port = Number(process.env.PORT || 3000);
const password = process.env.ADMIN_PASSWORD;
if (!password) throw new Error('Set ADMIN_PASSWORD before starting the server.');
await mkdir(storeDir, { recursive: true });
await mkdir(path.join(storeDir, 'files'), { recursive: true });
if (!existsSync(storeFile)) {
  const bundledStore = path.join(root, 'data', 'projects.json');
  if (storeFile !== bundledStore && existsSync(bundledStore)) {
    await copyFile(bundledStore, storeFile);
    const bundledFiles = path.join(root, 'data', 'files');
    if (existsSync(bundledFiles)) {
      const seedProjects = JSON.parse(await readFile(bundledStore, 'utf8'));
      for (const project of seedProjects) {
        if (!project.downloadFile) continue;
        const filename = path.basename(project.downloadFile);
        try { await copyFile(path.join(bundledFiles, filename), path.join(storeDir, 'files', filename)); }
        catch { /* The seed listing can remain visible even if its old download is absent. */ }
      }
    }
    console.log(`Initialized persistent project catalog in ${storeDir}`);
  } else {
    await writeFile(storeFile, '[]');
  }
}
if (onRender && !process.env.DATA_DIR) console.warn('DATA_DIR is not set; using /var/data. Attach a persistent disk at /var/data to preserve publications across deploys.');
const secretFile = path.join(storeDir, 'session.secret');
let secret = process.env.SESSION_SECRET;
if (!secret) {
  try { secret = await readFile(secretFile, 'utf8'); }
  catch { secret = randomBytes(32).toString('hex'); await writeFile(secretFile, secret, { mode: 0o600 }); }
}

const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
const sign = value => createHmac('sha256', secret).update(value).digest('hex');
const cookieValue = req => (req.headers.cookie || '').split('; ').find(x => x.startsWith('s1session='))?.slice('s1session='.length) || '';
const clientIp = req => (req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown').trim();
const equal = (a, b) => { const left = Buffer.from(a); const right = Buffer.from(b); return left.length === right.length && timingSafeEqual(left, right); };
const authorized = req => {
  const cookie = cookieValue(req); const splitAt = cookie.lastIndexOf('.'); if (splitAt < 0) return false;
  const token = cookie.slice(0, splitAt); const signature = cookie.slice(splitAt + 1); if (!equal(signature, sign(token))) return false;
  const [id, expires, fingerprint] = token.split('.');
  return !!id && Number(expires) > Date.now() && equal(fingerprint || '', sign(`ip:${clientIp(req)}`));
};
const send = (res, status, body, headers = {}) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers }); res.end(JSON.stringify(body)); };
const getProjects = async () => JSON.parse(await readFile(storeFile, 'utf8'));
const readBody = req => new Promise((resolve, reject) => { let raw=''; req.on('data', c => { raw += c; if(raw.length > 100_000) reject(new Error('Too large')); }); req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch { reject(new Error('Invalid JSON')); } }); req.on('error', reject); });
const readMultipart = req => new Promise((resolve, reject) => {
  const type = req.headers['content-type'] || '';
  const boundary = type.match(/boundary=(?:"([^"]+)"|([^;]+))/i)?.slice(1).find(Boolean);
  if (!boundary) return reject(new Error('Invalid upload format'));
  const chunks = []; let size = 0; const max = 101 * 1024 * 1024;
  req.on('data', chunk => { size += chunk.length; if (size > max) { reject(new Error('Upload too large')); req.destroy(); } else chunks.push(chunk); });
  req.on('end', () => {
    try {
      const body = Buffer.concat(chunks); const marker = Buffer.from(`--${boundary}`); const fields = {}; let file = null; let cursor = 0;
      while ((cursor = body.indexOf(marker, cursor)) !== -1) {
        cursor += marker.length;
        if (body[cursor] === 45 && body[cursor + 1] === 45) break;
        if (body[cursor] === 13 && body[cursor + 1] === 10) cursor += 2;
        const headerEnd = body.indexOf(Buffer.from('\r\n\r\n'), cursor); if (headerEnd < 0) break;
        const headers = body.subarray(cursor, headerEnd).toString('latin1');
        const disp = headers.match(/content-disposition:\s*form-data;([^\r\n]+)/i)?.[1] || '';
        const name = disp.match(/name="([^"]+)"/)?.[1]; const filename = disp.match(/filename="([^"]*)"/)?.[1];
        const dataStart = headerEnd + 4; const next = body.indexOf(Buffer.from(`\r\n--${boundary}`), dataStart); if (next < 0) break;
        const part = body.subarray(dataStart, next);
        if (name && filename !== undefined) file = { name, filename, mime: headers.match(/content-type:\s*([^\r\n]+)/i)?.[1]?.trim() || 'application/octet-stream', data: part };
        else if (name) fields[name] = part.toString('utf8');
        cursor = next + 2;
      }
      resolve({ fields, file });
    } catch (error) { reject(error); }
  });
  req.on('error', reject);
});

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/api/projects' && req.method === 'GET') return send(res, 200, { projects: await getProjects() });
    if (url.pathname === '/api/session' && req.method === 'GET') return send(res, 200, { authenticated: authorized(req) });
    if (url.pathname === '/api/login' && req.method === 'POST') {
      const body = await readBody(req);
      const a = Buffer.from(String(body.password || '')); const b = Buffer.from(password);
      if (a.length !== b.length || !timingSafeEqual(a, b)) return send(res, 401, { error: 'Пароль не подошёл. Попробуйте ещё раз.' });
      const id = randomBytes(24).toString('hex'); const expires = Date.now() + 365 * 24 * 60 * 60 * 1000;
      const token = `${id}.${expires}.${sign(`ip:${clientIp(req)}`)}`;
      const secure = req.socket.encrypted || req.headers['x-forwarded-proto']?.split(',')[0].trim() === 'https';
      return send(res, 200, { ok: true }, { 'Set-Cookie': `s1session=${token}.${sign(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000${secure ? '; Secure' : ''}` });
    }
    if (url.pathname === '/api/logout' && req.method === 'POST') return send(res, 200, { ok: true }, { 'Set-Cookie': 's1session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
    if (url.pathname === '/api/projects' && req.method === 'POST') {
      if (!authorized(req)) return send(res, 401, { error: 'Войдите в режим разработчика.' });
      const body = await readBody(req);
      const title = String(body.title || '').trim().slice(0, 100);
      const author = String(body.author || '').trim().slice(0, 80);
      const description = String(body.description || '').trim().slice(0, 600);
      const link = String(body.link || '').trim().slice(0, 500);
      if (!title || !author || !description || !/^https?:\/\//i.test(link)) return send(res, 400, { error: 'Заполните название, автора, описание и корректную ссылку с http:// или https://.' });
      const projects = await getProjects();
      const project = { id: randomBytes(8).toString('hex'), title, author, description, link, kind: 'site', createdAt: new Date().toISOString() };
      projects.unshift(project); await writeFile(storeFile, JSON.stringify(projects, null, 2));
      return send(res, 201, { project });
    }
    if (url.pathname === '/api/projects/app' && req.method === 'POST') {
      if (!authorized(req)) return send(res, 401, { error: 'Войдите в режим разработчика.' });
      const { fields, file } = await readMultipart(req);
      const title = String(fields.title || '').trim().slice(0, 100);
      const author = String(fields.author || '').trim().slice(0, 80);
      const description = String(fields.description || '').trim().slice(0, 600);
      const version = String(fields.version || '').trim().slice(0, 30);
      if (!title || !author || !description || !file || !file.filename || file.data.length === 0) return send(res, 400, { error: 'Заполните название, автора, описание и прикрепите файл приложения.' });
      if (file.data.length > 100 * 1024 * 1024) return send(res, 413, { error: 'Файл больше 100 МБ. Прикрепите файл меньшего размера.' });
      const ext = path.extname(file.filename).toLowerCase().replace(/[^.a-z0-9]/g, '').slice(0, 12);
      const id = randomBytes(10).toString('hex'); const downloadFile = `${id}${ext}`;
      await writeFile(path.join(storeDir, 'files', downloadFile), file.data);
      const notes = String(fields.changelog || '').trim().slice(0, 1200);
      const project = { id, title, author, description, kind: 'app', version, fileName: path.basename(file.filename).slice(0, 160), downloadFile, downloadPath: `/download/${id}`, changelog: notes ? [{ version, notes, date: new Date().toISOString() }] : [], createdAt: new Date().toISOString() };
      const projects = await getProjects(); projects.unshift(project); await writeFile(storeFile, JSON.stringify(projects, null, 2));
      return send(res, 201, { project });
    }
    if (url.pathname === '/api/projects/file' && req.method === 'POST') {
      if (!authorized(req)) return send(res, 401, { error: 'Войдите в режим разработчика.' });
      const { fields, file } = await readMultipart(req);
      const title = String(fields.title || '').trim().slice(0, 100);
      const author = String(fields.author || '').trim().slice(0, 80);
      const description = String(fields.description || '').trim().slice(0, 600);
      if (!title || !author || !description || !file?.filename || !file.data.length) return send(res, 400, { error: 'Заполните название, автора, описание и прикрепите файл.' });
      if (file.data.length > 100 * 1024 * 1024) return send(res, 413, { error: 'Файл больше 100 МБ.' });
      const id = randomBytes(10).toString('hex');
      const ext = path.extname(file.filename).toLowerCase().replace(/[^.a-z0-9]/g, '').slice(0, 12);
      const downloadFile = `${id}${ext}`;
      await writeFile(path.join(storeDir, 'files', downloadFile), file.data);
      const project = { id, title, author, description, kind: 'file', fileName: path.basename(file.filename).slice(0, 160), downloadFile, downloadPath: `/download/${id}`, createdAt: new Date().toISOString() };
      const projects = await getProjects(); projects.unshift(project); await writeFile(storeFile, JSON.stringify(projects, null, 2));
      return send(res, 201, { project });
    }
    if (url.pathname.startsWith('/api/projects/') && req.method === 'PUT') {
      if (!authorized(req)) return send(res, 401, { error: 'Войдите в режим разработчика.' });
      const id = decodeURIComponent(url.pathname.slice('/api/projects/'.length));
      const projects = await getProjects(); const index = projects.findIndex(item => item.id === id);
      if (index < 0) return send(res, 404, { error: 'Публикация не найдена.' });
      const project = projects[index];
      let fields; let file = null;
      if (project.kind !== 'site') ({ fields, file } = await readMultipart(req));
      else fields = await readBody(req);
      const title = String(fields.title || '').trim().slice(0, 100);
      const author = String(fields.author || '').trim().slice(0, 80);
      const description = String(fields.description || '').trim().slice(0, 600);
      if (!title || !author || !description) return send(res, 400, { error: 'Заполните название, автора и описание.' });
      project.title = title; project.author = author; project.description = description;
      let version = project.version || '';
      if (project.kind === 'site') {
        const link = String(fields.link || '').trim().slice(0, 500);
        if (!/^https?:\/\//i.test(link)) return send(res, 400, { error: 'Укажите корректную ссылку с http:// или https://.' });
        project.link = link;
      } else {
        if (project.kind === 'app') {
        version = String(fields.version || '').trim().slice(0, 30);
        project.version = version;
        }
        if (file?.filename && file.data.length) {
          if (file.data.length > 100 * 1024 * 1024) return send(res, 413, { error: 'Файл больше 100 МБ.' });
          const ext = path.extname(file.filename).toLowerCase().replace(/[^.a-z0-9]/g, '').slice(0, 12);
          const downloadFile = `${randomBytes(10).toString('hex')}${ext}`;
          await writeFile(path.join(storeDir, 'files', downloadFile), file.data);
          const oldFile = project.downloadFile;
          project.downloadFile = downloadFile;
          project.fileName = path.basename(file.filename).slice(0, 160);
          project.downloadPath = `/download/${id}`;
          if (oldFile) await unlink(path.join(storeDir, 'files', path.basename(oldFile))).catch(() => {});
        }
      }
      const notes = String(fields.changelog || '').trim().slice(0, 1200);
      if (notes) {
        project.changelog = Array.isArray(project.changelog) ? project.changelog : [];
        project.changelog.unshift({ version, notes, date: new Date().toISOString() });
        project.changelog = project.changelog.slice(0, 30);
      }
      project.updatedAt = new Date().toISOString();
      await writeFile(storeFile, JSON.stringify(projects, null, 2));
      return send(res, 200, { project });
    }
    if (url.pathname.startsWith('/api/projects/') && req.method === 'DELETE') {
      if (!authorized(req)) return send(res, 401, { error: 'Войдите в режим разработчика.' });
      const id = decodeURIComponent(url.pathname.slice('/api/projects/'.length));
      const projects = await getProjects(); const index = projects.findIndex(item => item.id === id);
      if (index < 0) return send(res, 404, { error: 'Публикация уже удалена или не найдена.' });
      const [project] = projects.splice(index, 1); await writeFile(storeFile, JSON.stringify(projects, null, 2));
      if (project.downloadFile) await unlink(path.join(storeDir, 'files', path.basename(project.downloadFile))).catch(() => {});
      return send(res, 200, { ok: true });
    }
    if (url.pathname.startsWith('/download/') && req.method === 'GET') {
      const id = path.basename(url.pathname.slice('/download/'.length));
      const project = (await getProjects()).find(item => item.id === id && ['app', 'file'].includes(item.kind) && item.downloadFile);
      if (!project) return send(res, 404, { error: 'Файл не найден.' });
      const data = await readFile(path.join(storeDir, 'files', project.downloadFile));
      const safeName = project.fileName.replace(/[\r\n"\\]/g, '_');
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${safeName.replace(/[^\x20-\x7E]/g, '_')}"; filename*=UTF-8''${encodeURIComponent(safeName)}`, 'Content-Length': data.length, 'X-Content-Type-Options': 'nosniff' });
      return res.end(data);
    }
    const requested = path.join(root, 'public', url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname).replace(/^\/+/, ''));
    if (!requested.startsWith(path.join(root, 'public'))) return send(res, 403, { error: 'Forbidden' });
    try { const data = await readFile(requested); res.writeHead(200, { 'Content-Type': mime[path.extname(requested)] || 'application/octet-stream', 'Cache-Control': 'no-store' }); return res.end(data); }
    catch { return send(res, 404, { error: 'Not found' }); }
  } catch (error) { return send(res, 500, { error: 'Не удалось обработать запрос.' }); }
});
server.listen(port, () => console.log(`S1 Studio is running on http://localhost:${port}`));
