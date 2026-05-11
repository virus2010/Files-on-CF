// ============= 在线文本管理器（多文本 / 文件夹式管理 + Ace Editor） =============
// 管理员： https://<worker域名>/<ADMIN_UUID>
// 访   客： https://<worker域名>/sub?token=<自定义Token>&file=<文件路径>
//
// Cloudflare 环境变量：
// ADMIN_UUID      必填：管理员路径 UUID
// ADMIN_PASSWORD  必填：管理员登录密码
// FILENAME        可选：页面标题
//
// KV 绑定名：KV

let ADMIN_UUID = null;
let ADMIN_PASSWORD = null;
let FileName = 'Files on Cloud';

const INDEX_KEY = 'FILES_INDEX_V1';
const FILE_PREFIX = 'FILE:';
const TXT_FILE = 'TEXT.txt'; // 旧版迁移用
const GUEST_TOKEN_KEY = 'GUEST_TOKEN';

const SESSION_COOKIE = 'ADMIN_SESSION';
const SESSION_TTL_SECONDS = 12 * 60 * 60; // 12 小时

const ACE_BASE = 'https://cdnjs.cloudflare.com/ajax/libs/ace/1.32.2';

// ===== HTML 转义，防止 XSS =====
function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[m]));
}

// ===== 安全 JSON 注入 =====
function safeJson(obj) {
  return JSON.stringify(obj).replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
}

// ===== 生成 CSP nonce =====
function createNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// ===== 响应头 =====
function baseHeaders(extra = {}) {
  return {
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    ...extra
  };
}

function htmlHeaders(nonce) {
  return baseHeaders({
    'Content-Type': 'text/html;charset=utf-8',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': [
      "default-src 'none'",
      "base-uri 'none'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "connect-src 'self'",
      "img-src 'self' data:",
      "font-src 'self' data: https://cdnjs.cloudflare.com",
      "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
      `script-src 'nonce-${nonce}' 'unsafe-eval' https://cdnjs.cloudflare.com`,
      "worker-src 'self' blob: https://cdnjs.cloudflare.com"
    ].join('; ')
  });
}

function textHeaders() {
  return baseHeaders({
    'Content-Type': 'text/plain;charset=utf-8'
  });
}

function jsonHeaders() {
  return baseHeaders({
    'Content-Type': 'application/json;charset=utf-8'
  });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: jsonHeaders()
  });
}

function bad(message, status = 400) {
  return jsonResponse({ ok: false, error: message }, status);
}

// ===== CSRF 校验：只用于已登录后的敏感 POST =====
function verifyPostOrigin(request, url) {
  if (request.method !== 'POST') return null;

  const origin = request.headers.get('Origin');

  if (!origin) {
    return new Response('CSRF Detected: missing Origin', {
      status: 403,
      headers: textHeaders()
    });
  }

  if (origin === 'null') {
    return new Response('CSRF Detected: null Origin', {
      status: 403,
      headers: textHeaders()
    });
  }

  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return new Response('CSRF Detected: invalid Origin', {
      status: 403,
      headers: textHeaders()
    });
  }

  if (parsed.origin !== url.origin) {
    return new Response('CSRF Detected: Origin mismatch', {
      status: 403,
      headers: textHeaders()
    });
  }

  const secFetchSite = request.headers.get('Sec-Fetch-Site');
  if (secFetchSite && !['same-origin', 'none'].includes(secFetchSite)) {
    return new Response('CSRF Detected: cross-site request', {
      status: 403,
      headers: textHeaders()
    });
  }

  return null;
}

// ===== Cookie 工具 =====
function parseCookies(request) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const cookies = {};

  for (const part of cookieHeader.split(';')) {
    const [rawName, ...rawValue] = part.trim().split('=');
    if (!rawName) continue;
    cookies[rawName] = rawValue.join('=');
  }

  return cookies;
}

function makeSetCookie(value) {
  return [
    `${SESSION_COOKIE}=${value}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Strict',
    `Max-Age=${SESSION_TTL_SECONDS}`
  ].join('; ');
}

function makeClearCookie() {
  return [
    `${SESSION_COOKIE}=`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Strict',
    'Max-Age=0'
  ].join('; ');
}

// ===== HMAC 签名，用于登录 Cookie =====
async function hmacHex(message, secret) {
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));

  return [...new Uint8Array(sig)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return diff === 0;
}

async function createSessionCookieValue(env) {
  const ts = Date.now().toString();
  const message = `${env.ADMIN_UUID}|${ts}`;
  const sig = await hmacHex(message, env.ADMIN_PASSWORD);

  return `${ts}.${sig}`;
}

async function isLoggedIn(request, env) {
  const cookies = parseCookies(request);
  const raw = cookies[SESSION_COOKIE];

  if (!raw) return false;

  const [ts, sig] = raw.split('.');
  if (!ts || !sig) return false;

  const timestamp = Number(ts);
  if (!Number.isFinite(timestamp)) return false;

  const ageMs = Date.now() - timestamp;
  if (ageMs < 0 || ageMs > SESSION_TTL_SECONDS * 1000) return false;

  const message = `${env.ADMIN_UUID}|${ts}`;
  const expected = await hmacHex(message, env.ADMIN_PASSWORD);

  return timingSafeEqual(sig, expected);
}

// ===== 文件路径工具 =====
function normalizePath(input, allowRoot = false) {
  let raw = String(input || '').replace(/\\/g, '/').trim();

  if (!raw && allowRoot) return '';
  if (!raw) throw new Error('路径不能为空');

  const parts = raw
    .split('/')
    .map(s => s.trim())
    .filter(Boolean);

  if (!parts.length && allowRoot) return '';
  if (!parts.length) throw new Error('路径不能为空');

  for (const part of parts) {
    if (part === '.' || part === '..') throw new Error('路径不能包含 . 或 ..');
    if (/[\x00-\x1F\x7F]/.test(part)) throw new Error('路径不能包含控制字符');
    if (part.length > 80) throw new Error('单段路径过长');
  }

  const path = parts.join('/');

  if (path.length > 240) throw new Error('路径过长');

  return path;
}

function parentFolder(filePath) {
  const parts = filePath.split('/');
  parts.pop();
  return parts.join('/');
}

function fileKey(path) {
  return FILE_PREFIX + path;
}

function dedupe(arr) {
  return [...new Set(arr.filter(v => typeof v === 'string'))];
}

function now() {
  return Date.now();
}

function sortIndex(index) {
  index.folders = dedupe(index.folders || [])
    .map(v => normalizePath(v, true))
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b, 'zh'));

  const map = new Map();

  for (const f of index.files || []) {
    try {
      const path = normalizePath(f.path);
      map.set(path, {
        path,
        updatedAt: Number(f.updatedAt || 0)
      });
    } catch {}
  }

  index.files = [...map.values()].sort((a, b) => a.path.localeCompare(b.path, 'zh'));

  if (!index.selected || !index.files.some(f => f.path === index.selected)) {
    index.selected = index.files[0]?.path || '';
  }

  return index;
}

function ensureParentFolders(index, path) {
  const folder = parentFolder(path);
  if (!folder) return;

  const parts = folder.split('/');
  let cur = '';

  for (const part of parts) {
    cur = cur ? cur + '/' + part : part;
    if (!index.folders.includes(cur)) index.folders.push(cur);
  }
}

// ===== 索引读取 / 保存 =====
async function getIndex(env) {
  const raw = await env.KV.get(INDEX_KEY);

  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      return sortIndex({
        files: parsed.files || [],
        folders: parsed.folders || [],
        selected: parsed.selected || ''
      });
    } catch {}
  }

  // 初次使用，尝试迁移旧版 TEXT.txt
  const legacy = await env.KV.get(TXT_FILE);
  const firstPath = '默认/TEXT.txt';

  await env.KV.put(fileKey(firstPath), legacy || '');

  const index = sortIndex({
    folders: ['默认'],
    files: [
      {
        path: firstPath,
        updatedAt: now()
      }
    ],
    selected: firstPath
  });

  await saveIndex(env, index);
  return index;
}

async function saveIndex(env, index) {
  const cleaned = sortIndex(index);
  await env.KV.put(INDEX_KEY, JSON.stringify(cleaned));
  return cleaned;
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

// ===== 管理端 API =====
async function handleAdminAction(request, env, url) {
  const csrfError = verifyPostOrigin(request, url);
  if (csrfError) return csrfError;

  const action = url.searchParams.get('action') || '';
  const index = await getIndex(env);
  const data = await readJson(request);

  try {
    if (action === 'list') {
      return jsonResponse({ ok: true, index });
    }

    if (action === 'load') {
      const path = normalizePath(data.path);
      const exists = index.files.some(f => f.path === path);
      if (!exists) return bad('文件不存在', 404);

      const content = await env.KV.get(fileKey(path)) || '';

      index.selected = path;
      await saveIndex(env, index);

      return jsonResponse({
        ok: true,
        path,
        content,
        index
      });
    }

    if (action === 'save') {
      const path = normalizePath(data.path);
      const content = String(data.content ?? '');

      if (content.length > 1024 * 1024) {
        return bad('内容过大，当前限制约 1MB', 413);
      }

      const existing = index.files.find(f => f.path === path);

      if (existing) {
        existing.updatedAt = now();
      } else {
        index.files.push({
          path,
          updatedAt: now()
        });
      }

      ensureParentFolders(index, path);
      index.selected = path;

      await env.KV.put(fileKey(path), content, {
        metadata: {
          updatedAt: now()
        }
      });

      const savedIndex = await saveIndex(env, index);

      return jsonResponse({
        ok: true,
        index: savedIndex
      });
    }

    if (action === 'createFile') {
      const path = normalizePath(data.path);

      if (index.files.some(f => f.path === path)) {
        return bad('文件已存在');
      }

      ensureParentFolders(index, path);

      index.files.push({
        path,
        updatedAt: now()
      });

      index.selected = path;

      await env.KV.put(fileKey(path), '');
      const savedIndex = await saveIndex(env, index);

      return jsonResponse({
        ok: true,
        index: savedIndex,
        path
      });
    }

    if (action === 'createFolder') {
      const path = normalizePath(data.path);

      if (!index.folders.includes(path)) {
        index.folders.push(path);
      }

      const savedIndex = await saveIndex(env, index);

      return jsonResponse({
        ok: true,
        index: savedIndex
      });
    }

    if (action === 'deleteFile') {
      const path = normalizePath(data.path);

      index.files = index.files.filter(f => f.path !== path);

      if (index.selected === path) {
        index.selected = index.files[0]?.path || '';
      }

      await env.KV.delete(fileKey(path));
      const savedIndex = await saveIndex(env, index);

      return jsonResponse({
        ok: true,
        index: savedIndex
      });
    }

    if (action === 'deleteFolder') {
      const path = normalizePath(data.path);
      const prefix = path + '/';

      const filesToDelete = index.files.filter(f => f.path.startsWith(prefix));

      for (const f of filesToDelete) {
        await env.KV.delete(fileKey(f.path));
      }

      index.files = index.files.filter(f => !f.path.startsWith(prefix));
      index.folders = index.folders.filter(f => f !== path && !f.startsWith(prefix));

      if (index.selected && index.selected.startsWith(prefix)) {
        index.selected = index.files[0]?.path || '';
      }

      const savedIndex = await saveIndex(env, index);

      return jsonResponse({
        ok: true,
        index: savedIndex
      });
    }

    if (action === 'renameFile') {
      const oldPath = normalizePath(data.oldPath);
      const newPath = normalizePath(data.newPath);

      if (!index.files.some(f => f.path === oldPath)) {
        return bad('原文件不存在', 404);
      }

      if (index.files.some(f => f.path === newPath)) {
        return bad('新文件名已存在');
      }

      const content = await env.KV.get(fileKey(oldPath)) || '';

      await env.KV.put(fileKey(newPath), content);
      await env.KV.delete(fileKey(oldPath));

      for (const f of index.files) {
        if (f.path === oldPath) {
          f.path = newPath;
          f.updatedAt = now();
        }
      }

      ensureParentFolders(index, newPath);

      if (index.selected === oldPath) {
        index.selected = newPath;
      }

      const savedIndex = await saveIndex(env, index);

      return jsonResponse({
        ok: true,
        index: savedIndex,
        path: newPath
      });
    }

    if (action === 'renameFolder') {
      const oldPath = normalizePath(data.oldPath);
      const newPath = normalizePath(data.newPath);

      if (oldPath === newPath) {
        return jsonResponse({ ok: true, index });
      }

      if (newPath.startsWith(oldPath + '/')) {
        return bad('不能把文件夹重命名到自身子目录');
      }

      const oldPrefix = oldPath + '/';
      const newPrefix = newPath + '/';

      const movedFiles = index.files.filter(f => f.path.startsWith(oldPrefix));

      for (const f of movedFiles) {
        const nextPath = newPrefix + f.path.slice(oldPrefix.length);
        const content = await env.KV.get(fileKey(f.path)) || '';
        await env.KV.put(fileKey(nextPath), content);
        await env.KV.delete(fileKey(f.path));
        f.path = nextPath;
        f.updatedAt = now();
      }

      index.folders = index.folders.map(f => {
        if (f === oldPath) return newPath;
        if (f.startsWith(oldPrefix)) return newPrefix + f.slice(oldPrefix.length);
        return f;
      });

      if (!index.folders.includes(newPath)) {
        index.folders.push(newPath);
      }

      if (index.selected && index.selected.startsWith(oldPrefix)) {
        index.selected = newPrefix + index.selected.slice(oldPrefix.length);
      }

      const savedIndex = await saveIndex(env, index);

      return jsonResponse({
        ok: true,
        index: savedIndex
      });
    }

    if (action === 'guestgen') {
      const custom = String(data.custom || '').trim();
      const token = custom || crypto.randomUUID();

      await env.KV.put(GUEST_TOKEN_KEY, token);

      return jsonResponse({
        ok: true,
        token
      });
    }

    return bad('未知操作', 404);
  } catch (err) {
    return bad(err.message || '操作失败');
  }
}

// ===== 主入口 =====
export default {
  async fetch(request, env) {
    ADMIN_UUID = env.ADMIN_UUID || ADMIN_UUID;
    ADMIN_PASSWORD = env.ADMIN_PASSWORD || ADMIN_PASSWORD;
    FileName = env.FILENAME || FileName;

    const url = new URL(request.url);
    const pathname = url.pathname.slice(1);
    const token = url.searchParams.get('token');

    if (!['GET', 'POST'].includes(request.method)) {
      return new Response('Method Not Allowed', {
        status: 405,
        headers: textHeaders()
      });
    }

    if (!ADMIN_UUID || !ADMIN_PASSWORD) {
      const nonce = createNonce();
      return new Response(configErrorPage(nonce), {
        status: 400,
        headers: htmlHeaders(nonce)
      });
    }

    // 管理员路径
    if (pathname === ADMIN_UUID) {
      if (request.method === 'GET' && url.searchParams.get('logout') === '1') {
        return new Response('', {
          status: 302,
          headers: {
            ...baseHeaders(),
            'Location': `/${ADMIN_UUID}`,
            'Set-Cookie': makeClearCookie()
          }
        });
      }

      const loggedIn = await isLoggedIn(request, {
        ADMIN_UUID,
        ADMIN_PASSWORD
      });

      // 登录 POST 不做 CSRF，避免部分环境 Origin:null 导致无法登录
      if (request.method === 'POST' && !loggedIn) {
        const contentType = request.headers.get('Content-Type') || '';

        if (!contentType.includes('application/x-www-form-urlencoded')) {
          return new Response('Unsupported login request', {
            status: 415,
            headers: textHeaders()
          });
        }

        const form = await request.formData();
        const password = String(form.get('password') || '');

        if (!timingSafeEqual(password, ADMIN_PASSWORD)) {
          const nonce = createNonce();
          return new Response(loginPage(nonce, true), {
            status: 401,
            headers: htmlHeaders(nonce)
          });
        }

        const cookieValue = await createSessionCookieValue({
          ADMIN_UUID,
          ADMIN_PASSWORD
        });

        return new Response('', {
          status: 302,
          headers: {
            ...baseHeaders(),
            'Location': `/${ADMIN_UUID}`,
            'Set-Cookie': makeSetCookie(cookieValue)
          }
        });
      }

      if (!loggedIn) {
        const nonce = createNonce();
        return new Response(loginPage(nonce, false), {
          headers: htmlHeaders(nonce)
        });
      }

      // 已登录管理 API
      if (request.method === 'POST' && url.searchParams.has('action')) {
        return handleAdminAction(request, env, url);
      }

      // 已登录管理页面
      const index = await getIndex(env);
      const selectedPath = index.selected || index.files[0]?.path || '';
      const content = selectedPath ? await env.KV.get(fileKey(selectedPath)) || '' : '';
      const nonce = createNonce();

      return new Response(adminPage(content, index, nonce), {
        headers: htmlHeaders(nonce)
      });
    }

    // 访客查看
    if (url.pathname === '/sub' && token) {
      if (request.method !== 'GET') {
        return new Response('Method Not Allowed', {
          status: 405,
          headers: textHeaders()
        });
      }

      const saved = await env.KV.get(GUEST_TOKEN_KEY);

      if (!saved || token !== saved) {
        return new Response('Token invalid', {
          status: 403,
          headers: textHeaders()
        });
      }

      const index = await getIndex(env);
      const fileParam = url.searchParams.get('file');
      let path = '';

      try {
        path = fileParam ? normalizePath(fileParam) : index.selected;
      } catch {
        return new Response('Invalid file path', {
          status: 400,
          headers: textHeaders()
        });
      }

      if (!path || !index.files.some(f => f.path === path)) {
        return new Response('File not found', {
          status: 404,
          headers: textHeaders()
        });
      }

      const data = await env.KV.get(fileKey(path)) || '';

      return new Response(data, {
        headers: textHeaders()
      });
    }

    return new Response('Not Found', {
      status: 404,
      headers: textHeaders()
    });
  }
};

// ===== 配置错误页 =====
function configErrorPage(nonce) {
  return `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>配置错误</title>
<style nonce="${nonce}">
body{margin:0;padding:24px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f7f8fa;color:#24292f}
main{max-width:720px;margin:40px auto;background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:20px}
code{background:#f6f8fa;padding:2px 6px;border-radius:4px}
</style>
</head>
<body>
<main>
<h1>⚠️ 请先设置环境变量</h1>
<p>必须设置：</p>
<ul>
  <li><code>ADMIN_UUID</code></li>
  <li><code>ADMIN_PASSWORD</code></li>
</ul>
<p>可选设置：</p>
<ul>
  <li><code>FILENAME</code></li>
</ul>
</main>
</body>
</html>`;
}

// ===== 登录页 =====
function loginPage(nonce, failed) {
  const safeFileName = escapeHtml(FileName);

  return `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${safeFileName} 登录</title>
<style nonce="${nonce}">
body{margin:0;padding:24px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f7f8fa;color:#24292f}
main{max-width:420px;margin:80px auto;background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:20px;box-shadow:0 8px 24px rgba(140,149,159,.2)}
h1{font-size:20px;margin:0 0 16px}
label{display:block;margin-bottom:8px;font-weight:600}
input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #d0d7de;border-radius:6px;font-size:14px}
button{margin-top:14px;width:100%;padding:10px;border:none;border-radius:6px;background:#238636;color:#fff;cursor:pointer;font-size:14px}
.error{margin:0 0 12px;padding:10px;border:1px solid #ffebe9;border-radius:6px;background:#fff1f0;color:#cf222e}
.small{margin-top:12px;color:#57606a;font-size:12px;line-height:1.5}
</style>
</head>
<body>
<main>
  <h1>${safeFileName} 管理员登录</h1>
  ${failed ? '<div class="error">密码错误</div>' : ''}
  <form method="post" action="">
    <label for="password">管理员密码</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">登录</button>
  </form>
  <p class="small">登录成功后会创建 HttpOnly 安全 Cookie，有效期 12 小时。</p>
</main>
</body>
</html>`;
}

// ===== 管理页 =====
function adminPage(content, index, nonce) {
  const safeContent = escapeHtml(content);
  const safeFileName = escapeHtml(FileName);
  const safeIndex = safeJson(index);

  return `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${safeFileName} 管理器</title>
<style nonce="${nonce}">
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:14px;background:#f7f8fa;color:#24292f}
header{padding:12px 14px;background:#fff;border-bottom:1px solid #d0d7de;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
h1{font-size:18px;margin:0}
a{color:inherit;text-decoration:none}
.main{display:grid;grid-template-columns:280px 1fr;height:calc(100vh - 58px)}
.sidebar{border-right:1px solid #d0d7de;background:#fff;overflow:auto;padding:10px;box-sizing:border-box}
.content{padding:10px;box-sizing:border-box;min-width:0;display:flex;flex-direction:column}
.toolbar{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:8px}
button{padding:6px 12px;border:none;border-radius:6px;background:#238636;color:#fff;cursor:pointer}
button.secondary{background:#57606a}
button.danger{background:#cf222e}
button.small{padding:3px 7px;font-size:12px}
button:disabled{opacity:.6;cursor:not-allowed}
select{padding:6px 8px;border:1px solid #d0d7de;border-radius:6px;background:#fff;color:#24292f}
input{box-sizing:border-box;padding:6px;border:1px solid #d0d7de;border-radius:4px}
.sideTitle{font-weight:700;margin:8px 0}
.sideActions{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.folder{margin-top:9px;padding:5px 6px;background:#f6f8fa;border-radius:6px;color:#57606a;font-weight:600;display:flex;justify-content:space-between;gap:6px}
.file{padding:6px 8px;margin:2px 0 2px 12px;border-radius:6px;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.file:hover{background:#f6f8fa}
.file.active{background:#ddf4ff;color:#0969da;font-weight:600}
.rootHint{color:#8c959f;font-size:12px;margin:6px 0}
.pathBar{font-family:ui-monospace,SFMono-Regular,SFMono,Consolas,"Liberation Mono",Menlo,monospace;font-size:12px;color:#57606a;margin-bottom:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#editor{width:100%;flex:1;min-height:360px;border:1px solid #d0d7de;border-radius:6px;box-sizing:border-box;background:#fff}
#initialContent{display:none}
#share{margin-top:10px;padding:10px;border:1px dashed #d0d7de;border-radius:6px;background:#fff}
#share input{width:100%;margin-top:4px;font-family:ui-monospace,SFMono-Regular,SFMono,Consolas,"Liberation Mono",Menlo,monospace}
#linkArea{margin-top:8px;display:none}
#status,#tokenStatus{color:#57606a}
.warning{margin-top:8px;color:#9a6700;font-size:13px;line-height:1.5}
.logout{color:#cf222e}
@media(max-width:760px){
  .main{grid-template-columns:1fr;height:auto}
  .sidebar{border-right:none;border-bottom:1px solid #d0d7de;max-height:260px}
  .content{height:calc(100vh - 320px);min-height:520px}
}
</style>
<script nonce="${nonce}" src="${ACE_BASE}/ace.js" crossorigin="anonymous"></script>
</head>
<body>
<header>
  <h1>${safeFileName} 管理器</h1>
  <div>
    <a href="https://github.com/ethgan/Online-Text-Edit" target="_blank" rel="noopener noreferrer">GitHub</a>
    &nbsp;&nbsp;
    <a class="logout" href="?logout=1">退出登录</a>
  </div>
</header>

<div class="main">
  <aside class="sidebar">
    <div class="sideTitle">文件管理</div>
    <div class="sideActions">
      <button id="newFileBtn" class="small" type="button">新建文件</button>
      <button id="newFolderBtn" class="small secondary" type="button">新建文件夹</button>
    </div>
    <div class="rootHint">文件路径示例：配置/yaml/config.yaml</div>
    <div id="fileTree"></div>
  </aside>

  <section class="content">
    <div class="toolbar">
      <button id="saveBtn" type="button">保存内容</button>
      <button id="renameBtn" class="secondary" type="button">重命名文件</button>
      <button id="deleteBtn" class="danger" type="button">删除文件</button>

      <select id="modeSelect" title="语法模式">
        <option value="text">Text</option>
        <option value="javascript">JavaScript</option>
        <option value="json">JSON</option>
        <option value="html">HTML</option>
        <option value="css">CSS</option>
        <option value="markdown">Markdown</option>
        <option value="yaml">YAML</option>
        <option value="sh">Shell</option>
        <option value="python">Python</option>
      </select>

      <select id="themeSelect" title="主题">
        <option value="github">GitHub</option>
        <option value="chrome">Chrome</option>
        <option value="monokai">Monokai</option>
        <option value="tomorrow">Tomorrow</option>
        <option value="xcode">Xcode</option>
      </select>

      <button id="wrapBtn" class="secondary" type="button">开启换行</button>
      <span id="status"></span>
    </div>

    <div id="pathBar" class="pathBar"></div>

    <textarea id="initialContent">${safeContent}</textarea>
    <div id="editor"></div>

    <div id="share">
      <strong>访客 Token 设置</strong><br>
      <input id="customToken" placeholder="留空则随机生成 UUID">
      <button id="genBtn" type="button">生成 / 更新当前文件访客链接</button>
      <span id="tokenStatus"></span>
      <div id="linkArea">
        当前文件访客地址：
        <input id="url" readonly>
      </div>
      <div class="warning">
        提醒：访客链接等同于读取密码。任何拿到链接的人都可以读取对应文件内容。
      </div>
    </div>
  </section>
</div>

<script nonce="${nonce}">
let fileIndex = ${safeIndex};
let currentPath = fileIndex.selected || (fileIndex.files[0] && fileIndex.files[0].path) || '';

const initialContent = document.getElementById('initialContent');
const fileTree = document.getElementById('fileTree');
const pathBar = document.getElementById('pathBar');
const statusEl = document.getElementById('status');
const tokenStatus = document.getElementById('tokenStatus');
const customToken = document.getElementById('customToken');
const urlInput = document.getElementById('url');
const linkArea = document.getElementById('linkArea');

const saveBtn = document.getElementById('saveBtn');
const renameBtn = document.getElementById('renameBtn');
const deleteBtn = document.getElementById('deleteBtn');
const newFileBtn = document.getElementById('newFileBtn');
const newFolderBtn = document.getElementById('newFolderBtn');
const genBtn = document.getElementById('genBtn');
const wrapBtn = document.getElementById('wrapBtn');
const modeSelect = document.getElementById('modeSelect');
const themeSelect = document.getElementById('themeSelect');

ace.config.set('basePath', '${ACE_BASE}');
ace.config.set('modePath', '${ACE_BASE}');
ace.config.set('themePath', '${ACE_BASE}');
ace.config.set('workerPath', '${ACE_BASE}');

const editor = ace.edit('editor', {
  readOnly: false
});

editor.setValue(initialContent.value || '', -1);
editor.setTheme('ace/theme/github');
editor.session.setUseWorker(false);
editor.session.setTabSize(2);
editor.session.setUseSoftTabs(true);
editor.session.setUseWrapMode(false);
editor.setReadOnly(false);

editor.setOptions({
  fontSize: '14px',
  showPrintMargin: false,
  highlightActiveLine: true,
  highlightSelectedWord: true,
  useWorker: false,
  readOnly: false
});

editor.commands.addCommand({
  name: 'saveContent',
  bindKey: {
    win: 'Ctrl-S',
    mac: 'Command-S'
  },
  exec: function () {
    saveContent();
  }
});

function setStatus(text) {
  statusEl.textContent = text;
}

function api(action, data) {
  return fetch(location.pathname + '?action=' + encodeURIComponent(action), {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data || {})
  }).then(async res => {
    const json = await res.json().catch(() => ({}));
    if (!res.ok || !json.ok) {
      throw new Error(json.error || '请求失败');
    }
    return json;
  });
}

function parentOf(path) {
  const parts = path.split('/');
  parts.pop();
  return parts.join('/');
}

function nameOf(path) {
  return path.split('/').pop();
}

function detectMode(path) {
  const lower = path.toLowerCase();

  if (lower.endsWith('.js') || lower.endsWith('.mjs') || lower.endsWith('.cjs')) return 'javascript';
  if (lower.endsWith('.json')) return 'json';
  if (lower.endsWith('.html') || lower.endsWith('.htm')) return 'html';
  if (lower.endsWith('.css')) return 'css';
  if (lower.endsWith('.md') || lower.endsWith('.markdown')) return 'markdown';
  if (lower.endsWith('.yaml') || lower.endsWith('.yml')) return 'yaml';
  if (lower.endsWith('.sh') || lower.endsWith('.bash')) return 'sh';
  if (lower.endsWith('.py')) return 'python';

  return 'text';
}

function applyModeByPath(path) {
  const mode = detectMode(path);
  modeSelect.value = mode;
  editor.session.setMode('ace/mode/' + mode);
  editor.session.setUseWorker(false);
}

function renderTree() {
  fileTree.innerHTML = '';

  const folders = [''].concat(fileIndex.folders || []);
  const files = fileIndex.files || [];

  const used = new Set();

  for (const folder of folders) {
    const groupFiles = files.filter(f => parentOf(f.path) === folder);

    if (folder && !groupFiles.length && !(fileIndex.folders || []).some(x => parentOf(x) === folder)) {
      continue;
    }

    if (folder) {
      const folderRow = document.createElement('div');
      folderRow.className = 'folder';

      const label = document.createElement('span');
      label.textContent = '📁 ' + folder;

      const actions = document.createElement('span');

      const rename = document.createElement('button');
      rename.className = 'small secondary';
      rename.textContent = '改名';
      rename.addEventListener('click', () => renameFolder(folder));

      const del = document.createElement('button');
      del.className = 'small danger';
      del.textContent = '删';
      del.addEventListener('click', () => deleteFolder(folder));

      actions.appendChild(rename);
      actions.appendChild(del);

      folderRow.appendChild(label);
      folderRow.appendChild(actions);
      fileTree.appendChild(folderRow);
    } else {
      const root = document.createElement('div');
      root.className = 'folder';
      root.textContent = '📁 根目录';
      fileTree.appendChild(root);
    }

    for (const f of groupFiles) {
      used.add(f.path);

      const item = document.createElement('div');
      item.className = 'file' + (f.path === currentPath ? ' active' : '');
      item.textContent = '📄 ' + nameOf(f.path);
      item.title = f.path;
      item.addEventListener('click', () => loadFile(f.path));
      fileTree.appendChild(item);
    }
  }

  // 兜底：如果某些文件的父目录不在 folders 中，也显示出来
  for (const f of files) {
    if (used.has(f.path)) continue;

    const item = document.createElement('div');
    item.className = 'file' + (f.path === currentPath ? ' active' : '');
    item.textContent = '📄 ' + f.path;
    item.title = f.path;
    item.addEventListener('click', () => loadFile(f.path));
    fileTree.appendChild(item);
  }

  pathBar.textContent = currentPath ? '当前文件：' + currentPath : '当前没有文件';
}

async function loadFile(path) {
  try {
    setStatus('正在读取...');
    const res = await api('load', { path });

    fileIndex = res.index;
    currentPath = res.path;

    editor.setValue(res.content || '', -1);
    applyModeByPath(currentPath);
    renderTree();

    setStatus('✅ 已打开');
    setTimeout(() => {
      editor.resize(true);
      editor.renderer.updateFull();
      editor.focus();
    }, 80);
  } catch (err) {
    setStatus('❌ ' + err.message);
  }
}

async function saveContent() {
  if (!currentPath) {
    setStatus('❌ 请先新建文件');
    return;
  }

  saveBtn.disabled = true;
  setStatus('正在保存...');

  try {
    const res = await api('save', {
      path: currentPath,
      content: editor.getValue()
    });

    fileIndex = res.index;
    renderTree();
    setStatus('✅ 已保存');
  } catch (err) {
    setStatus('❌ ' + err.message);
  } finally {
    saveBtn.disabled = false;
  }
}

async function createFile() {
  const path = prompt('请输入文件路径，例如：配置/yaml/config.yaml');
  if (!path) return;

  try {
    const res = await api('createFile', { path });
    fileIndex = res.index;
    currentPath = res.path;
    editor.setValue('', -1);
    applyModeByPath(currentPath);
    renderTree();
    setStatus('✅ 文件已创建');
  } catch (err) {
    setStatus('❌ ' + err.message);
  }
}

async function createFolder() {
  const path = prompt('请输入文件夹路径，例如：配置/yaml');
  if (!path) return;

  try {
    const res = await api('createFolder', { path });
    fileIndex = res.index;
    renderTree();
    setStatus('✅ 文件夹已创建');
  } catch (err) {
    setStatus('❌ ' + err.message);
  }
}

async function renameFile() {
  if (!currentPath) {
    setStatus('❌ 当前没有文件');
    return;
  }

  const next = prompt('请输入新的文件路径', currentPath);
  if (!next || next === currentPath) return;

  try {
    const res = await api('renameFile', {
      oldPath: currentPath,
      newPath: next
    });

    fileIndex = res.index;
    currentPath = res.path;
    applyModeByPath(currentPath);
    renderTree();
    setStatus('✅ 文件已重命名');
  } catch (err) {
    setStatus('❌ ' + err.message);
  }
}

async function deleteFile() {
  if (!currentPath) {
    setStatus('❌ 当前没有文件');
    return;
  }

  if (!confirm('确定删除文件？\\n' + currentPath)) return;

  try {
    const res = await api('deleteFile', { path: currentPath });
    fileIndex = res.index;
    currentPath = fileIndex.selected || (fileIndex.files[0] && fileIndex.files[0].path) || '';

    if (currentPath) {
      await loadFile(currentPath);
    } else {
      editor.setValue('', -1);
      renderTree();
      setStatus('✅ 文件已删除');
    }
  } catch (err) {
    setStatus('❌ ' + err.message);
  }
}

async function renameFolder(path) {
  const next = prompt('请输入新的文件夹路径', path);
  if (!next || next === path) return;

  try {
    const res = await api('renameFolder', {
      oldPath: path,
      newPath: next
    });

    fileIndex = res.index;
    currentPath = fileIndex.selected || currentPath;
    renderTree();
    setStatus('✅ 文件夹已重命名');
  } catch (err) {
    setStatus('❌ ' + err.message);
  }
}

async function deleteFolder(path) {
  if (!confirm('确定删除这个文件夹及其下面的所有文件？\\n' + path)) return;

  try {
    const res = await api('deleteFolder', { path });
    fileIndex = res.index;
    currentPath = fileIndex.selected || (fileIndex.files[0] && fileIndex.files[0].path) || '';

    if (currentPath) {
      await loadFile(currentPath);
    } else {
      editor.setValue('', -1);
      renderTree();
      setStatus('✅ 文件夹已删除');
    }
  } catch (err) {
    setStatus('❌ ' + err.message);
  }
}

saveBtn.addEventListener('click', saveContent);
newFileBtn.addEventListener('click', createFile);
newFolderBtn.addEventListener('click', createFolder);
renameBtn.addEventListener('click', renameFile);
deleteBtn.addEventListener('click', deleteFile);

modeSelect.addEventListener('change', () => {
  editor.session.setMode('ace/mode/' + modeSelect.value);
  editor.session.setUseWorker(false);
  editor.focus();
});

themeSelect.addEventListener('change', () => {
  editor.setTheme('ace/theme/' + themeSelect.value);
  editor.focus();
});

wrapBtn.addEventListener('click', () => {
  const now = !editor.session.getUseWrapMode();
  editor.session.setUseWrapMode(now);
  wrapBtn.textContent = now ? '关闭换行' : '开启换行';
  editor.focus();
});

genBtn.addEventListener('click', async () => {
  if (!currentPath) {
    tokenStatus.textContent = '❌ 请先选择文件';
    return;
  }

  const custom = customToken.value.trim();

  genBtn.disabled = true;
  tokenStatus.textContent = '正在生成...';

  try {
    const res = await api('guestgen', { custom });
    const visitorUrl =
      location.origin +
      '/sub?token=' +
      encodeURIComponent(res.token) +
      '&file=' +
      encodeURIComponent(currentPath);

    urlInput.value = visitorUrl;
    linkArea.style.display = 'block';
    tokenStatus.textContent = '✅ 已更新';
  } catch (err) {
    tokenStatus.textContent = '❌ ' + err.message;
  } finally {
    genBtn.disabled = false;
  }
});

if (currentPath) {
  applyModeByPath(currentPath);
}

renderTree();

setTimeout(() => {
  editor.resize(true);
  editor.renderer.updateFull();
  editor.focus();
}, 300);
</script>
</body>
</html>`;
}
