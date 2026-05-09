// ============= 在线文本管理器（安全加固版） =============
// 管理员： https://<worker域名>/<ADMIN_UUID>
// 访   客： https://<worker域名>/sub?token=<自定义Token>
//
// Cloudflare 环境变量：
// ADMIN_UUID      必填：管理员路径 UUID
// ADMIN_PASSWORD  必填：管理员登录密码
// FILENAME        可选：页面标题

let ADMIN_UUID = null;
let ADMIN_PASSWORD = null;
let FileName = 'CF-Workers-TXT';

const TXT_FILE = 'TEXT.txt';
const GUEST_TOKEN_KEY = 'GUEST_TOKEN';
const SESSION_COOKIE = 'ADMIN_SESSION';
const SESSION_TTL_SECONDS = 12 * 60 * 60; // 12 小时

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

// ===== 生成 CSP nonce =====
function createNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// ===== 基础安全响应头 =====
function baseHeaders(extra = {}) {
  return {
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    ...extra
  };
}

// ===== HTML 安全响应头，带 CSP =====
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
      `style-src 'nonce-${nonce}'`,
      `script-src 'nonce-${nonce}'`
    ].join('; ')
  });
}

function textHeaders() {
  return baseHeaders({
    'Content-Type': 'text/plain;charset=utf-8'
  });
}

// ===== POST CSRF 校验：用于已登录后的敏感 POST，不用于登录 POST =====
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

    // 基础配置检查
    if (!ADMIN_UUID || !ADMIN_PASSWORD) {
      const nonce = createNonce();

      return new Response(configErrorPage(nonce), {
        status: 400,
        headers: htmlHeaders(nonce)
      });
    }

    // 管理员路径
    if (pathname === ADMIN_UUID) {
      // 登出
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

      // 登录 POST：这里不做 CSRF 校验，避免 Origin:null 导致无法登录
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

      // 未登录时显示登录页
      if (!loggedIn) {
        const nonce = createNonce();

        return new Response(loginPage(nonce, false), {
          headers: htmlHeaders(nonce)
        });
      }

      // 已登录后的管理 POST：保存内容 / 更新访客链接，这里做 CSRF 校验
      if (request.method === 'POST') {
        const csrfError = verifyPostOrigin(request, url);
        if (csrfError) return csrfError;

        const body = await request.text();

        if (body.startsWith('GUESTGEN|')) {
          const custom = body.slice('GUESTGEN|'.length).trim();
          const guestToken = custom || crypto.randomUUID();

          await env.KV.put(GUEST_TOKEN_KEY, guestToken);

          return new Response(guestToken, {
            headers: textHeaders()
          });
        }

        const contentLength = Number(request.headers.get('Content-Length') || 0);
        if (contentLength > 1024 * 1024) {
          return new Response('Content too large', {
            status: 413,
            headers: textHeaders()
          });
        }

        await env.KV.put(TXT_FILE, body, {
          metadata: {
            updatedAt: Date.now()
          }
        });

        return new Response('saved', {
          headers: textHeaders()
        });
      }

      // 已登录后的管理页面
      const content = await env.KV.get(TXT_FILE) || '';
      const nonce = createNonce();

      return new Response(adminPage(content, nonce), {
        headers: htmlHeaders(nonce)
      });
    }

    // 访客查看逻辑
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

      const data = await env.KV.get(TXT_FILE) || '';

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

// ===== 管理页 HTML 模板 =====
function adminPage(content, nonce) {
  const safeContent = escapeHtml(content);
  const safeFileName = escapeHtml(FileName);

  return `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${safeFileName} 管理器</title>
<style nonce="${nonce}">
body{margin:0;padding:15px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:14px;background:#f7f8fa;color:#333}
h1{margin-top:0;font-size:18px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
h1 span{display:flex;align-items:center;gap:12px;font-size:14px;font-weight:400}
a{color:inherit;text-decoration:none;display:inline-flex;align-items:center;gap:2px}
textarea{width:100%;box-sizing:border-box;height:60vh;border:1px solid #d0d7de;border-radius:6px;padding:10px;resize:vertical;font-family:ui-monospace,SFMono-Regular,SFMono,Consolas,"Liberation Mono",Menlo,monospace}
button{margin:8px 4px 0 0;padding:6px 14px;border:none;border-radius:6px;background:#238636;color:#fff;cursor:pointer}
button:disabled{background:#94d3a2;cursor:not-allowed}
#share{margin-top:10px;padding:10px;border:1px dashed #d0d7de;border-radius:6px;background:#fff}
#share input{width:100%;box-sizing:border-box;margin-top:4px;padding:6px;border:1px solid #d0d7de;border-radius:4px;font-family:ui-monospace,SFMono-Regular,SFMono,Consolas,"Liberation Mono",Menlo,monospace}
#linkArea{margin-top:8px;display:none}
#status,#tokenStatus{margin-left:6px;color:#57606a}
.warning{margin-top:8px;color:#9a6700;font-size:13px;line-height:1.5}
.logout{color:#cf222e}
</style>
</head>
<body>
<h1>
  ${safeFileName} 管理器
  <span>
    <a href="https://github.com/ethgan/Online-Text-Edit" target="_blank" rel="noopener noreferrer">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.085 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
      GitHub
    </a>
    <a class="logout" href="?logout=1">退出登录</a>
  </span>
</h1>

<textarea id="editor" placeholder="在此输入内容...">${safeContent}</textarea>
<div>
  <button id="saveBtn" type="button">保存内容</button>
  <span id="status"></span>
</div>

<div id="share">
  <strong>访客 Token 设置</strong><br>
  <input id="customToken" placeholder="留空则随机生成 UUID">
  <button id="genBtn" type="button">更新访客链接</button>
  <span id="tokenStatus"></span>
  <div id="linkArea">
    访客地址，需手动复制：
    <input id="url" readonly>
  </div>
  <div class="warning">
    提醒：访客链接等同于读取密码。任何拿到链接的人都可以读取当前文本。
  </div>
</div>

<script nonce="${nonce}">
const editor = document.getElementById('editor');
const statusEl = document.getElementById('status');
const tokenStatus = document.getElementById('tokenStatus');
const customToken = document.getElementById('customToken');
const urlInput = document.getElementById('url');
const linkArea = document.getElementById('linkArea');
const saveBtn = document.getElementById('saveBtn');
const genBtn = document.getElementById('genBtn');

saveBtn.addEventListener('click', async () => {
  saveBtn.disabled = true;
  statusEl.textContent = '正在保存...';

  try {
    const res = await fetch(location.href, {
      method: 'POST',
      body: editor.value,
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'text/plain'
      }
    });

    statusEl.textContent = res.ok ? '✅ 已保存' : '❌ 保存失败：' + await res.text();
  } catch {
    statusEl.textContent = '❌ 网络错误';
  } finally {
    saveBtn.disabled = false;
  }
});

genBtn.addEventListener('click', async () => {
  const custom = customToken.value.trim();

  genBtn.disabled = true;
  tokenStatus.textContent = '正在生成...';

  try {
    const res = await fetch(location.href, {
      method: 'POST',
      body: 'GUESTGEN|' + custom,
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'text/plain'
      }
    });

    const text = await res.text();

    if (!res.ok) {
      tokenStatus.textContent = '❌ 生成失败：' + text;
      return;
    }

    const visitorUrl = location.origin + '/sub?token=' + encodeURIComponent(text);
    urlInput.value = visitorUrl;
    linkArea.style.display = 'block';
    tokenStatus.textContent = '✅ 已更新';
  } catch {
    tokenStatus.textContent = '❌ 网络错误';
  } finally {
    genBtn.disabled = false;
  }
});
</script>
</body>
</html>`;
}
