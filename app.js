const express = require('express');
const basicAuth = require('basic-auth');
const axios = require('axios');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();

const PORT = parseInt(process.env.PORT || '3000', 10);
const DATA_DIR = process.env.DATA_DIR || '/app/data';
const DATA_FILE = path.join(DATA_DIR, 'data.json');
const CREDENTIALS_FILE = path.join(DATA_DIR, 'credentials.json');

const USERNAME = process.env.USERNAME;
const PASSWORD = process.env.PASSWORD;
const SUB_TOKEN = process.env.SUB_TOKEN;
const API_URL = process.env.API_URL || '';
const REQUEST_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_MS || '10000', 10);
const MAX_SUBSCRIPTIONS = parseInt(process.env.MAX_SUBSCRIPTIONS || '200', 10);
const MAX_NODES = parseInt(process.env.MAX_NODES || '5000', 10);

if (!USERNAME || USERNAME.length < 3) {
  throw new Error('USERNAME is required and must be at least 3 chars');
}
if (!PASSWORD || PASSWORD.length < 7) {
  throw new Error('PASSWORD is required and must be at least 10 chars');
}
if (!SUB_TOKEN || SUB_TOKEN.length < 7) {
  throw new Error('SUB_TOKEN is required and must be at least 20 chars');
}

app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.json({ limit: '1mb' }));

let state = {
  subscriptions: [],
  nodes: [],
};

let credentials = {
  username: USERNAME,
  passwordHash: '',
};

function escapeHtml(input) {
  return String(input)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function isValidHttpUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

function normalizeLines(input) {
  return String(input || '')
    .split('\n')
    .map(v => v.trim())
    .filter(Boolean);
}

function normalizeSubscription(input) {
  const value = String(input || '').trim();
  if (!isValidHttpUrl(value)) {
    throw new Error(`invalid subscription url: ${value}`);
  }
  return value;
}

function looksLikeProxyNode(line) {
  return /^(vmess|vless|trojan|ss|ssr|snell|juicity|hysteria|hysteria2|tuic|anytls|wireguard|socks5|http|https):\/\//i.test(line);
}

function tryDecodeBase64(line) {
  const value = String(line || '').trim();
  if (!value) return '';
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  if (!base64Regex.test(value)) return value;

  try {
    const decoded = Buffer.from(value, 'base64').toString('utf8').trim();
    if (looksLikeProxyNode(decoded)) {
      return decoded;
    }
    return value;
  } catch {
    return value;
  }
}

function normalizeNode(input) {
  const line = tryDecodeBase64(String(input || '').trim());
  if (!looksLikeProxyNode(line)) {
    throw new Error(`invalid node line: ${line.slice(0, 32)}...`);
  }
  return line;
}

function uniqueArray(items) {
  return [...new Set(items)];
}

async function ensureDataDir() {
  await fs.mkdir(DATA_DIR, { recursive: true });
}

async function saveState() {
  const payload = {
    subscriptions: state.subscriptions,
    nodes: state.nodes,
  };
  await fs.writeFile(DATA_FILE, JSON.stringify(payload, null, 2), 'utf8');
}

async function loadState() {
  try {
    const raw = await fs.readFile(DATA_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    state.subscriptions = Array.isArray(parsed.subscriptions) ? parsed.subscriptions : [];
    state.nodes = Array.isArray(parsed.nodes) ? parsed.nodes : [];
  } catch {
    state = { subscriptions: [], nodes: [] };
    await saveState();
  }
}

async function saveCredentials() {
  await fs.writeFile(CREDENTIALS_FILE, JSON.stringify(credentials, null, 2), 'utf8');
}

async function loadCredentials() {
  try {
    const raw = await fs.readFile(CREDENTIALS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (
      parsed &&
      typeof parsed.username === 'string' &&
      typeof parsed.passwordHash === 'string' &&
      parsed.username &&
      parsed.passwordHash
    ) {
      credentials = parsed;
      return;
    }
  } catch {
    // ignore and initialize below
  }

  credentials = {
    username: USERNAME,
    passwordHash: await bcrypt.hash(PASSWORD, 12),
  };
  await saveCredentials();
}

async function verifyAuth(req) {
  const user = basicAuth(req);
  if (!user) return false;
  if (user.name !== credentials.username) return false;
  return bcrypt.compare(user.pass || '', credentials.passwordHash);
}

async function auth(req, res, next) {
  const ok = await verifyAuth(req);
  if (!ok) {
    res.set('WWW-Authenticate', 'Basic realm="merge-sub-secure"');
    return res.status(401).send('Unauthorized');
  }
  next();
}

function renderAdminPage(message = '', error = '') {
  const msgHtml = message ? `<div class="ok">${escapeHtml(message)}</div>` : '';
  const errHtml = error ? `<div class="err">${escapeHtml(error)}</div>` : '';

  const subList = state.subscriptions.map(v => `<li><code>${escapeHtml(v)}</code></li>`).join('');
  const nodeList = state.nodes.map(v => `<li><code>${escapeHtml(v)}</code></li>`).join('');

  const rawSubUrl = `/${SUB_TOKEN}`;
  const qxUrl = API_URL
    ? `${API_URL}/sub?target=quanx&url=${encodeURIComponent(rawSubUrl.startsWith('http') ? rawSubUrl : '')}`
    : '';
  const note = API_URL
    ? '已配置 API_URL，可在页面中自行拼接转换链接。'
    : '未配置 API_URL；这很正常，表示你没有依赖第三方转换器。';

  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>merge-sub-secure</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; line-height: 1.5; color: #111; }
    h1,h2 { margin-bottom: 8px; }
    .card { border: 1px solid #ddd; border-radius: 10px; padding: 16px; margin-bottom: 18px; }
    textarea, input[type="text"], input[type="password"] { width: 100%; box-sizing: border-box; padding: 10px; margin: 8px 0 12px; }
    button { padding: 10px 14px; cursor: pointer; }
    code { word-break: break-all; }
    .ok { background: #eef9ee; border: 1px solid #b7e0b7; padding: 10px; margin-bottom: 12px; border-radius: 8px; }
    .err { background: #fff2f2; border: 1px solid #efb4b4; padding: 10px; margin-bottom: 12px; border-radius: 8px; }
    ul { padding-left: 18px; }
    .muted { color: #666; }
  </style>
</head>
<body>
  <h1>merge-sub-secure</h1>
  <p class="muted">统一维护订阅与节点；原始订阅路径：<code>${escapeHtml(rawSubUrl)}</code></p>
  ${msgHtml}
  ${errHtml}

  <div class="card">
    <h2>添加订阅</h2>
    <form method="post" action="/admin/subscriptions/add">
      <textarea name="subscription" rows="6" placeholder="每行一个订阅 URL"></textarea>
      <button type="submit">添加订阅</button>
    </form>
  </div>

  <div class="card">
    <h2>删除订阅</h2>
    <form method="post" action="/admin/subscriptions/delete">
      <textarea name="subscription" rows="6" placeholder="每行一个订阅 URL"></textarea>
      <button type="submit">删除订阅</button>
    </form>
  </div>

  <div class="card">
    <h2>添加节点</h2>
    <form method="post" action="/admin/nodes/add">
      <textarea name="node" rows="8" placeholder="每行一个 vmess:// 或 vless:// 等节点"></textarea>
      <button type="submit">添加节点</button>
    </form>
  </div>

  <div class="card">
    <h2>删除节点</h2>
    <form method="post" action="/admin/nodes/delete">
      <textarea name="node" rows="8" placeholder="每行一个完整节点"></textarea>
      <button type="submit">删除节点</button>
    </form>
  </div>

  <div class="card">
    <h2>修改后台账号密码</h2>
    <form method="post" action="/admin/credentials/update">
      <input type="text" name="username" placeholder="新用户名" />
      <input type="password" name="currentPassword" placeholder="当前密码" />
      <input type="password" name="newPassword" placeholder="新密码（建议 16 位以上）" />
      <button type="submit">更新账号密码</button>
    </form>
  </div>

  <div class="card">
    <h2>当前订阅</h2>
    <ul>${subList || '<li>暂无</li>'}</ul>
  </div>

  <div class="card">
    <h2>当前节点</h2>
    <ul>${nodeList || '<li>暂无</li>'}</ul>
  </div>

  <div class="card">
    <h2>客户端用法</h2>
    <p>v2rayN / v2rayNG 直接订阅：<code>${escapeHtml(rawSubUrl)}</code></p>
    <p>${escapeHtml(note)}</p>
    <p class="muted">建议最终通过你的自定义域名访问，而不是 Northflank 临时域名。</p>
  </div>
</body>
</html>`;
}

app.get('/healthz', (_req, res) => {
  res.status(200).send('ok');
});

app.get('/', (_req, res) => {
  res.status(200).send(
    `merge-sub-secure is running.
health: /healthz
subscription: /${SUB_TOKEN}
admin: /admin`
  );
});

app.get(`/${SUB_TOKEN}`, async (_req, res) => {
  try {
    const merged = [];

    for (const sub of state.subscriptions) {
      try {
        const response = await axios.get(sub, {
          timeout: REQUEST_TIMEOUT_MS,
          responseType: 'text',
          maxRedirects: 3,
          validateStatus: s => s >= 200 && s < 400,
        });

        const text = String(response.data || '').trim();
        const decoded = tryDecodeBase64(text);
        const lines = normalizeLines(decoded);
        for (const line of lines) {
          if (looksLikeProxyNode(line)) {
            merged.push(line);
          }
        }
      } catch {
        // 单个上游失败时跳过，不中断整体
      }
    }

    for (const node of state.nodes) {
      merged.push(node);
    }

    const uniq = uniqueArray(merged);

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(Buffer.from(uniq.join('\n'), 'utf8').toString('base64'));
  } catch {
    res.status(500).send('failed to generate subscription');
  }
});

app.get('/admin', auth, (_req, res) => {
  res.status(200).send(renderAdminPage());
});

app.post('/admin/subscriptions/add', auth, async (req, res) => {
  try {
    const lines = normalizeLines(req.body.subscription).map(normalizeSubscription);
    if (!lines.length) {
      return res.status(400).send(renderAdminPage('', '没有可添加的订阅'));
    }

    const next = uniqueArray([...state.subscriptions, ...lines]);
    if (next.length > MAX_SUBSCRIPTIONS) {
      return res.status(400).send(renderAdminPage('', `订阅数量超过上限 ${MAX_SUBSCRIPTIONS}`));
    }

    const added = next.length - state.subscriptions.length;
    state.subscriptions = next;
    await saveState();
    res.status(200).send(renderAdminPage(`成功添加 ${added} 个订阅`, ''));
  } catch (err) {
    res.status(400).send(renderAdminPage('', err.message || '添加订阅失败'));
  }
});

app.post('/admin/subscriptions/delete', auth, async (req, res) => {
  try {
    const lines = normalizeLines(req.body.subscription).map(normalizeSubscription);
    if (!lines.length) {
      return res.status(400).send(renderAdminPage('', '没有可删除的订阅'));
    }

    const before = state.subscriptions.length;
    state.subscriptions = state.subscriptions.filter(v => !lines.includes(v));
    const removed = before - state.subscriptions.length;
    await saveState();
    res.status(200).send(renderAdminPage(`成功删除 ${removed} 个订阅`, ''));
  } catch (err) {
    res.status(400).send(renderAdminPage('', err.message || '删除订阅失败'));
  }
});

app.post('/admin/nodes/add', auth, async (req, res) => {
  try {
    const lines = normalizeLines(req.body.node).map(normalizeNode);
    if (!lines.length) {
      return res.status(400).send(renderAdminPage('', '没有可添加的节点'));
    }

    const next = uniqueArray([...state.nodes, ...lines]);
    if (next.length > MAX_NODES) {
      return res.status(400).send(renderAdminPage('', `节点数量超过上限 ${MAX_NODES}`));
    }

    const added = next.length - state.nodes.length;
    state.nodes = next;
    await saveState();
    res.status(200).send(renderAdminPage(`成功添加 ${added} 个节点`, ''));
  } catch (err) {
    res.status(400).send(renderAdminPage('', err.message || '添加节点失败'));
  }
});

app.post('/admin/nodes/delete', auth, async (req, res) => {
  try {
    const lines = normalizeLines(req.body.node).map(v => tryDecodeBase64(v).trim()).filter(Boolean);
    if (!lines.length) {
      return res.status(400).send(renderAdminPage('', '没有可删除的节点'));
    }

    const before = state.nodes.length;
    state.nodes = state.nodes.filter(v => !lines.includes(v));
    const removed = before - state.nodes.length;
    await saveState();
    res.status(200).send(renderAdminPage(`成功删除 ${removed} 个节点`, ''));
  } catch (err) {
    res.status(400).send(renderAdminPage('', err.message || '删除节点失败'));
  }
});

app.post('/admin/credentials/update', auth, async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const currentPassword = String(req.body.currentPassword || '');
    const newPassword = String(req.body.newPassword || '');

    if (username.length < 3) {
      return res.status(400).send(renderAdminPage('', '用户名至少 3 位'));
    }
    if (newPassword.length < 10) {
      return res.status(400).send(renderAdminPage('', '新密码至少 10 位'));
    }

    const ok = await bcrypt.compare(currentPassword, credentials.passwordHash);
    if (!ok) {
      return res.status(400).send(renderAdminPage('', '当前密码错误'));
    }

    credentials = {
      username,
      passwordHash: await bcrypt.hash(newPassword, 12),
    };

    await saveCredentials();
    res.status(200).send(renderAdminPage('账号密码更新成功', ''));
  } catch {
    res.status(500).send(renderAdminPage('', '更新账号密码失败'));
  }
});

async function bootstrap() {
  await ensureDataDir();
  await loadState();
  await loadCredentials();

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`merge-sub-secure listening on ${PORT}`);
  });
}

bootstrap().catch(err => {
  console.error('bootstrap failed:', err.message);
  process.exit(1);
});
