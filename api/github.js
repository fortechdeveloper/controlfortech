const crypto = require('crypto');

const GH_API = 'https://api.github.com';
const SESSION_TTL = 24 * 60 * 60 * 1000; // 24 jam

function sign(data) {
  return crypto
    .createHmac('sha256', process.env.SESSION_SECRET || 'default-secret')
    .update(data)
    .digest('hex');
}

function makeToken(user) {
  const payload = Buffer.from(
    JSON.stringify({ u: user, t: Date.now() })
  ).toString('base64url');
  const sig = sign(payload);
  return payload + '.' + sig;
}

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  if (sign(payload) !== sig) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (Date.now() - data.t > SESSION_TTL) return null;
    return data.u;
  } catch (e) {
    return null;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(function (pair) {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

async function ghFetch(path, options) {
  options = options || {};
  const url = GH_API + path;
  const res = await fetch(url, {
    method: options.method || 'GET',
    headers: Object.assign(
      {
        Authorization: 'Bearer ' + process.env.GITHUB_TOKEN,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'fortech-panel'
      },
      options.headers || {}
    ),
    body: options.body
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    data = { raw: text };
  }
  return { ok: res.ok, status: res.status, data: data };
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  let body = {};
  if (req.method === 'POST') {
    if (typeof req.body === 'string') {
      try {
        body = JSON.parse(req.body);
      } catch (e) {
        body = {};
      }
    } else if (req.body && typeof req.body === 'object') {
      body = req.body;
    }
  }

  const action = body.action;
  const cookies = parseCookies(req);

  // ============ LOGIN ============
  if (action === 'login') {
    const username = (body.username || '').trim();
    const password = (body.password || '').trim();

    if (
      username === process.env.ADMIN_USER &&
      password === process.env.ADMIN_PASS
    ) {
      const token = makeToken(username);
      res.setHeader(
        'Set-Cookie',
        'session=' +
          token +
          '; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax; Secure'
      );
      return res.status(200).json({ ok: true });
    }
    return res
      .status(401)
      .json({ ok: false, error: 'Username atau password salah' });
  }

  // ============ LOGOUT ============
  if (action === 'logout') {
    res.setHeader(
      'Set-Cookie',
      'session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure'
    );
    return res.status(200).json({ ok: true });
  }

  // ============ CHECK SESSION ============
  if (action === 'check') {
    const user = verifyToken(cookies.session);
    return res.status(200).json({ ok: true, loggedIn: !!user, user: user });
  }

  // ============ PROTECTED AREA ============
  const user = verifyToken(cookies.session);
  if (!user) {
    return res.status(401).json({ ok: false, error: 'Belum login' });
  }

  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  const branch = process.env.GITHUB_BRANCH || 'main';
  const base = '/repos/' + owner + '/' + repo + '/contents';

  try {
    // ============ LIST ============
    if (action === 'list') {
      const path = (body.path || '').replace(/^\/+/, '');
      const r = await ghFetch(base + '/' + path + '?ref=' + branch);
      if (!r.ok) {
        return res
          .status(r.status)
          .json({ ok: false, error: r.data.message || 'Gagal membaca folder' });
      }
      const items = Array.isArray(r.data) ? r.data : [r.data];
      return res.status(200).json({
        ok: true,
        items: items.map(function (i) {
          return {
            name: i.name,
            path: i.path,
            type: i.type,
            size: i.size,
            sha: i.sha
          };
        })
      });
    }

    // ============ READ ============
    if (action === 'read') {
      const path = (body.path || '').replace(/^\/+/, '');
      if (!path) {
        return res.status(400).json({ ok: false, error: 'Path kosong' });
      }
      const r = await ghFetch(base + '/' + path + '?ref=' + branch);
      if (!r.ok) {
        return res
          .status(r.status)
          .json({ ok: false, error: r.data.message || 'Gagal membaca file' });
      }
      if (r.data.type !== 'file') {
        return res
          .status(400)
          .json({ ok: false, error: 'Bukan file' });
      }
      const content = Buffer.from(r.data.content || '', 'base64').toString(
        'utf-8'
      );
      return res.status(200).json({
        ok: true,
        content: content,
        sha: r.data.sha,
        path: r.data.path
      });
    }

    // ============ WRITE ============
    if (action === 'write') {
      const path = (body.path || '').replace(/^\/+/, '');
      const content = body.content || '';
      const message = body.message || 'Update ' + path + ' via Fortech Panel';
      if (!path) {
        return res.status(400).json({ ok: false, error: 'Path kosong' });
      }

      let sha;
      const g = await ghFetch(base + '/' + path + '?ref=' + branch);
      if (g.ok && g.data && g.data.sha) sha = g.data.sha;

      const payload = {
        message: message,
        content: Buffer.from(content, 'utf-8').toString('base64'),
        branch: branch
      };
      if (sha) payload.sha = sha;

      const r = await ghFetch(base + '/' + path, {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      if (!r.ok) {
        return res
          .status(r.status)
          .json({ ok: false, error: r.data.message || 'Gagal menyimpan' });
      }
      return res.status(200).json({ ok: true });
    }

    // ============ DELETE ============
    if (action === 'delete') {
      const path = (body.path || '').replace(/^\/+/, '');
      if (!path) {
        return res.status(400).json({ ok: false, error: 'Path kosong' });
      }
      const g = await ghFetch(base + '/' + path + '?ref=' + branch);
      if (!g.ok) {
        return res
          .status(404)
          .json({ ok: false, error: 'File tidak ditemukan' });
      }
      const r = await ghFetch(base + '/' + path, {
        method: 'DELETE',
        body: JSON.stringify({
          message: 'Delete ' + path + ' via Fortech Panel',
          sha: g.data.sha,
          branch: branch
        })
      });
      if (!r.ok) {
        return res
          .status(r.status)
          .json({ ok: false, error: r.data.message || 'Gagal menghapus' });
      }
      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ ok: false, error: 'Action tidak dikenal' });
  } catch (e) {
    return res
      .status(500)
      .json({ ok: false, error: e.message || 'Server error' });
  }
};
