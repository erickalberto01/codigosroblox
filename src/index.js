// Worker de Códigos de Roblox: sirve los assets estáticos y la API de comentarios.
// No contiene secretos: la clave de moderación vive SOLO como secreto del Worker
// (env.ADMIN_KEY, configurado en el panel de Cloudflare). Nunca se escribe aquí
// ni en el repo, que es público.

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

function getClientIp(request) {
  var cf = request.headers.get('CF-Connecting-IP');
  if (cf) return cf.trim();
  var forwarded = request.headers.get('X-Forwarded-For');
  if (forwarded) return forwarded.split(',')[0].trim();
  return 'unknown';
}

async function sha256Hex(text) {
  var digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(digest))
    .map(function (b) { return b.toString(16).padStart(2, '0'); })
    .join('');
}

function hasUrl(text) {
  return /https?:\/\/|www\./i.test(text);
}

async function listComments(env) {
  var result = await env.DB.prepare(
    'SELECT id, name, body, created_at FROM comments ORDER BY created_at DESC, id DESC LIMIT 100',
  ).all();
  return json(result.results || [], 200);
}

async function createComment(request, env) {
  var data;
  try {
    data = await request.json();
  } catch (e) {
    return json({ error: 'El cuerpo debe ser JSON válido.' }, 400);
  }
  if (!data || typeof data.body !== 'string') {
    return json({ error: 'Escribe un comentario.' }, 400);
  }
  var body = data.body.trim();
  if (body.length < 1 || body.length > 500) {
    return json({ error: 'El comentario debe tener entre 1 y 500 caracteres.' }, 400);
  }
  if (hasUrl(body)) {
    return json({ error: 'Los comentarios no pueden incluir enlaces.' }, 400);
  }
  var name = 'Anónimo';
  if (typeof data.name === 'string' && data.name.trim().length > 0) {
    if (data.name.trim().length > 50) {
      return json({ error: 'El nombre debe tener como máximo 50 caracteres.' }, 400);
    }
    name = data.name.trim();
  }

  var now = Date.now();
  var ipHash = await sha256Hex(getClientIp(request));
  var last = await env.DB.prepare(
    'SELECT created_at FROM comments WHERE ip_hash = ? ORDER BY created_at DESC LIMIT 1',
  ).bind(ipHash).first();
  if (last && now - last.created_at < 60000) {
    return json({ error: 'Espera un momento antes de publicar otro comentario.' }, 429);
  }

  var inserted = await env.DB.prepare(
    'INSERT INTO comments (name, body, created_at, ip_hash) VALUES (?, ?, ?, ?)',
  ).bind(name, body, now, ipHash).run();
  var id = inserted.meta && inserted.meta.last_row_id;
  var created = { id: id, name: name, body: body, created_at: now };
  if (!id) {
    var row = await env.DB.prepare(
      'SELECT id, name, body, created_at FROM comments WHERE ip_hash = ? ORDER BY id DESC LIMIT 1',
    ).bind(ipHash).first();
    if (row) created = row;
  }
  return json(created, 201);
}

async function deleteComment(id, request, env) {
  // Fail closed: sin secreto configurado, nunca se borra.
  if (!env.ADMIN_KEY) {
    return json({ error: 'La moderación no está configurada.' }, 401);
  }
  if (request.headers.get('X-Admin-Key') !== env.ADMIN_KEY) {
    return json({ error: 'Clave incorrecta.' }, 401);
  }
  var deleted = await env.DB.prepare(
    'DELETE FROM comments WHERE id = ?',
  ).bind(id).run();
  var changes = deleted.meta ? deleted.meta.changes : 0;
  if (!changes) {
    return json({ error: 'El comentario no existe.' }, 404);
  }
  return json({ ok: true }, 200);
}

async function ensureSchema(env) {
  // La tabla se crea sola en la primera llamada a la API, para no depender
  // de un paso manual en el panel. Si esto falla, la consulta siguiente
  // mostrará el error real (por ejemplo, si falta la tabla o el binding).
  var statements = [
    'CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, body TEXT NOT NULL, created_at INTEGER NOT NULL, ip_hash TEXT)',
    'CREATE INDEX IF NOT EXISTS idx_comments_created_at ON comments (created_at DESC)',
  ];
  for (var i = 0; i < statements.length; i++) {
    await env.DB.prepare(statements[i]).run();
  }
}

export default {
  async fetch(request, env, ctx) {
    var url = new URL(request.url);
    var path = url.pathname;

    if (path.startsWith('/api/')) {
      try { await ensureSchema(env); } catch (e) { /* ver nota en ensureSchema */ }
    }

    if (path === '/api/comments') {
      if (request.method === 'GET') return listComments(env);
      if (request.method === 'POST') return createComment(request, env);
      return json({ error: 'Método no permitido.' }, 405);
    }

    if (path.startsWith('/api/comments/')) {
      if (request.method !== 'DELETE') {
        return json({ error: 'Método no permitido.' }, 405);
      }
      var id = Number(path.slice('/api/comments/'.length));
      if (!Number.isInteger(id) || id <= 0) {
        return json({ error: 'El comentario no existe.' }, 404);
      }
      return deleteComment(id, request, env);
    }

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }
    return new Response('Assets binding not configured', { status: 500 });
  },
};
