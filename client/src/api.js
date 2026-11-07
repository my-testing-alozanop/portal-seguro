// Cliente HTTP mínimo. credentials: 'same-origin' envía la cookie de sesión HttpOnly
// (el JavaScript nunca la lee directamente).
export async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const type = res.headers.get('content-type') || '';
  const data = type.includes('application/json') ? await res.json() : await res.text();
  return { ok: res.ok, status: res.status, data };
}
