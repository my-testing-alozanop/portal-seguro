'use strict';
/**
 * Fase I-C · Cross-Site Scripting.
 * PRUEBA OBLIGATORIA 2: "Comentario con contenido HTML -> no se ejecuta como contenido activo".
 */
const { JSDOM } = require('jsdom');
const createDOMPurify = require('dompurify');
const { createApp, request, describeDb, crearUsuario, login, cookieSesion, finalizar, rnd } = require('./helpers');

const PAYLOAD = '<img src=x onerror="window.__xss=1">';
afterAll(finalizar);

describeDb('I-C · XSS almacenado — API segura', () => {
  const app = createApp({ labVuln: false });
  let cookie;
  let marca;
  beforeAll(async () => {
    cookie = await login(app, await crearUsuario());
    marca = rnd();
    const r = await request(app).post('/api/comentarios').set('Cookie', cookie).send({ contenido: `${PAYLOAD} ${marca}` });
    expect(r.status).toBe(201);
  });

  test('[PRUEBA 2] el comentario se devuelve como DATO JSON, no como HTML', async () => {
    const res = await request(app).get('/api/comentarios');
    expect(res.headers['content-type']).toMatch(/application\/json/);
    const c = res.body.comentarios.find((x) => x.contenido.includes(marca));
    expect(c.contenido).toBe(`${PAYLOAD} ${marca}`);
  });

  test('[PRUEBA 2] respuesta con CSP sin scripts en línea y nosniff', async () => {
    const res = await request(app).get('/api/comentarios');
    const csp = res.headers['content-security-policy'];
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).not.toContain('unsafe-inline');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });
});

describe('I-C · renderizado del comentario en el navegador (jsdom)', () => {
  // Reproduce exactamente las 3 formas de insertar el texto que usa el cliente React.
  const nuevoDom = () => new JSDOM('<!doctype html><div id="c"></div>', { runScripts: 'outside-only' });

  test('[PRUEBA 2] SEGURO · textContent (equivale a {texto} en React): no se crea ningún elemento', () => {
    const { window } = nuevoDom();
    const div = window.document.getElementById('c');
    div.textContent = PAYLOAD;
    expect(div.querySelector('img')).toBeNull();
    expect(div.textContent).toBe(PAYLOAD);
    expect(div.innerHTML).toContain('&lt;img');
  });

  test('[PRUEBA 2] SEGURO · DOMPurify: conserva formato permitido y elimina el manejador onerror', () => {
    const { window } = nuevoDom();
    const DOMPurify = createDOMPurify(window);
    const limpio = DOMPurify.sanitize(`<b>hola</b>${PAYLOAD}<script>alert(1)</script>`, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'u'],
      ALLOWED_ATTR: [],
    });
    expect(limpio).toBe('<b>hola</b>');
  });

  test('VULNERABLE · innerHTML (dangerouslySetInnerHTML): se crea un <img> con onerror activo', () => {
    const { window } = nuevoDom();
    const div = window.document.getElementById('c');
    div.innerHTML = PAYLOAD;
    const img = div.querySelector('img');
    expect(img).not.toBeNull();
    expect(img.getAttribute('onerror')).toContain('__xss');
  });
});

describe('I-C · XSS reflejado', () => {
  const cookie = cookieSesion();

  test('SEGURO · la búsqueda nunca devuelve HTML: un <script> se rechaza en JSON sin reflejarse', async () => {
    const res = await request(createApp({ labVuln: false }))
      .get('/api/estudiantes/buscar').query({ q: '<script>alert(1)</script>' }).set('Cookie', cookie);
    expect(res.status).toBe(400);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.text).not.toContain('<script>');
  });

  test('VULNERABLE · /vuln/buscar-html refleja el <script> en text/html y sin CSP', async () => {
    const res = await request(createApp({ labVuln: true }))
      .get('/vuln/buscar-html').query({ q: '<script>alert(1)</script>' }).set('Cookie', cookie);
    expect(res.headers['content-type']).toMatch(/text\/html/);
    expect(res.text).toContain('<script>alert(1)</script>');
    expect(res.headers['content-security-policy']).toBeUndefined();
  });
});

describe('I-C · cookie de sesión', () => {
  test('la API segura entrega la sesión con HttpOnly, Secure y SameSite=Strict', async () => {
    // Se usa /api/auth/logout porque emite la cookie (vacía) con los mismos atributos sin requerir BD.
    const res = await request(createApp({ labVuln: false })).post('/api/auth/logout');
    const c = res.headers['set-cookie'][0];
    expect(c).toMatch(/HttpOnly/i);
    expect(c).toMatch(/Secure/i);
    expect(c).toMatch(/SameSite=Strict/i);
  });
});

describeDb('I-C · cookie emitida en el login real', () => {
  test('login exitoso -> cookie sid HttpOnly; Secure; SameSite=Strict', async () => {
    const res = await request(createApp({ labVuln: false })).post('/api/auth/login').send(await crearUsuario());
    expect(res.status).toBe(200);
    const c = res.headers['set-cookie'].find((x) => x.startsWith('sid='));
    expect(c).toMatch(/HttpOnly/i);
    expect(c).toMatch(/Secure/i);
    expect(c).toMatch(/SameSite=Strict/i);
  });
});
