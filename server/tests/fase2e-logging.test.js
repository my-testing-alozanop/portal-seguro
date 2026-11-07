'use strict';
/**
 * Fase II-E · Registro seguro con pino.
 */
const crypto = require('node:crypto');
const { createApp, request, describeDb, crearUsuario, cookieSesion, capturarLogs, finalizar, rnd } = require('./helpers');
const { getLogger, seudonimo, auditar } = require('../src/lib/logger');
const { getPool } = require('../src/db/pool');

afterAll(finalizar);

describe('II-E · redact y seudonimización (unitarias)', () => {
  test('redact oculta password, token, cookie, authorization y dpi aunque se pasen por error', () => {
    const logs = capturarLogs();
    getLogger().info({
      password: 'P4ss-secreta', token: 'tok-123', dpi: '1000000000101',
      body: { password: 'otra-clave', dpi: '1999999999999' },
      req: { headers: { authorization: 'Bearer abc.def', cookie: 'sid=xyz' } },
    }, 'prueba');
    const t = logs.texto();
    for (const s of ['P4ss-secreta', 'tok-123', '1000000000101', 'otra-clave', '1999999999999', 'Bearer abc.def', 'sid=xyz']) {
      expect(t).not.toContain(s);
    }
    expect(t).toContain('[REDACTADO]');
  });

  test('el seudónimo HMAC es estable, no contiene el correo y depende de la clave', () => {
    const a = seudonimo('Ana.Perez@universidad.example');
    expect(a).toBe(seudonimo('ana.perez@universidad.example'));
    expect(a).toMatch(/^u_[0-9a-f]{16}$/);
    expect(a).not.toContain('ana');
    // un hash simple (sin clave) del correo SÍ se podría reproducir: el HMAC no
    const shaSimple = crypto.createHash('sha256').update('ana.perez@universidad.example').digest('hex').slice(0, 16);
    expect(a).not.toBe(`u_${shaSimple}`);
  });

  test('solo se aceptan los eventos de auditoría definidos', () => {
    expect(() => auditar('cualquier_cosa', {})).toThrow();
  });

  test('cada línea es JSON con nivel, hora ISO y evento', () => {
    const logs = capturarLogs();
    auditar('acceso_admin', { usuario_id: 1, accion: 'prueba' });
    const [e] = logs.eventos('acceso_admin');
    expect(e).toMatchObject({ level: 'info', evento: 'acceso_admin', app: 'portal-lab' });
    expect(new Date(e.time).toISOString()).toBe(e.time);
  });
});

describeDb('II-E · eventos de auditoría (integración)', () => {
  const app = createApp({ loginMax: 1000 });
  let logs;
  beforeEach(() => { logs = capturarLogs(); });

  test('login_exitoso y login_fallido: sin contraseña, sin correo, con seudónimo e id de petición', async () => {
    const u = await crearUsuario();
    await request(app).post('/api/auth/login').send(u);
    await request(app).post('/api/auth/login').send({ email: u.email, password: 'Incorrecta-Xyz-987' });
    const [ok] = logs.eventos('login_exitoso');
    const [ko] = logs.eventos('login_fallido');
    expect(ok.usuario).toBe(seudonimo(u.email));
    expect(ko).toMatchObject({ level: 'warn', usuario: seudonimo(u.email), motivo: 'password_incorrecta' });
    expect(ko.req_id).toMatch(/^[0-9a-f-]{36}$/);
    const t = logs.texto();
    expect(t).not.toContain(u.password);
    expect(t).not.toContain('Incorrecta-Xyz-987');
    expect(t).not.toContain(u.email);
  });

  test('consulta_expediente (propio y denegado) y acceso_admin al consultar uno ajeno', async () => {
    await request(app).get('/api/estudiantes/2026-0002/expediente').set('Cookie', cookieSesion({ rol: 'estudiante', est: -1 }));
    await request(app).get('/api/estudiantes/2026-0002/expediente').set('Cookie', cookieSesion({ rol: 'admin' }));
    const ev = logs.eventos('consulta_expediente');
    expect(ev.map((e) => e.resultado)).toEqual(['denegado', 'ok']);
    expect(logs.eventos('acceso_admin')[0]).toMatchObject({ accion: 'consulta_expediente_ajeno', carne: '2026-0002' });
    expect(logs.texto()).not.toMatch(/\d{13}/); // ningún DPI
  });

  test('modificacion_nota registra quién, qué nota, valor anterior y nuevo', async () => {
    const [[n]] = await getPool().query("SELECT n.id, n.nota FROM notas n JOIN estudiantes e ON e.id = n.estudiante_id WHERE e.carne = '2026-0003' LIMIT 1");
    const admin = cookieSesion({ id: 4242, rol: 'admin' });
    const nueva = n.nota === 100 ? 99 : n.nota + 1;
    expect((await request(app).put(`/api/notas/${n.id}`).set('Cookie', admin).send({ nota: nueva })).status).toBe(200);
    await request(app).put(`/api/notas/${n.id}`).set('Cookie', admin).send({ nota: n.nota }); // restaura
    expect(logs.eventos('modificacion_nota')[0]).toMatchObject({
      usuario_id: 4242, nota_id: n.id, carne: '2026-0003', valor_anterior: n.nota, valor_nuevo: nueva,
    });
  });

  test('error_interno: al cliente solo código + id; en el log, tipo y código del error sin mensaje', async () => {
    const carne = `7${crypto.randomInt(100, 999)}-${crypto.randomInt(1000, 9999)}`;
    await getPool().execute(
      "INSERT INTO estudiantes (carne, nombres, apellidos, email, carrera, dpi_cifrado) VALUES (?, 'Error', 'Interno', ?, 'Sistemas', 'v1:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAA==:AAAA')",
      [carne, `test-${rnd()}@universidad.example`],
    );
    const res = await request(app).get(`/api/estudiantes/${carne}/expediente`).set('Cookie', cookieSesion({ rol: 'admin' }));
    expect(res.status).toBe(500);
    expect(Object.keys(res.body).sort()).toEqual(['error', 'id']);
    expect(res.body.error).toBe('ERR_INTERNO');
    const [e] = logs.eventos('error_interno');
    expect(e.req_id).toBe(res.body.id);
    expect(e.error).toMatchObject({ tipo: 'Error' });
    expect(JSON.stringify(e)).not.toMatch(/authenticate|stack/i);
  });
});
