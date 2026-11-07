'use strict';
/**
 * Fase II-A (contraseñas), II-B (cifrado en reposo / TLS) y II-C (gestión de secretos).
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const argon2 = require('argon2');
const { createApp, request, describeDb, crearUsuario, login, cookieSesion, finalizar, rnd } = require('./helpers');
const { hashPassword, verifyPassword } = require('../src/lib/passwords');
const { getPool } = require('../src/db/pool');
const { encrypt, decrypt } = require('../src/lib/crypto');
const secrets = require('../src/config/secrets');
const { crearRedireccionHttps } = require('../src/https');
const { hayOpenssl, levantarHttps } = require('./tls-helpers');

afterAll(finalizar);

// =============================================================================================
describe('II-A · Argon2id (unitarias)', () => {
  test('el hash es Argon2id con parámetros y sal codificados', async () => {
    const h = await hashPassword('Contraseña-Ficticia-1');
    expect(h).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
  });

  test('sal aleatoria: la misma contraseña produce hashes distintos', async () => {
    const [a, b] = await Promise.all([hashPassword('MismaClave-123'), hashPassword('MismaClave-123')]);
    expect(a).not.toBe(b);
    expect(a.split('$')[4]).not.toBe(b.split('$')[4]); // sales distintas
  });

  test('verificación: correcta -> true, incorrecta -> false', async () => {
    const h = await hashPassword('Correcta-12345');
    await expect(verifyPassword(h, 'Correcta-12345')).resolves.toBe(true);
    await expect(verifyPassword(h, 'Incorrecta-123')).resolves.toBe(false);
  });

  test('SHA-256 es determinista y rápido; Argon2id es deliberadamente costoso', async () => {
    const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
    expect(sha('MismaClave-123')).toBe(sha('MismaClave-123'));
    let t = process.hrtime.bigint();
    for (let i = 0; i < 1000; i += 1) sha(`clave${i}`);
    const msSha = Number(process.hrtime.bigint() - t) / 1e6 / 1000;
    t = process.hrtime.bigint();
    await argon2.hash('clave', { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
    const msArgon = Number(process.hrtime.bigint() - t) / 1e6;
    expect(msArgon / msSha).toBeGreaterThan(100); // órdenes de magnitud más lento por intento
  });
});

describeDb('II-A · almacenamiento y login (integración)', () => {
  const app = createApp({ labVuln: true, loginMax: 1000 });

  test('registro seguro guarda Argon2id; registro vulnerable guarda SHA-256 sin sal', async () => {
    const password = `Igual-${rnd()}`;
    const s1 = `test-${rnd()}@universidad.example`;
    const s2 = `test-${rnd()}@universidad.example`;
    const v1 = `test-${rnd()}@universidad.example`;
    const v2 = `test-${rnd()}@universidad.example`;
    for (const email of [s1, s2]) expect((await request(app).post('/api/auth/registro').send({ email, password })).status).toBe(201);
    for (const email of [v1, v2]) expect((await request(app).post('/vuln/registro').send({ email, password })).status).toBe(201);

    const [filas] = await getPool().execute(
      'SELECT email, password_algo, password_hash FROM usuarios WHERE email IN (?, ?, ?, ?)', [s1, s2, v1, v2]);
    const h = Object.fromEntries(filas.map((f) => [f.email, f]));
    expect(h[s1].password_hash).toMatch(/^\$argon2id\$/);
    expect(h[s1].password_hash).not.toBe(h[s2].password_hash); // sal distinta
    expect(h[v1].password_hash).toBe(crypto.createHash('sha256').update(password).digest('hex'));
    expect(h[v1].password_hash).toBe(h[v2].password_hash); // misma contraseña => mismo hash
  });

  test('login seguro: correo inexistente y contraseña incorrecta dan la MISMA respuesta', async () => {
    const u = await crearUsuario();
    const a = await request(app).post('/api/auth/login').send({ email: u.email, password: 'incorrecta-123' });
    const b = await request(app).post('/api/auth/login').send({ email: `no-existe-${rnd()}@universidad.example`, password: 'x-123456789' });
    expect(a.status).toBe(401);
    expect(b.status).toBe(401);
    expect(a.body).toEqual({ error: 'ERR_CREDENCIALES' });
    expect(b.body).toEqual(a.body);
  });

  test('login vulnerable: revela si el correo existe (enumeración)', async () => {
    const email = `test-${rnd()}@universidad.example`;
    await request(app).post('/vuln/registro').send({ email, password: 'Clave-123456' });
    const a = await request(app).post('/vuln/login').send({ email, password: 'otra' });
    const b = await request(app).post('/vuln/login').send({ email: 'nadie@x.example', password: 'otra' });
    expect(a.body.error).toBe('Contraseña incorrecta');
    expect(b.body.error).toBe('El usuario no existe');
  });

  test('rate limit: tras N intentos fallidos responde 429 (aun con la contraseña correcta)', async () => {
    const limitado = createApp({ loginMax: 3 });
    const u = await crearUsuario();
    for (let i = 0; i < 3; i += 1) {
      expect((await request(limitado).post('/api/auth/login').send({ email: u.email, password: 'mala-123456' })).status).toBe(401);
    }
    const r = await request(limitado).post('/api/auth/login').send(u);
    expect(r.status).toBe(429);
    expect(r.body).toEqual({ error: 'ERR_DEMASIADOS_INTENTOS' });
    expect(r.headers.ratelimit || r.headers['ratelimit-policy']).toBeDefined();
  });
});

// =============================================================================================
describe('II-B · cifrado en reposo AES-256-GCM y rotación de claves', () => {
  test('rotación: un dato v1 sigue descifrándose cuando la clave activa pasa a v2', () => {
    const v1 = encrypt('1000000000101', '2026-0001');
    const env = { ...process.env, DATA_KEY_V2: crypto.randomBytes(32).toString('base64'), DATA_KEY_CURRENT: 'v2' };
    secrets._resetSecretsCache();
    const original = { ...process.env };
    Object.assign(process.env, env);
    try {
      const v2 = encrypt('1000000000101', '2026-0001');
      expect(v1.startsWith('v1:')).toBe(true);
      expect(v2.startsWith('v2:')).toBe(true);
      expect(decrypt(v1, '2026-0001')).toBe('1000000000101');
      expect(decrypt(v2, '2026-0001')).toBe('1000000000101');
    } finally {
      for (const k of ['DATA_KEY_V2', 'DATA_KEY_CURRENT']) {
        if (original[k] === undefined) delete process.env[k]; else process.env[k] = original[k];
      }
      secrets._resetSecretsCache();
    }
  });

  test('un dato cifrado con una versión de clave retirada no se puede descifrar', () => {
    expect(() => decrypt('v9:AAAA:BBBB:CCCC')).toThrow('ERR_CIFRADO_VERSION');
  });
});

describeDb('II-B · DPI en base de datos', () => {
  const app = createApp({ labVuln: true });
  const admin = cookieSesion({ rol: 'admin' });

  test('los DPI del seed están cifrados (v1:...) y no contienen el número en claro', async () => {
    const [filas] = await getPool().query("SELECT carne, dpi_cifrado, dpi_plano FROM estudiantes WHERE carne LIKE '2026-000_'");
    expect(filas.length).toBe(8);
    for (const f of filas) {
      expect(f.dpi_cifrado).toMatch(/^v\d+:/);
      expect(f.dpi_cifrado).not.toMatch(/\d{13}/);
      expect(f.dpi_plano).toBeNull();
    }
  });

  test('alta segura cifra el DPI; alta vulnerable lo guarda en texto plano', async () => {
    const digitos = (n) => Array.from({ length: n }, () => crypto.randomInt(10)).join('');
    const dpi = `1${digitos(12)}`;
    const base = { nombres: 'Prueba', apellidos: 'Cifrado', carrera: 'Ingeniería en Sistemas', dpi };
    const sufijo = `${digitos(3)}-${digitos(4)}`;
    const cs = `9${sufijo}`; // carnés 9xxx/8xxx: no chocan con el seed (2026-xxxx)
    const cv = `8${sufijo}`;
    expect((await request(app).post('/api/estudiantes').set('Cookie', admin)
      .send({ ...base, carne: cs, email: `test-${rnd()}@universidad.example` })).status).toBe(201);
    expect((await request(app).post('/vuln/estudiantes').set('Cookie', admin)
      .send({ ...base, carne: cv, email: `test-${rnd()}@universidad.example` })).status).toBe(201);

    const [[seguro]] = await getPool().execute('SELECT dpi_cifrado, dpi_plano FROM estudiantes WHERE carne = ?', [cs]);
    const [[vuln]] = await getPool().execute('SELECT dpi_cifrado, dpi_plano FROM estudiantes WHERE carne = ?', [cv]);
    expect(seguro.dpi_plano).toBeNull();
    expect(seguro.dpi_cifrado).not.toContain(dpi);
    expect(decrypt(seguro.dpi_cifrado, cs)).toBe(dpi);
    expect(vuln.dpi_plano).toBe(dpi);
  });

  test('el expediente muestra el DPI enmascarado (minimización)', async () => {
    const res = await request(app).get('/api/estudiantes/2026-0001/expediente').set('Cookie', admin);
    expect(res.status).toBe(200);
    expect(res.body.dpi).toBe('*********0101');
    expect(res.body.dpi_cifrado).toBeUndefined();
  });
});

(hayOpenssl ? describe : describe.skip)('II-B · TLS (servidor HTTPS real, certificado OpenSSL)', () => {
  let srv;
  beforeAll(async () => { srv = await levantarHttps(createApp({ labVuln: false })); }, 30000);
  afterAll(() => srv?.cerrar());

  test('HTTPS con certificado validado contra la CA de laboratorio, TLS >= 1.2 y AEAD', async () => {
    const r = await srv.get('/api/health');
    expect(r.status).toBe(200);
    expect(['TLSv1.2', 'TLSv1.3']).toContain(r.protocolo);
    expect(r.cifrado.name).toMatch(/GCM|CHACHA20/);
    expect(r.certificado.subjectAltName).toContain('DNS:localhost');
    expect(r.headers['strict-transport-security']).toMatch(/max-age=\d+/);
  });

  test('se rechaza un cliente limitado a TLS 1.1', async () => {
    await expect(srv.conectarTls({ minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT@SECLEVEL=0' })).rejects.toThrow();
  });

  test('se acepta un cliente limitado a TLS 1.2', async () => {
    const r = await srv.conectarTls({ minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' });
    expect(r).toEqual({ protocolo: 'TLSv1.2', autorizado: true });
  });

  test('un cliente que no confía en la CA de laboratorio rechaza la conexión', async () => {
    await expect(srv.get('/api/health', { ca: undefined })).rejects.toThrow();
  });

  test('el puerto HTTP redirige (308) a HTTPS con host fijo', async () => {
    const r = await request(crearRedireccionHttps(3443)).get('/api/health').set('Host', 'atacante.example');
    expect(r.status).toBe(308);
    expect(r.headers.location).toBe('https://localhost:3443/api/health');
  });
});

// =============================================================================================
describe('II-C · gestión de secretos', () => {
  test('initSecrets obtiene los secretos desde Vault (cliente simulado) y reporta el origen', async () => {
    const vaultSecretos = {
      DB_PASSWORD: 'desde-vault', SESSION_SECRET: crypto.randomBytes(32).toString('base64'),
      DATA_KEY_V1: crypto.randomBytes(32).toString('base64'), LOG_HMAC_KEY: crypto.randomBytes(32).toString('base64'),
    };
    const llamadas = [];
    const crearClienteVault = (cfg) => ({
      read: async (ruta) => { llamadas.push({ cfg, ruta }); return { data: { data: vaultSecretos } }; },
    });
    const env = { ...process.env, SECRETS_PROVIDER: 'vault', VAULT_ADDR: 'http://127.0.0.1:8200', VAULT_TOKEN: 'token-de-prueba' };
    delete env.DB_PASSWORD;
    const r = await secrets.initSecrets(env, { crearClienteVault });
    expect(llamadas[0].ruta).toBe('secret/data/portal-lab');
    expect(r.origenes.DB_PASSWORD).toBe('vault');
    expect(secrets.getSecrets().db.password).toBe('desde-vault');
    expect(JSON.stringify(r)).not.toContain('desde-vault'); // el reporte no incluye valores
    secrets._resetSecretsCache();
  });

  test('si Vault falla, el error no revela token ni rutas internas', async () => {
    const crearClienteVault = () => ({ read: async () => { throw Object.assign(new Error('permission denied token=s.SECRETO'), { response: { statusCode: 403 } }); } });
    const env = { ...process.env, SECRETS_PROVIDER: 'vault', VAULT_ADDR: 'http://127.0.0.1:8200', VAULT_TOKEN: 's.SECRETO' };
    const err = await secrets.initSecrets(env, { crearClienteVault }).catch((e) => e);
    expect(err.message).toBe('No se pudo leer secretos de Vault (403)');
    expect(err.message).not.toMatch(/SECRETO|token/);
    secrets._resetSecretsCache();
  });
});
