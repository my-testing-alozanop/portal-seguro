'use strict';
/**
 * LAS 9 PRUEBAS TÉCNICAS OBLIGATORIAS (sección 4 del enunciado).
 * Cada bloque lleva el nombre exacto de la fila de la tabla y verifica el "resultado esperado".
 *   npx jest tests/pruebas-obligatorias.test.js --verbose
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync, spawnSync } = require('node:child_process');
const { createApp, request, describeDb, hayBD, crearUsuario, login, cookieSesion, capturarLogs, finalizar, rnd } = require('./helpers');
const { buscarEstudiantes } = require('../src/db/estudiantes.repo');
const { getPool } = require('../src/db/pool');
const { loadSecrets } = require('../src/config/secrets');
const { seudonimo } = require('../src/lib/logger');
const { hayOpenssl, levantarHttps } = require('./tls-helpers');

const RAIZ = path.resolve(__dirname, '..', '..');
const describeTls = hayOpenssl ? describe : describe.skip;
const app = createApp({ labVuln: false, loginMax: 1000 });
afterAll(finalizar);

// ---------------------------------------------------------------------------------------------
describeDb('1 · Entrada con caracteres especiales en búsqueda -> no altera la estructura SQL', () => {
  test('tautología, UNION, comentario y apilado se tratan como texto literal', async () => {
    for (const p of ["x' OR 'a' LIKE 'a", "' UNION SELECT email, password_hash, rol, id FROM usuarios -- -",
      "' OR 1=1 -- ", "'; DROP TABLE estudiantes; -- ", '%', '_']) {
      await expect(buscarEstudiantes(p)).resolves.toEqual([]);
    }
    const r = await buscarEstudiantes("O'Connor");
    expect(r.map((x) => x.apellidos)).toContain("O'Connor Herrera"); // la comilla legítima funciona
    expect(r.every((x) => x.apellidos.includes("O'Connor"))).toBe(true);
    const [[{ n }]] = await getPool().query('SELECT COUNT(*) AS n FROM estudiantes');
    expect(n).toBeGreaterThanOrEqual(8); // la tabla sigue intacta
  });
});

// ---------------------------------------------------------------------------------------------
describeDb('2 · Comentario con contenido HTML -> no se ejecuta como contenido activo', () => {
  test('se almacena y se devuelve como dato JSON; al pintarlo como texto no crea elementos', async () => {
    const { JSDOM } = require('jsdom');
    const payload = `<img src=x onerror="alert(1)"><script>alert(2)</script> ${rnd()}`;
    const cookie = await login(app, await crearUsuario());
    expect((await request(app).post('/api/comentarios').set('Cookie', cookie).send({ contenido: payload })).status).toBe(201);
    const res = await request(app).get('/api/comentarios');
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.headers['content-security-policy']).toContain("script-src 'self'");
    const c = res.body.comentarios.find((x) => x.contenido === payload);
    const div = new JSDOM('<div id="c"></div>').window.document.getElementById('c');
    div.textContent = c.contenido; // lo que hace React con {c.contenido}
    expect(div.querySelector('img, script')).toBeNull();
  });
});

// ---------------------------------------------------------------------------------------------
describeDb('3 · Contraseña almacenada -> se conserva mediante una KDF con sal', () => {
  test('Argon2id con parámetros y sal propia por usuario (misma contraseña, hashes distintos)', async () => {
    const password = `Misma-${rnd()}`;
    const correos = [`test-${rnd()}@universidad.example`, `test-${rnd()}@universidad.example`];
    for (const email of correos) await request(app).post('/api/auth/registro').send({ email, password });
    const [f] = await getPool().execute('SELECT password_hash FROM usuarios WHERE email IN (?, ?)', correos);
    for (const { password_hash: h } of f) expect(h).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    expect(f[0].password_hash).not.toBe(f[1].password_hash);
    expect(f[0].password_hash.split('$')[4]).not.toBe(f[1].password_hash.split('$')[4]);
  });
});

// ---------------------------------------------------------------------------------------------
describeDb('4 · Contraseña incorrecta -> se rechaza la autenticación', () => {
  test('401 genérico, sin cookie de sesión, idéntico al de un correo inexistente', async () => {
    const u = await crearUsuario();
    const mala = await request(app).post('/api/auth/login').send({ email: u.email, password: `${u.password}x` });
    const inexistente = await request(app).post('/api/auth/login').send({ email: `nadie-${rnd()}@universidad.example`, password: u.password });
    expect(mala.status).toBe(401);
    expect(mala.body).toEqual({ error: 'ERR_CREDENCIALES' });
    expect(mala.headers['set-cookie']).toBeUndefined();
    expect(inexistente.body).toEqual(mala.body);
    const ok = await request(app).post('/api/auth/login').send(u);
    expect(ok.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------------------------
function comandoGitleaks() {
  const v = spawnSync('gitleaks', ['version'], { encoding: 'utf8' });
  if (v.status !== 0) return null;
  const nuevo = spawnSync('gitleaks', ['git', '--help'], { encoding: 'utf8' }).status === 0;
  return (repo, config, reporte) => (nuevo
    ? ['git', repo, '--config', config, '--report-format', 'json', '--report-path', reporte, '--redact', '--no-banner', '--exit-code', '1']
    : ['detect', '--source', repo, '--config', config, '--report-format', 'json', '--report-path', reporte, '--redact', '--no-banner', '--exit-code', '1']);
}
const argsGitleaks = comandoGitleaks();

(argsGitleaks ? describe : describe.skip)('5 · Credencial ficticia en Git -> la herramienta detecta la exposición', () => {
  test('gitleaks encuentra la clave AWS ficticia en el HISTORIAL aunque se haya borrado después', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-fuga-test-'));
    const git = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'pipe' });
    git('init', '-q');
    git('config', 'user.email', 'lab@universidad.example');
    git('config', 'user.name', 'Laboratorio');
    git('config', 'commit.gpgsign', 'false');
    // La clave se arma en tiempo de ejecución: este archivo de prueba no contiene el literal.
    const clave = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('');
    fs.writeFileSync(path.join(dir, 'config.js'), `module.exports = { awsAccessKeyId: '${clave}' };\n`);
    git('add', '.');
    git('commit', '-q', '-m', 'config inicial');
    fs.writeFileSync(path.join(dir, 'config.js'), 'module.exports = { awsAccessKeyId: process.env.AWS_ACCESS_KEY_ID };\n');
    git('commit', '-q', '-am', 'quitar clave');
    expect(fs.readFileSync(path.join(dir, 'config.js'), 'utf8')).not.toContain('AKIA'); // ya no está en el código actual

    const config = path.join(RAIZ, '..', 'lab-fuga', '.gitleaks.toml');
    const reporte = path.join(dir, 'reporte.json');
    const r = spawnSync('gitleaks', argsGitleaks(dir, config, reporte), { encoding: 'utf8' });
    expect(r.status).toBe(1); // 1 = hallazgos
    const hallazgos = JSON.parse(fs.readFileSync(reporte, 'utf8'));
    expect(hallazgos.some((h) => /aws/i.test(h.RuleID) && h.File === 'config.js')).toBe(true);
    fs.rmSync(dir, { recursive: true, force: true });
  }, 30000);
});
if (!argsGitleaks) test.todo('5 · Credencial ficticia en Git: instale gitleaks (winget install gitleaks) para ejecutarla');

// ---------------------------------------------------------------------------------------------
describe('6 · Secreto retirado del código -> la aplicación obtiene la credencial desde una fuente externa', () => {
  const envFile = path.join(RAIZ, 'server', '.env');
  const real = fs.existsSync(envFile) ? require('dotenv').parse(fs.readFileSync(envFile)) : null;

  test('la configuración de BD proviene del entorno (fuente externa), no de una constante', () => {
    const env = { ...process.env, DB_PASSWORD: `externa-${rnd()}` };
    expect(loadSecrets(env).db.password).toBe(env.DB_PASSWORD);
    expect(() => loadSecrets({ ...env, DB_PASSWORD: '' })).toThrow(/DB_PASSWORD/);
  });

  (real ? test : test.skip)('ningún archivo versionado contiene los valores reales de server/.env', () => {
    const versionados = execFileSync('git', ['ls-files'], { cwd: RAIZ, encoding: 'utf8' }).split('\n').filter(Boolean);
    expect(versionados).not.toContain('server/.env');
    const valores = ['DB_PASSWORD', 'SESSION_SECRET', 'DATA_KEY_V1', 'LOG_HMAC_KEY', 'SEED_ADMIN_PASSWORD', 'SEED_USER_PASSWORD']
      .map((k) => real[k]).filter((v) => v && v.length >= 8);
    for (const archivo of versionados) {
      const ruta = path.join(RAIZ, archivo);
      if (!fs.existsSync(ruta) || fs.statSync(ruta).size > 2e6) continue;
      const contenido = fs.readFileSync(ruta, 'utf8');
      for (const v of valores) {
        if (contenido.includes(v)) throw new Error(`Secreto real encontrado en ${archivo}`); // sin imprimir el valor
      }
    }
  });
});

// ---------------------------------------------------------------------------------------------
describeTls('7 · Consulta mediante HTTPS -> la comunicación utiliza TLS correctamente', () => {
  let srv;
  beforeAll(async () => { srv = await levantarHttps(createApp({ labVuln: false })); }, 30000);
  afterAll(() => srv?.cerrar());

  test('TLS 1.2/1.3 con certificado válido (SAN localhost) y cifrado AEAD; TLS 1.1 rechazado', async () => {
    const r = await srv.get('/api/health');
    expect(r.status).toBe(200);
    expect(['TLSv1.2', 'TLSv1.3']).toContain(r.protocolo);
    expect(r.cifrado.name).toMatch(/GCM|CHACHA20/);
    expect(r.certificado.subjectAltName).toContain('DNS:localhost');
    await expect(srv.conectarTls({ minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT@SECLEVEL=0' })).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------------------------
describeDb('8 · Inicio de sesión fallido -> se genera un registro sin revelar la contraseña', () => {
  test('evento login_fallido con seudónimo, sin contraseña ni correo', async () => {
    const logs = capturarLogs();
    const u = await crearUsuario();
    const intento = `NoDebeVerse-${rnd()}`;
    await request(app).post('/api/auth/login').send({ email: u.email, password: intento });
    const [e] = logs.eventos('login_fallido');
    expect(e).toMatchObject({ evento: 'login_fallido', usuario: seudonimo(u.email) });
    expect(logs.texto()).not.toContain(intento);
    expect(logs.texto()).not.toContain(u.email);
  });
});

// ---------------------------------------------------------------------------------------------
describeDb('9 · Error interno -> no expone claves, tokens ni detalles sensibles al usuario', () => {
  test('respuesta 500 con solo { error, id }', async () => {
    const carne = `7${crypto.randomInt(100, 999)}-${crypto.randomInt(1000, 9999)}`;
    await getPool().execute(
      "INSERT INTO estudiantes (carne, nombres, apellidos, email, carrera, dpi_cifrado) VALUES (?, 'Error', 'Interno', ?, 'Sistemas', 'v1:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAA==:AAAA')",
      [carne, `test-${rnd()}@universidad.example`],
    );
    const cookie = cookieSesion({ rol: 'admin' });
    const res = await request(app).get(`/api/estudiantes/${carne}/expediente`).set('Cookie', cookie);
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'ERR_INTERNO', id: expect.stringMatching(/^[0-9a-f-]{36}$/) });
    const sensibles = [process.env.SESSION_SECRET, process.env.DATA_KEY_V1, process.env.DB_PASSWORD, cookie.slice(4), 'stack', 'node_modules', 'portal_app', 'authenticate'];
    for (const s of sensibles) expect(res.text).not.toContain(s);
  });
});

if (!hayBD) test.todo('Pruebas 1-4, 8 y 9 requieren MySQL de laboratorio con seed (npm run db:reset)');
