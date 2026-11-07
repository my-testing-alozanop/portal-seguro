'use strict';
/**
 * ⚠️  RUTAS DELIBERADAMENTE VULNERABLES — SOLO LABORATORIO  ⚠️
 *
 * Este router solo se monta cuando LAB_VULN=1 (ver src/app.js), ANTES de helmet (sin CSP ni
 * cabeceras de protección) y el servidor escucha únicamente en 127.0.0.1.
 * Cada endpoint tiene su contraparte segura en /api/... — ver MATRIZ.md.
 * Requieren sesión igual que las seguras, para que la ÚNICA diferencia sea la falla demostrada.
 */
const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { exec } = require('node:child_process');
const { getPool } = require('../db/pool');
const { requireAuth, requireRol } = require('../middleware/auth');
const { aCsv, TIPOS, REPORTS_DIR } = require('../lib/reportes');
const { emitirSesion } = require('../middleware/auth');
const pino = require('pino');
const { LOG_DIR } = require('../lib/logger');

// Logger INSEGURO (Fase II-E): sin redact, sin seudónimos. Escribe en logs/inseguro.log.
const logInseguro = pino(
  { base: { app: 'portal-lab-VULN' }, timestamp: pino.stdTimeFunctions.isoTime },
  process.env.NODE_ENV === 'test'
    ? { write: () => {} }
    : pino.multistream([
      { stream: process.stdout },
      { stream: pino.destination({ dest: path.join(LOG_DIR, 'inseguro.log'), mkdir: true, sync: false }) },
    ]),
);

const router = express.Router();

router.get('/', (_req, res) => {
  res.json({ aviso: 'Modo laboratorio vulnerable ACTIVO (LAB_VULN=1). No usar fuera de localhost.' });
});

// ---------------------------------------------------------------------------------------------
// Fase I-B · SQL INJECTION (VULNERABLE)
// Causa raíz: la entrada se CONCATENA dentro del texto SQL, así que el usuario puede cerrar la
// cadena con ' y añadir lógica propia. Sin validación y devolviendo el error SQL al cliente.
//   Prueba:  q = x' OR 'a' LIKE 'a                       -> devuelve TODOS los estudiantes
//   Prueba:  q = ' UNION SELECT email, password_hash, rol, id FROM usuarios -- -
// ---------------------------------------------------------------------------------------------
router.get('/buscar', requireAuth, async (req, res) => {
  const q = req.query.q ?? '';
  const sql =
    'SELECT carne, nombres, apellidos, carrera FROM estudiantes ' +
    "WHERE nombres LIKE '%" + q + "%' OR apellidos LIKE '%" + q + "%'";
  try {
    const [resultados] = await getPool().query(sql);
    res.json({ sql, resultados });
  } catch (err) {
    // También vulnerable: filtra el mensaje del motor SQL (facilita SQLi basada en errores).
    res.status(500).json({ sql, error: err.message });
  }
});

// ---------------------------------------------------------------------------------------------
// Fase I-C · XSS REFLEJADO (VULNERABLE)
// Causa raíz: el parámetro q se inserta sin codificar en una respuesta HTML.
//   Prueba: /vuln/buscar-html?q=<script>alert(document.domain)</script>
// ---------------------------------------------------------------------------------------------
router.get('/buscar-html', requireAuth, (req, res) => {
  const q = req.query.q ?? '';
  res.send(`<!doctype html><html><body><h1>Resultados para: ${q}</h1><p>(sin resultados)</p></body></html>`);
});

// ---------------------------------------------------------------------------------------------
// Fase I-C · XSS ALMACENADO (VULNERABLE, lado servidor)
// Acepta cualquier contenido sin validar ni limitar. El fallo que lo vuelve explotable está en
// el cliente (VulnComentarios.jsx usa dangerouslySetInnerHTML).
// ---------------------------------------------------------------------------------------------
router.get('/comentarios', async (_req, res) => {
  const [rows] = await getPool().query(
    "SELECT c.id, c.contenido, c.creado_en, SUBSTRING_INDEX(u.email, '@', 1) AS autor " +
      'FROM comentarios c JOIN usuarios u ON u.id = c.usuario_id ORDER BY c.id DESC LIMIT 50',
  );
  res.json({ comentarios: rows });
});

router.post('/comentarios', requireAuth, async (req, res) => {
  const [r] = await getPool().execute('INSERT INTO comentarios (usuario_id, contenido) VALUES (?, ?)', [
    req.usuario.id,
    String(req.body?.contenido ?? ''),
  ]);
  res.status(201).json({ ok: true, id: r.insertId });
});

// ---------------------------------------------------------------------------------------------
// Fase I-D · INYECCIÓN DE COMANDOS (VULNERABLE)
// Causa raíz: exec() pasa UNA CADENA a la shell (cmd.exe / sh) y "nombre" viene del usuario.
// Las comillas NO protegen: el atacante las cierra.
//   Prueba: { "tipo": "notas", "nombre": "x\" & echo INYECTADO & echo \"" }
// ---------------------------------------------------------------------------------------------
router.post('/reporte', requireAuth, requireRol('admin'), async (req, res) => {
  const { tipo = 'notas', nombre = 'reporte' } = req.body ?? {};
  const def = TIPOS[tipo] ?? TIPOS.notas;
  const [filas] = await getPool().query(def.sql);
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  const csv = `tmp-${crypto.randomBytes(4).toString('hex')}.csv`;
  fs.writeFileSync(path.join(REPORTS_DIR, csv), aCsv(def.columnas, filas));

  const comando = `tar -a -c -f "${nombre}.zip" ${csv}`;
  exec(comando, { cwd: REPORTS_DIR, timeout: 10000 }, (err, stdout, stderr) => {
    fs.rmSync(path.join(REPORTS_DIR, csv), { force: true });
    res.json({ comando, stdout, stderr, codigo: err?.code ?? 0 });
  });
});

// ---------------------------------------------------------------------------------------------
// Fase I-D · PATH TRAVERSAL en la descarga (VULNERABLE)
// Causa raíz: el nombre del archivo del usuario se une a la ruta sin comprobar el resultado.
//   Prueba: /vuln/reporte/descargar?archivo=../package.json
// ---------------------------------------------------------------------------------------------
router.get('/reporte/descargar', requireAuth, requireRol('admin'), (req, res) => {
  const ruta = path.join(REPORTS_DIR, String(req.query.archivo ?? ''));
  res.sendFile(ruta, (err) => {
    if (err && !res.headersSent) res.status(404).json({ ruta, error: err.message });
  });
});

// ---------------------------------------------------------------------------------------------
// Fase II-A · CONTRASEÑAS CON SHA-256 SIN SAL (VULNERABLE)
// Causa raíz: SHA-256 es una función RÁPIDA (miles de millones de hashes/s en GPU) y sin sal:
// la misma contraseña produce el mismo hash en todas las cuentas y en todas las bases de datos,
// lo que permite tablas arcoíris y detectar contraseñas repetidas a simple vista.
// Además, el login revela si el correo existe y no limita intentos.
// ---------------------------------------------------------------------------------------------
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

router.post('/registro', async (req, res) => {
  const { email, password } = req.body ?? {};
  await getPool().execute(
    "INSERT INTO usuarios (email, password_hash, password_algo, rol) VALUES (?, ?, 'sha256', 'estudiante')",
    [String(email), sha256(password)],
  );
  res.status(201).json({ ok: true, hash_guardado: sha256(password) });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body ?? {};
  // Fase II-E · REGISTRO INSEGURO: guarda el cuerpo completo, contraseña incluida, y el correo en claro.
  logInseguro.info({ evento: 'login', body: req.body, headers: req.headers }, 'intento de login');
  const [[u]] = await getPool().execute(
    "SELECT id, password_hash, rol, estudiante_id FROM usuarios WHERE email = ? AND password_algo = 'sha256'",
    [String(email)],
  );
  // Mensajes distintos: permiten enumerar qué correos existen.
  if (!u) return res.status(401).json({ error: 'El usuario no existe' });
  if (u.password_hash !== sha256(password)) return res.status(401).json({ error: 'Contraseña incorrecta' });
  emitirSesion(res, u);
  return res.json({ ok: true });
});

// ---------------------------------------------------------------------------------------------
// Fase II-B · DPI EN TEXTO PLANO (VULNERABLE)
// Causa raíz: el dato sensible se guarda tal cual; cualquiera con acceso a la BD, a un respaldo
// o a un volcado (o vía SQLi) lo lee directamente. TLS no ayuda: protege solo el tránsito.
// ---------------------------------------------------------------------------------------------
router.post('/estudiantes', requireAuth, requireRol('admin'), async (req, res) => {
  const { carne, nombres, apellidos, email, carrera, dpi } = req.body ?? {};
  await getPool().execute(
    'INSERT INTO estudiantes (carne, nombres, apellidos, email, carrera, dpi_plano) VALUES (?, ?, ?, ?, ?, ?)',
    [carne, nombres, apellidos, email, carrera, dpi].map((v) => String(v ?? '')),
  );
  res.status(201).json({ ok: true, carne });
});

// ---------------------------------------------------------------------------------------------
// Fase II-E · ERROR INTERNO QUE FILTRA DETALLES (VULNERABLE)
// Devuelve mensaje, stack (rutas internas) y la configuración de conexión al cliente.
//   Prueba: GET /vuln/expediente/no-existe  (provoca un error en el servidor)
// ---------------------------------------------------------------------------------------------
router.get('/expediente/:carne', requireAuth, async (req, res) => {
  const [[e]] = await getPool().query(`SELECT * FROM estudiantes WHERE carne = '${req.params.carne}'`);
  res.json({ ...e, dpi_descifrado: require('../lib/crypto').decrypt(e.dpi_cifrado, e.carne) });
});

// eslint-disable-next-line no-unused-vars
router.use((err, req, res, _next) => {
  const { getSecrets } = require('../config/secrets');
  const { password, ...db } = getSecrets().db; // ni siquiera la versión vulnerable expone la contraseña real
  res.status(500).json({ mensaje: err.message, stack: err.stack, sql: err.sql, conexion_bd: db });
});

module.exports = router;
