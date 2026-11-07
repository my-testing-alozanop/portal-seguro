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

module.exports = router;
