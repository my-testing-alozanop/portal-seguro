'use strict';
/**
 * Fase I-C · Comentarios SEGUROS.
 * El servidor guarda el texto tal cual (validado y normalizado) y lo devuelve como DATO en JSON.
 * La defensa contra XSS es la codificación en la SALIDA: el cliente lo inserta como texto
 * (React escapa {texto}) o, si se permite formato, lo sanea con DOMPurify. Además, la CSP de
 * helmet bloquea scripts en línea como segunda barrera.
 */
const express = require('express');
const { getPool } = require('../db/pool');
const { reglas, validar } = require('../middleware/validators');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/', async (_req, res, next) => {
  try {
    const [rows] = await getPool().execute(
      `SELECT c.id, c.contenido, c.creado_en, SUBSTRING_INDEX(u.email, '@', 1) AS autor
         FROM comentarios c JOIN usuarios u ON u.id = c.usuario_id
        ORDER BY c.id DESC LIMIT 50`,
    );
    res.json({ comentarios: rows });
  } catch (err) {
    next(err);
  }
});

router.post('/', requireAuth, reglas.comentario(), validar, async (req, res, next) => {
  try {
    const [r] = await getPool().execute(
      'INSERT INTO comentarios (usuario_id, contenido) VALUES (?, ?)',
      [req.usuario.id, req.body.contenido],
    );
    res.status(201).json({ ok: true, id: r.insertId });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
