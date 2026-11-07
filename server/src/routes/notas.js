'use strict';
const express = require('express');
const { getPool } = require('../db/pool');
const { reglas, validar } = require('../middleware/validators');
const { requireAuth, requireRol } = require('../middleware/auth');
const { auditar } = require('../lib/logger');

const router = express.Router();

// Modificación de nota: solo admin, id numérico y nota entera 0-100 (además del CHECK en BD).
// Se registra QUIÉN cambió QUÉ nota, el valor anterior y el nuevo (trazabilidad / no repudio).
router.put('/:id', requireAuth, requireRol('admin'), reglas.idNumerico('id'), reglas.nota(), validar,
  async (req, res, next) => {
    try {
      const pool = getPool();
      const [[actual]] = await pool.execute(
        'SELECT n.nota, e.carne, n.curso FROM notas n JOIN estudiantes e ON e.id = n.estudiante_id WHERE n.id = ?',
        [req.params.id],
      );
      if (!actual) return res.status(404).json({ error: 'ERR_NO_ENCONTRADO' });
      await pool.execute('UPDATE notas SET nota = ? WHERE id = ?', [req.body.nota, req.params.id]);
      const evento = { req_id: req.id, usuario_id: req.usuario.id, nota_id: req.params.id, carne: actual.carne, curso: actual.curso };
      auditar('modificacion_nota', { ...evento, valor_anterior: actual.nota, valor_nuevo: req.body.nota });
      auditar('acceso_admin', { req_id: req.id, usuario_id: req.usuario.id, accion: 'modificacion_nota' });
      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

module.exports = router;
