'use strict';
const express = require('express');
const { getPool } = require('../db/pool');
const { reglas, validar } = require('../middleware/validators');
const { requireAuth, requireRol } = require('../middleware/auth');

const router = express.Router();

// Modificación de nota: solo admin, id numérico y nota entera 0-100 (además del CHECK en BD).
router.put('/:id', requireAuth, requireRol('admin'), reglas.idNumerico('id'), reglas.nota(), validar,
  async (req, res, next) => {
    try {
      const [r] = await getPool().execute('UPDATE notas SET nota = ? WHERE id = ?', [req.body.nota, req.params.id]);
      if (r.affectedRows === 0) return res.status(404).json({ error: 'ERR_NO_ENCONTRADO' });
      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

module.exports = router;
