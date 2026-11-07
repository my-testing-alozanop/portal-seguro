'use strict';
const express = require('express');
const { body, param } = require('express-validator');
const { validar } = require('../middleware/validators');
const { requireAuth, requireRol } = require('../middleware/auth');
const { generarReporte, rutaSegura, TIPOS } = require('../lib/reportes');

const router = express.Router();

// Privilegio mínimo: solo el rol admin genera y descarga reportes.
router.use(requireAuth, requireRol('admin'));

router.post('/', body('tipo').isIn(Object.keys(TIPOS)).withMessage('lista blanca'), validar,
  async (req, res, next) => {
    try {
      const r = await generarReporte(req.body.tipo);
      res.status(201).json({ ...r, descarga: `/api/reportes/${r.archivo}` });
    } catch (err) {
      next(err);
    }
  });

router.get('/:archivo', param('archivo').isString(), validar, (req, res) => {
  const ruta = rutaSegura(req.params.archivo);
  if (!ruta) return res.status(400).json({ error: 'ERR_VALIDACION', campos: ['archivo'] });
  return res.download(ruta, 'reporte.zip', (err) => {
    if (err && !res.headersSent) res.status(404).json({ error: 'ERR_NO_ENCONTRADO' });
  });
});

module.exports = router;
