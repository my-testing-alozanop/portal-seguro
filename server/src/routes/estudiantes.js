'use strict';
const express = require('express');
const { param } = require('express-validator');
const { getPool } = require('../db/pool');
const { buscarEstudiantes, obtenerExpediente } = require('../db/estudiantes.repo');
const { reglas, validar } = require('../middleware/validators');
const { requireAuth, requireRol } = require('../middleware/auth');
const { encrypt, decrypt } = require('../lib/crypto');

const router = express.Router();

/** Muestra solo los últimos 4 dígitos del DPI (minimización de datos). */
function dpiEnmascarado(est) {
  if (!est.dpi_cifrado) return null;
  const dpi = decrypt(est.dpi_cifrado, est.carne); // el carné es el AAD de GCM
  return `${'*'.repeat(dpi.length - 4)}${dpi.slice(-4)}`;
}

// Fase I-B · búsqueda SEGURA: validación + consulta parametrizada. Responde JSON (no HTML).
router.get('/buscar', requireAuth, reglas.busqueda('q'), validar, async (req, res, next) => {
  try {
    res.json({ resultados: await buscarEstudiantes(req.query.q) });
  } catch (err) {
    next(err);
  }
});

// Expediente: un estudiante solo ve el suyo; el admin puede ver cualquiera.
router.get('/:carne/expediente', requireAuth, reglas.carne('carne', param), validar,
  async (req, res, next) => {
    try {
      const exp = await obtenerExpediente(req.params.carne);
      const esPropio = exp && exp.id === req.usuario.estudianteId;
      if (!exp || (!esPropio && req.usuario.rol !== 'admin')) {
        // Misma respuesta para "no existe" y "no autorizado": no revela qué carnés existen.
        return res.status(404).json({ error: 'ERR_NO_ENCONTRADO' });
      }
      const { id, dpi_cifrado, ...publico } = exp;
      return res.json({ ...publico, dpi: dpiEnmascarado(exp) });
    } catch (err) {
      return next(err);
    }
  });

// Alta de estudiante (admin): valida todos los campos y cifra el DPI antes de guardarlo.
router.post('/', requireAuth, requireRol('admin'),
  reglas.carne(), reglas.nombre('nombres'), reglas.nombre('apellidos'), reglas.email(),
  reglas.carrera(), reglas.dpi(), validar,
  async (req, res, next) => {
    try {
      const { carne, nombres, apellidos, email, carrera, dpi } = req.body;
      await getPool().execute(
        'INSERT INTO estudiantes (carne, nombres, apellidos, email, carrera, dpi_cifrado) VALUES (?, ?, ?, ?, ?, ?)',
        [carne, nombres, apellidos, email, carrera, encrypt(dpi, carne)],
      );
      return res.status(201).json({ ok: true, carne });
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'ERR_DUPLICADO' });
      return next(err);
    }
  });

module.exports = router;
