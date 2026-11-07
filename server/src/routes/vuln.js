'use strict';
/**
 * ⚠️  RUTAS DELIBERADAMENTE VULNERABLES — SOLO LABORATORIO  ⚠️
 *
 * Este router solo se monta cuando LAB_VULN=1 (ver src/app.js) y el servidor
 * escucha únicamente en 127.0.0.1. Cada endpoint tiene su contraparte segura en /api/...
 * Las vulnerabilidades se agregan en las Fases I y II.
 */
const express = require('express');

const router = express.Router();

router.get('/', (_req, res) => {
  res.json({ aviso: 'Modo laboratorio vulnerable ACTIVO (LAB_VULN=1). No usar fuera de localhost.' });
});

module.exports = router;
