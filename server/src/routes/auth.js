'use strict';
const express = require('express');
const { getPool } = require('../db/pool');
const { hashPassword, verifyPassword } = require('../lib/passwords');
const { reglas, validar } = require('../middleware/validators');
const { emitirSesion, cerrarSesion, requireAuth } = require('../middleware/auth');

const router = express.Router();

// Hash señuelo: si el correo no existe se verifica igual contra él, para que el tiempo de
// respuesta no revele qué correos están registrados (enumeración de usuarios).
let hashSenuelo;
const senuelo = async () => (hashSenuelo ??= await hashPassword('senuelo-no-es-una-credencial'));

router.post('/registro', reglas.email(), reglas.password(), validar, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const hash = await hashPassword(password); // Argon2id con sal aleatoria
    await getPool().execute(
      "INSERT INTO usuarios (email, password_hash, password_algo, rol) VALUES (?, ?, 'argon2id', 'estudiante')",
      [email, hash],
    );
    return res.status(201).json({ ok: true });
  } catch (err) {
    // Correo duplicado: respuesta genérica (no confirma ni niega la existencia de la cuenta).
    if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'ERR_REGISTRO' });
    return next(err);
  }
});

// En login NO se responde 400 con detalle de validación: cualquier entrada inválida termina en
// el mismo 401 genérico. reglas.email() se usa solo para normalizar (NFKC + minúsculas).
router.post('/login', reglas.email(), async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (typeof email !== 'string' || typeof password !== 'string' || password.length > 128) {
      return res.status(401).json({ error: 'ERR_CREDENCIALES' });
    }
    const [[u]] = await getPool().execute(
      "SELECT id, password_hash, rol, estudiante_id FROM usuarios WHERE email = ? AND password_algo = 'argon2id'",
      [email],
    );
    const ok = u
      ? await verifyPassword(u.password_hash, password.normalize('NFKC'))
      : (await verifyPassword(await senuelo(), password), false);

    if (!ok) {
      // Mensaje genérico: no indica si falló el correo o la contraseña.
      return res.status(401).json({ error: 'ERR_CREDENCIALES' });
    }
    emitirSesion(res, u);
    return res.json({ ok: true, rol: u.rol });
  } catch (err) {
    return next(err);
  }
});

router.post('/logout', (_req, res) => {
  cerrarSesion(res);
  res.json({ ok: true });
});

router.get('/yo', requireAuth, async (req, res, next) => {
  try {
    const [[u]] = await getPool().execute(
      `SELECT u.email, u.rol, e.carne
         FROM usuarios u LEFT JOIN estudiantes e ON e.id = u.estudiante_id
        WHERE u.id = ?`,
      [req.usuario.id],
    );
    if (!u) return res.status(401).json({ error: 'ERR_NO_AUTENTICADO' });
    return res.json(u);
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
