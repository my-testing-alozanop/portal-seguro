'use strict';
/**
 * Utilidades de prueba. Cada ejecución crea usuarios temporales con correo aleatorio
 * (prefijo "test-") y contraseña aleatoria, y los elimina al terminar.
 */
const crypto = require('node:crypto');
const request = require('supertest');
const { createApp } = require('../src/app');
const { getPool, closePool } = require('../src/db/pool');
const { hashPassword } = require('../src/lib/passwords');

const hayBD = process.env.TEST_DB === '1';
const describeDb = hayBD ? describe : describe.skip;

const rnd = (n = 6) => crypto.randomBytes(n).toString('hex');

async function crearUsuario({ rol = 'estudiante', carne = null } = {}) {
  const email = `test-${rnd()}@universidad.example`;
  const password = `Pw-${rnd(12)}`;
  const pool = getPool();
  let estudianteId = null;
  if (carne) {
    const [[e]] = await pool.execute('SELECT id FROM estudiantes WHERE carne = ?', [carne]);
    estudianteId = e.id;
  }
  await pool.execute(
    "INSERT INTO usuarios (email, password_hash, password_algo, rol, estudiante_id) VALUES (?, ?, 'argon2id', ?, ?)",
    [email, await hashPassword(password), rol, estudianteId],
  );
  return { email, password };
}

/** Cookie de sesión firmada directamente (para pruebas que no necesitan un usuario en BD). */
function cookieSesion({ id = 999999, rol = 'estudiante', est = null } = {}) {
  const jwt = require('jsonwebtoken');
  const token = jwt.sign({ sub: String(id), rol, est }, process.env.SESSION_SECRET, { algorithm: 'HS256', expiresIn: 300 });
  return `sid=${token}`;
}

/** Inicia sesión y devuelve la cabecera Cookie lista para reutilizar. */
async function login(app, { email, password }) {
  const res = await request(app).post('/api/auth/login').send({ email, password });
  if (res.status !== 200) throw new Error(`login de prueba falló: ${res.status}`);
  return res.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');
}

/** Redirige el logger seguro a memoria y devuelve accesores a las líneas JSON registradas. */
function capturarLogs() {
  const lineas = [];
  require('../src/lib/logger')._setLoggerParaPruebas({ write: (l) => lineas.push(l) });
  return {
    texto: () => lineas.join(''),
    eventos: (nombre) => lineas.map((l) => JSON.parse(l)).filter((e) => !nombre || e.evento === nombre),
    limpiar: () => lineas.splice(0),
  };
}

async function limpiar() {
  const pool = getPool();
  await pool.query("DELETE FROM comentarios WHERE usuario_id IN (SELECT id FROM usuarios WHERE email LIKE 'test-%')");
  await pool.query("DELETE FROM usuarios WHERE email LIKE 'test-%'");
  await pool.query("DELETE FROM estudiantes WHERE email LIKE 'test-%'");
}

async function finalizar() {
  if (hayBD) await limpiar();
  await closePool();
}

module.exports = { createApp, request, hayBD, describeDb, crearUsuario, login, cookieSesion, capturarLogs, limpiar, finalizar, rnd };
