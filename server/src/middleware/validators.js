'use strict';
/**
 * Fase I-A · Validación de entradas con express-validator.
 *
 * Orden aplicado a cada campo de texto:
 *   1. Normalización Unicode NFKC  -> "２０２６－０００１" (ancho completo) pasa a "2026-0001";
 *      evita que caracteres equivalentes visualmente salten las listas blancas.
 *   2. trim
 *   3. Validación por lista blanca (formato/rango esperado).
 *
 * IMPORTANTE: validar NO hace que un dato sea seguro para SQL, HTML o la shell.
 * Ejemplo: "O'Connor" es un apellido VÁLIDO y contiene una comilla; "<b>hola</b>" puede ser un
 * comentario válido. Por eso además se usa: consultas parametrizadas (SQL), codificación de
 * salida (HTML) y argumentos sin shell (comandos). La validación reduce superficie; no sustituye
 * el control específico de cada contexto.
 */
const { body, query, param, validationResult } = require('express-validator');

const nfkc = (v) => (typeof v === 'string' ? v.normalize('NFKC').trim() : v);

// Letras Unicode (con tildes, ñ), espacios, apóstrofo y guion. 2-60 caracteres.
const RE_NOMBRE = /^\p{L}[\p{L}\p{M}' -]{1,59}$/u;
const RE_CARNE = /^\d{4}-\d{4}$/;
// Búsqueda: letras, dígitos, espacio, apóstrofo, punto y guion. Deliberadamente admite la
// comilla simple (apellidos como O'Connor): la protección contra SQLi NO depende de esto.
const RE_BUSQUEDA = /^[\p{L}\p{M}\p{N}' .-]{1,50}$/u;

const reglas = {
  email: (campo = 'email', origen = body) =>
    origen(campo)
      .customSanitizer(nfkc)
      .isLength({ max: 120 }).withMessage('largo')
      .isEmail({ allow_utf8_local_part: false }).withMessage('formato')
      .customSanitizer((v) => (typeof v === 'string' ? v.toLowerCase() : v)),

  password: (campo = 'password') =>
    body(campo)
      .isString()
      .customSanitizer((v) => (typeof v === 'string' ? v.normalize('NFKC') : v))
      .isLength({ min: 10, max: 128 }).withMessage('largo'),

  carne: (campo = 'carne', origen = body) =>
    origen(campo).customSanitizer(nfkc).matches(RE_CARNE).withMessage('formato ####-####'),

  nombre: (campo) =>
    body(campo).customSanitizer(nfkc).matches(RE_NOMBRE).withMessage('solo letras, espacio, apóstrofo o guion'),

  nota: (campo = 'nota') =>
    body(campo).isInt({ min: 0, max: 100 }).withMessage('entero 0-100').toInt(),

  busqueda: (campo = 'q') =>
    query(campo).customSanitizer(nfkc).matches(RE_BUSQUEDA).withMessage('caracteres no permitidos'),

  comentario: (campo = 'contenido') =>
    body(campo).isString().customSanitizer(nfkc).isLength({ min: 1, max: 1000 }).withMessage('1-1000 caracteres'),

  idNumerico: (campo = 'id') => param(campo).isInt({ min: 1 }).toInt(),

  dpi: (campo = 'dpi') => body(campo).customSanitizer(nfkc).matches(/^\d{13}$/).withMessage('13 dígitos'),

  carrera: (campo = 'carrera') =>
    body(campo).customSanitizer(nfkc).matches(/^[\p{L}\p{M} ]{3,80}$/u).withMessage('solo letras y espacios'),
};

/** Responde 400 con los NOMBRES de los campos inválidos (sin reflejar los valores recibidos). */
function validar(req, res, next) {
  const errores = validationResult(req);
  if (errores.isEmpty()) return next();
  const campos = [...new Set(errores.array().map((e) => e.path))];
  return res.status(400).json({ error: 'ERR_VALIDACION', campos });
}

module.exports = { reglas, validar, nfkc, RE_BUSQUEDA, RE_CARNE, RE_NOMBRE };
