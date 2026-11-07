'use strict';
/**
 * Sesión con JWT (HS256) firmado con SESSION_SECRET y entregado en una cookie:
 *   - HttpOnly  -> JavaScript (incluido un XSS) no puede leer el token.
 *   - Secure    -> solo viaja por HTTPS (los navegadores aceptan además http://localhost).
 *   - SameSite=Strict -> no se envía en peticiones originadas en otros sitios (mitiga CSRF).
 */
const jwt = require('jsonwebtoken');
const { getSecrets } = require('../config/secrets');

const COOKIE = 'sid';
const DURACION_S = 60 * 60; // 1 hora

const cookieOptions = () => ({
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  path: '/',
  maxAge: DURACION_S * 1000,
});

function emitirSesion(res, usuario) {
  const token = jwt.sign(
    { sub: String(usuario.id), rol: usuario.rol, est: usuario.estudiante_id ?? null },
    getSecrets().sessionSecret,
    { algorithm: 'HS256', expiresIn: DURACION_S },
  );
  res.cookie(COOKIE, token, cookieOptions());
}

function cerrarSesion(res) {
  const { maxAge, ...opts } = cookieOptions();
  res.clearCookie(COOKIE, opts);
}

function leerSesion(req) {
  const token = req.cookies?.[COOKIE];
  if (!token) return null;
  try {
    // algorithms fijo: evita ataques de confusión de algoritmo ("alg": "none").
    const p = jwt.verify(token, getSecrets().sessionSecret, { algorithms: ['HS256'] });
    return { id: Number(p.sub), rol: p.rol, estudianteId: p.est };
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const usuario = leerSesion(req);
  if (!usuario) return res.status(401).json({ error: 'ERR_NO_AUTENTICADO' });
  req.usuario = usuario;
  return next();
}

const requireRol = (rol) => (req, res, next) =>
  req.usuario?.rol === rol ? next() : res.status(403).json({ error: 'ERR_PROHIBIDO' });

module.exports = { COOKIE, emitirSesion, cerrarSesion, leerSesion, requireAuth, requireRol };
