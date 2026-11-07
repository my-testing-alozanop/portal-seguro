'use strict';
const crypto = require('node:crypto');

/**
 * Id de correlación por petición. Se devuelve al cliente en X-Request-Id y en los errores,
 * y se incluye en cada evento del log: soporte puede ubicar el detalle técnico en el log
 * sin que el usuario vea nada sensible. No se acepta un id enviado por el cliente
 * (evita inyección de valores arbitrarios en los logs).
 */
module.exports = function requestId(req, res, next) {
  req.id = crypto.randomUUID();
  res.setHeader('X-Request-Id', req.id);
  next();
};
