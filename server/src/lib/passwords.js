'use strict';
/**
 * Hash de contraseñas con Argon2id (paquete argon2, implementación de referencia).
 * Parámetros según OWASP Password Storage Cheat Sheet (m=19 MiB, t=2, p=1).
 * La sal (16 bytes aleatorios) la genera argon2 y queda codificada en el propio hash:
 *   $argon2id$v=19$m=19456,t=2,p=1$<sal>$<hash>
 */
const argon2 = require('argon2');

const ARGON2_OPTIONS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
});

const hashPassword = (plain) => argon2.hash(plain, ARGON2_OPTIONS);
const verifyPassword = (hash, plain) => argon2.verify(hash, plain);

module.exports = { ARGON2_OPTIONS, hashPassword, verifyPassword };
