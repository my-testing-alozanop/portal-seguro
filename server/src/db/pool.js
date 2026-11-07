'use strict';
const mysql = require('mysql2/promise');
const { getSecrets } = require('../config/secrets');

let pool;

/** Pool de conexiones creado bajo demanda con credenciales obtenidas de secrets.js */
function getPool() {
  if (!pool) {
    const { db } = getSecrets();
    pool = mysql.createPool({
      ...db,
      waitForConnections: true,
      connectionLimit: 10,
      // Una sola sentencia por llamada: limita el impacto de una inyección
      // (no permite "; DROP TABLE ..." apilado).
      multipleStatements: false,
      charset: 'utf8mb4',
    });
  }
  return pool;
}

async function closePool() {
  if (pool) {
    await pool.end();
    pool = undefined;
  }
}

module.exports = { getPool, closePool };
