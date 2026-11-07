'use strict';
/**
 * Comprueba UNA vez si MySQL de laboratorio está disponible. Si no lo está, las pruebas de
 * integración se marcan como omitidas (no fallidas) y se informa el motivo sin credenciales.
 */
module.exports = async () => {
  require('./setup-env');
  const mysql = require('mysql2/promise');
  try {
    const c = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT),
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      connectTimeout: 3000,
    });
    const [[{ n }]] = await c.query('SELECT COUNT(*) AS n FROM estudiantes');
    await c.end();
    process.env.TEST_DB = n >= 8 ? '1' : '0';
    if (n < 8) console.warn('\n[tests] BD sin seed: ejecute "npm run db:reset". Pruebas de integración omitidas.');
  } catch (err) {
    process.env.TEST_DB = '0';
    console.warn(`\n[tests] MySQL no disponible (${err.code}). Pruebas de integración omitidas.`);
  }
};
