'use strict';
/**
 * Aplica en orden los archivos server/db/migrations/NNN_*.sql que aún no se hayan
 * aplicado, registrándolos en la tabla schema_migrations.
 */
require('../src/config/load-env');
const fs = require('node:fs');
const path = require('node:path');
const { getPool, closePool } = require('../src/db/pool');

const DIR = path.join(__dirname, '..', 'db', 'migrations');

/** Divide un archivo SQL en sentencias (el pool no permite multipleStatements). */
function splitStatements(sql) {
  return sql
    .split('\n')
    .filter((l) => !l.trim().startsWith('--'))
    .join('\n')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);
}

async function main() {
  const pool = getPool();
  await pool.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    nombre VARCHAR(120) PRIMARY KEY,
    aplicada_en TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);

  const [rows] = await pool.query('SELECT nombre FROM schema_migrations');
  const aplicadas = new Set(rows.map((r) => r.nombre));
  const archivos = fs.readdirSync(DIR).filter((f) => /^\d{3}_.+\.sql$/.test(f)).sort();

  for (const archivo of archivos) {
    if (aplicadas.has(archivo)) {
      console.log(`= ${archivo} (ya aplicada)`);
      continue;
    }
    const sql = fs.readFileSync(path.join(DIR, archivo), 'utf8');
    for (const stmt of splitStatements(sql)) await pool.query(stmt);
    await pool.execute('INSERT INTO schema_migrations (nombre) VALUES (?)', [archivo]);
    console.log(`+ ${archivo}`);
  }
  console.log('Migraciones completas.');
}

main()
  .catch((err) => {
    // Solo código y mensaje del driver: nunca se imprimen credenciales.
    console.error(`[migrate] ${err.code || err.name}: ${err.message}`);
    process.exitCode = 1;
  })
  .finally(closePool);
