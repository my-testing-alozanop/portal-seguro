'use strict';
/**
 * Fase II-B/C · Rotación de la clave de cifrado de datos (DPI).
 *
 * Procedimiento:
 *   1. Generar la nueva clave:          openssl rand -base64 32
 *   2. Agregarla a server/.env (o Vault): DATA_KEY_V2=<nueva>   y   DATA_KEY_CURRENT=v2
 *      (conservar DATA_KEY_V1: se necesita para descifrar lo existente)
 *   3. Ejecutar:                         npm run rotar-clave
 *      -> descifra cada DPI con su versión (v1) y lo vuelve a cifrar con la actual (v2).
 *   4. Verificar que no queden registros v1 y entonces RETIRAR DATA_KEY_V1 (revocación).
 *
 * Gracias al prefijo de versión "vN:" en cada valor, la rotación puede hacerse en caliente:
 * la aplicación descifra datos de ambas versiones mientras dura la migración.
 */
require('../src/config/load-env');
const { getSecrets } = require('../src/config/secrets');
const { getPool, closePool } = require('../src/db/pool');
const { encrypt, decrypt } = require('../src/lib/crypto');

async function main() {
  const actual = getSecrets().dataKeyCurrent;
  const pool = getPool();
  const [filas] = await pool.query('SELECT id, carne, dpi_cifrado FROM estudiantes WHERE dpi_cifrado IS NOT NULL');
  let rotados = 0;
  for (const f of filas) {
    if (f.dpi_cifrado.startsWith(`${actual}:`)) continue;
    const nuevo = encrypt(decrypt(f.dpi_cifrado, f.carne), f.carne);
    await pool.execute('UPDATE estudiantes SET dpi_cifrado = ? WHERE id = ?', [nuevo, f.id]);
    rotados += 1;
  }
  const [vers] = await pool.query(
    "SELECT SUBSTRING_INDEX(dpi_cifrado, ':', 1) AS version, COUNT(*) AS n FROM estudiantes WHERE dpi_cifrado IS NOT NULL GROUP BY version",
  );
  console.log(`Clave activa: ${actual}. Registros re-cifrados: ${rotados}.`);
  console.table(vers);
}

main()
  .catch((err) => {
    console.error(`[rotar-clave] ${err.name}: ${err.code || err.message}`);
    process.exitCode = 1;
  })
  .finally(closePool);
