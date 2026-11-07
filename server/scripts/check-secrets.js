'use strict';
/**
 * Fase II-C · Muestra DE DÓNDE obtiene la aplicación cada secreto y comprueba que funciona,
 * SIN imprimir ningún valor.   npm run secrets:check
 */
require('../src/config/load-env');
const { initSecrets, getSecrets } = require('../src/config/secrets');
const { getPool, closePool } = require('../src/db/pool');

async function main() {
  const { fuente, origenes } = await initSecrets();
  const s = getSecrets();
  console.log(`Proveedor de secretos: ${fuente}\n`);
  console.log('VARIABLE            ORIGEN     ESTADO');
  console.log('------------------  ---------  ------------------------------');
  for (const [k, origen] of Object.entries(origenes)) {
    let estado = 'presente (valor oculto)';
    if (/^DATA_KEY_V\d+$/.test(k)) estado = `clave AES de ${s.dataKeys[k.slice(9).toLowerCase()]?.length * 8 || '?'} bits`;
    if (k === 'DATA_KEY_CURRENT') estado = `clave activa: ${s.dataKeyCurrent}`;
    if (k === 'DB_USER' || k === 'DB_NAME' || k === 'DB_HOST' || k === 'DB_PORT') estado = 'presente (dato de configuración)';
    console.log(`${k.padEnd(18)}  ${origen.padEnd(9)}  ${estado}`);
  }
  const [[r]] = await getPool().query('SELECT CURRENT_USER() AS usuario');
  console.log(`\nConexión a MySQL OK como ${r.usuario} usando la credencial de la fuente externa.`);
}

main()
  .catch((err) => {
    console.error(`[secrets] ${err.name}: ${err.message}`);
    process.exitCode = 1;
  })
  .finally(closePool);
