'use strict';
/**
 * Carga 8 estudiantes FICTICIOS, sus notas, una cuenta por estudiante y una cuenta admin.
 * - Contraseñas: leídas de SEED_ADMIN_PASSWORD / SEED_USER_PASSWORD (nunca en el código),
 *   almacenadas con Argon2id.
 * - DPI ficticio: cifrado con AES-256-GCM (clave versionada), con el carné como AAD.
 * Es idempotente: vacía las tablas antes de insertar.
 */
require('../src/config/load-env');
const { getPool, closePool } = require('../src/db/pool');
const { encrypt } = require('../src/lib/crypto');
const { hashPassword } = require('../src/lib/passwords');

const DOMINIO = 'universidad.example'; // dominio reservado (RFC 2606): no existe

const ESTUDIANTES = [
  { carne: '2026-0001', nombres: 'Ana Lucía', apellidos: 'Pérez Gómez', carrera: 'Ingeniería en Sistemas', dpi: '1000000000101' },
  { carne: '2026-0002', nombres: 'Carlos Eduardo', apellidos: 'Méndez Ruiz', carrera: 'Ingeniería en Sistemas', dpi: '1000000000202' },
  { carne: '2026-0003', nombres: 'María José', apellidos: 'López Castillo', carrera: 'Administración de Empresas', dpi: '1000000000303' },
  { carne: '2026-0004', nombres: 'José Andrés', apellidos: 'García Morales', carrera: 'Derecho', dpi: '1000000000404' },
  { carne: '2026-0005', nombres: 'Sofía Alejandra', apellidos: 'Ramírez Ortiz', carrera: 'Medicina', dpi: '1000000000505' },
  { carne: '2026-0006', nombres: 'Diego Fernando', apellidos: "O'Connor Herrera", carrera: 'Arquitectura', dpi: '1000000000606' },
  { carne: '2026-0007', nombres: 'Valeria', apellidos: 'Núñez Estrada', carrera: 'Psicología', dpi: '1000000000707' },
  { carne: '2026-0008', nombres: 'Luis Miguel', apellidos: 'Santos Aguilar', carrera: 'Ingeniería en Sistemas', dpi: '1000000000808' },
];

const CURSOS = ['Matemática I', 'Programación I', 'Seguridad Informática', 'Bases de Datos'];

function requiredEnv(name) {
  const v = process.env[name];
  if (!v || v === '__CAMBIAR__') throw new Error(`Falta la variable ${name} en server/.env`);
  return v;
}

function emailDe(e) {
  const quitarTildes = (s) => s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
  const nombre = quitarTildes(e.nombres.split(' ')[0]);
  const apellido = quitarTildes(e.apellidos.split(' ')[0]).replace(/[^a-z]/g, '');
  return `${nombre}.${apellido}@${DOMINIO}`;
}

async function main() {
  const adminPass = requiredEnv('SEED_ADMIN_PASSWORD');
  const userPass = requiredEnv('SEED_USER_PASSWORD');
  const pool = getPool();

  await pool.query('SET FOREIGN_KEY_CHECKS = 0');
  for (const t of ['comentarios', 'notas', 'usuarios', 'estudiantes']) await pool.query(`TRUNCATE TABLE ${t}`);
  await pool.query('SET FOREIGN_KEY_CHECKS = 1');

  const userHash = await hashPassword(userPass);

  for (const [i, e] of ESTUDIANTES.entries()) {
    const email = emailDe(e);
    const [r] = await pool.execute(
      'INSERT INTO estudiantes (carne, nombres, apellidos, email, carrera, dpi_cifrado) VALUES (?, ?, ?, ?, ?, ?)',
      [e.carne, e.nombres, e.apellidos, email, e.carrera, encrypt(e.dpi, e.carne)],
    );
    const estudianteId = r.insertId;

    for (const [j, curso] of CURSOS.entries()) {
      const nota = 55 + ((i * 7 + j * 11) % 46); // 55..100, determinista
      await pool.execute(
        'INSERT INTO notas (estudiante_id, curso, semestre, nota) VALUES (?, ?, ?, ?)',
        [estudianteId, curso, '2026-1', nota],
      );
    }

    await pool.execute(
      "INSERT INTO usuarios (email, password_hash, password_algo, rol, estudiante_id) VALUES (?, ?, 'argon2id', 'estudiante', ?)",
      [email, userHash, estudianteId],
    );
  }

  await pool.execute(
    "INSERT INTO usuarios (email, password_hash, password_algo, rol) VALUES (?, ?, 'argon2id', 'admin')",
    [`admin@${DOMINIO}`, await hashPassword(adminPass)],
  );

  console.log(`Seed completo: ${ESTUDIANTES.length} estudiantes, ${ESTUDIANTES.length * CURSOS.length} notas, ${ESTUDIANTES.length + 1} usuarios.`);
  console.log(`Cuenta admin: admin@${DOMINIO}  | Estudiantes: <nombre>.<apellido>@${DOMINIO}`);
}

main()
  .catch((err) => {
    console.error(`[seed] ${err.code || err.name}: ${err.message}`);
    process.exitCode = 1;
  })
  .finally(closePool);
