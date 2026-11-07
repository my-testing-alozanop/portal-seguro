'use strict';
/**
 * Fase I-B · SQL Injection.
 * PRUEBA OBLIGATORIA 1: "Entrada con caracteres especiales en búsqueda -> no altera la estructura SQL".
 */
const { createApp, request, describeDb, crearUsuario, login, finalizar } = require('./helpers');
const { buscarEstudiantes } = require('../src/db/estudiantes.repo');

const TAUTOLOGIA = "x' OR 'a' LIKE 'a"; // solo usa caracteres permitidos por la validación
const UNION = "' UNION SELECT email, password_hash, rol, id FROM usuarios -- -";

afterAll(finalizar);

describeDb('I-B · búsqueda SEGURA (consulta parametrizada)', () => {
  const app = createApp({ labVuln: false });
  let cookie;
  beforeAll(async () => {
    cookie = await login(app, await crearUsuario());
  });

  test('[PRUEBA 1] la tautología pasa la validación pero NO devuelve registros', async () => {
    const res = await request(app).get('/api/estudiantes/buscar').query({ q: TAUTOLOGIA }).set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.resultados).toEqual([]);
  });

  test("[PRUEBA 1] una comilla legítima (O'Connor) se busca literalmente", async () => {
    const res = await request(app).get('/api/estudiantes/buscar').query({ q: "O'Connor" }).set('Cookie', cookie);
    expect(res.status).toBe(200);
    // Devuelve SOLO apellidos que contienen literalmente O'Connor (puede haber más de uno)
    const apellidos = res.body.resultados.map((r) => r.apellidos);
    expect(apellidos).toContain("O'Connor Herrera");
    expect(apellidos.every((x) => x.includes("O'Connor"))).toBe(true);
  });

  test('[PRUEBA 1] UNION en la capa de datos se trata como texto: 0 filas y ningún hash', async () => {
    const filas = await buscarEstudiantes(UNION);
    expect(filas).toEqual([]);
    expect(JSON.stringify(filas)).not.toContain('$argon2');
  });

  test('[PRUEBA 1] payloads clásicos en la capa de datos no alteran la consulta', async () => {
    for (const p of ["' OR 1=1 -- ", "'; DROP TABLE estudiantes; -- ", '" OR ""="', '\\', '%', '_']) {
      await expect(buscarEstudiantes(p)).resolves.toEqual([]);
    }
    // la tabla sigue intacta
    expect((await buscarEstudiantes('Pérez')).length).toBeGreaterThan(0);
  });

  test('UNION con comas/guiones bajos es rechazado antes por la validación (400)', async () => {
    const res = await request(app).get('/api/estudiantes/buscar').query({ q: UNION }).set('Cookie', cookie);
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'ERR_VALIDACION', campos: ['q'] });
  });

  test('sin sesión la búsqueda responde 401', async () => {
    const res = await request(app).get('/api/estudiantes/buscar').query({ q: 'Ana' });
    expect(res.status).toBe(401);
  });
});

describeDb('I-B · búsqueda VULNERABLE (contraste, LAB_VULN=1)', () => {
  const app = createApp({ labVuln: true });
  let cookie;
  beforeAll(async () => {
    cookie = await login(app, await crearUsuario());
  });

  test('la tautología altera el WHERE y devuelve TODOS los estudiantes', async () => {
    const res = await request(app).get('/vuln/buscar').query({ q: TAUTOLOGIA }).set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.resultados.length).toBeGreaterThanOrEqual(8);
    expect(res.body.sql).toContain("LIKE '%x' OR 'a' LIKE 'a%'");
  });

  test('UNION extrae correos y hashes de la tabla usuarios', async () => {
    const res = await request(app).get('/vuln/buscar').query({ q: UNION }).set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body.resultados)).toContain('$argon2id$');
  });

  test('una comilla suelta provoca error SQL que se filtra al cliente', async () => {
    const res = await request(app).get('/vuln/buscar').query({ q: "O'Connor" }).set('Cookie', cookie);
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/SQL syntax/i);
  });
});
