'use strict';
/**
 * Fase I-A · Validación de entradas y normalización NFKC.
 * No requiere BD: los rechazos ocurren antes de cualquier consulta.
 */
const { createApp, request, cookieSesion, finalizar } = require('./helpers');
const { reglas } = require('../src/middleware/validators');
const { validationResult } = require('express-validator');

/** Ejecuta una cadena de validación sobre una petición simulada. */
async function correr(regla, req) {
  await regla.run(req);
  return { ok: validationResult(req).isEmpty(), req };
}

afterAll(finalizar);

describe('I-A · reglas de validación (lista blanca)', () => {
  test.each([
    ['2026-0001', true],
    ['20260001', false],
    ['2026-001', false],
    ["2026-0001' OR '1'='1", false],
  ])('carné %p -> válido=%p', async (carne, esperado) => {
    expect((await correr(reglas.carne(), { body: { carne } })).ok).toBe(esperado);
  });

  test.each([
    ['ana.perez@universidad.example', true],
    ['no-es-correo', false],
    ['a@b', false],
    ['<script>@x.com', false],
  ])('correo %p -> válido=%p', async (email, esperado) => {
    expect((await correr(reglas.email(), { body: { email } })).ok).toBe(esperado);
  });

  test.each([
    ['María José', true],
    ["O'Connor", true],
    ['Núñez-Estrada', true],
    ['<script>', false],
    ['Robert1', false],
    ['A', false],
  ])('nombre %p -> válido=%p', async (v, esperado) => {
    expect((await correr(reglas.nombre('nombres'), { body: { nombres: v } })).ok).toBe(esperado);
  });

  test.each([
    [0, true],
    [100, true],
    ['85', true],
    [101, false],
    [-1, false],
    [85.5, false],
    ['abc', false],
  ])('nota %p -> válida=%p', async (nota, esperado) => {
    expect((await correr(reglas.nota(), { body: { nota } })).ok).toBe(esperado);
  });

  test.each([
    ['Pérez', true],
    ["O'Connor", true],
    ['%', false],
    ['a;DROP TABLE x', false],
    ['x'.repeat(51), false],
  ])('búsqueda %p -> válida=%p', async (q, esperado) => {
    expect((await correr(reglas.busqueda(), { query: { q } })).ok).toBe(esperado);
  });
});

describe('I-A · normalización NFKC antes de validar', () => {
  test('carné en dígitos de ancho completo se normaliza a ASCII', async () => {
    const { ok, req } = await correr(reglas.carne(), { body: { carne: '２０２６－０００１' } });
    expect(ok).toBe(true);
    expect(req.body.carne).toBe('2026-0001');
  });

  test('ligaduras y compatibilidad: "ﬁ" -> "fi"', async () => {
    const { req } = await correr(reglas.nombre('nombres'), { body: { nombres: 'Deﬁna' } });
    expect(req.body.nombres).toBe('Defina');
  });

  test('comilla de ancho completo ＇ se normaliza a \' (y por eso igual se necesita SQL parametrizado)', async () => {
    const { ok, req } = await correr(reglas.busqueda(), { query: { q: 'x＇ OR ＇a＇ LIKE ＇a' } });
    expect(ok).toBe(true);
    expect(req.query.q).toBe("x' OR 'a' LIKE 'a");
  });
});

describe('I-A · validar NO equivale a "seguro para SQL/HTML/shell"', () => {
  test("una carga SQLi formada solo con caracteres permitidos PASA la validación", async () => {
    const { ok } = await correr(reglas.busqueda(), { query: { q: "x' OR 'a' LIKE 'a" } });
    expect(ok).toBe(true); // => la defensa real es la consulta parametrizada (ver fase1b)
  });

  test('un comentario con HTML es un comentario válido', async () => {
    const { ok } = await correr(reglas.comentario(), { body: { contenido: '<img src=x onerror=alert(1)>' } });
    expect(ok).toBe(true); // => la defensa real es codificar la salida (ver fase1c)
  });
});

describe('I-A · los endpoints rechazan con 400 sin reflejar el valor', () => {
  const app = createApp({ labVuln: false });
  const admin = cookieSesion({ rol: 'admin' });

  test('alta de estudiante con campos inválidos -> 400 con nombres de campos', async () => {
    const malo = '<script>alert(1)</script>';
    const res = await request(app).post('/api/estudiantes').set('Cookie', admin).send({
      carne: '123', nombres: malo, apellidos: 'Pérez', email: 'x', carrera: 'Sistemas', dpi: '12',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('ERR_VALIDACION');
    expect(res.body.campos).toEqual(expect.arrayContaining(['carne', 'nombres', 'email', 'dpi']));
    expect(JSON.stringify(res.body)).not.toContain('<script>');
  });

  test('nota fuera de rango -> 400', async () => {
    const res = await request(app).put('/api/notas/1').set('Cookie', admin).send({ nota: 150 });
    expect(res.status).toBe(400);
    expect(res.body.campos).toEqual(['nota']);
  });

  test('registro con correo inválido o contraseña corta -> 400', async () => {
    const res = await request(app).post('/api/auth/registro').send({ email: 'malo', password: 'corta' });
    expect(res.status).toBe(400);
    expect(res.body.campos).toEqual(expect.arrayContaining(['email', 'password']));
  });
});
