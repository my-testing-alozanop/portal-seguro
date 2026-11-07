'use strict';
/**
 * Fase I-D · Inyección de comandos y control de rutas en la generación de reportes.
 */
const fs = require('node:fs');
const path = require('node:path');
const childProcess = require('node:child_process');
const { createApp, request, describeDb, cookieSesion, finalizar } = require('./helpers');
const { rutaSegura, celdaCsv, REPORTS_DIR } = require('../src/lib/reportes');

const admin = cookieSesion({ rol: 'admin' });
const estudiante = cookieSesion({ rol: 'estudiante' });
const UUID_ZIP = /^[0-9a-f-]{36}\.zip$/;

afterAll(async () => {
  // limpia archivos creados por la versión vulnerable (nombres no-UUID)
  if (fs.existsSync(REPORTS_DIR)) {
    for (const f of fs.readdirSync(REPORTS_DIR)) {
      if (!UUID_ZIP.test(f)) fs.rmSync(path.join(REPORTS_DIR, f), { force: true });
    }
  }
  await finalizar();
});

describe('I-D · controles sin BD', () => {
  const app = createApp({ labVuln: false });

  test('tipo fuera de la lista blanca -> 400 (los metacaracteres nunca llegan a nada)', async () => {
    for (const tipo of ['notas & echo INYECTADO', 'notas; id', '../notas', '$(whoami)']) {
      const res = await request(app).post('/api/reportes').set('Cookie', admin).send({ tipo });
      expect(res.status).toBe(400);
    }
  });

  test('privilegio mínimo: un estudiante no puede generar reportes (403)', async () => {
    const res = await request(app).post('/api/reportes').set('Cookie', estudiante).send({ tipo: 'notas' });
    expect(res.status).toBe(403);
  });

  test('control de rutas: solo nombres UUID.zip dentro de reports/', () => {
    expect(rutaSegura('../package.json')).toBeNull();
    expect(rutaSegura('..\\..\\.env')).toBeNull();
    expect(rutaSegura('/etc/passwd')).toBeNull();
    expect(rutaSegura('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.zip/../../x')).toBeNull();
    const ok = rutaSegura('0b0f2f0e-1111-4222-8333-944444444444.zip');
    expect(ok.startsWith(REPORTS_DIR + path.sep)).toBe(true);
  });

  test('descarga con path traversal -> 400', async () => {
    for (const archivo of ['..%2Fpackage.json', '..%5C..%5C.env', 'package.json']) {
      const res = await request(app).get(`/api/reportes/${archivo}`).set('Cookie', admin);
      expect(res.status).toBe(400);
    }
  });

  test('CSV: neutraliza inyección de fórmulas', () => {
    expect(celdaCsv('=HYPERLINK("http://x")')).toBe('"\'=HYPERLINK(""http://x"")"');
    expect(celdaCsv('Pérez')).toBe('"Pérez"');
  });
});

describeDb('I-D · generación SEGURA con archiver', () => {
  const app = createApp({ labVuln: false });

  test('genera ZIP válido sin invocar ningún proceso del sistema', async () => {
    const spies = ['exec', 'execFile', 'spawn', 'execSync'].map((m) => jest.spyOn(childProcess, m));
    const res = await request(app).post('/api/reportes').set('Cookie', admin)
      .send({ tipo: 'notas', nombre: 'x" & echo INYECTADO & echo "' }); // "nombre" se ignora
    expect(res.status).toBe(201);
    expect(res.body.archivo).toMatch(UUID_ZIP);
    for (const s of spies) expect(s).not.toHaveBeenCalled();

    const dl = await request(app).get(res.body.descarga).set('Cookie', admin)
      .buffer(true).parse((r, cb) => { const d = []; r.on('data', (c) => d.push(c)); r.on('end', () => cb(null, Buffer.concat(d))); });
    expect(dl.status).toBe(200);
    expect(dl.body.subarray(0, 2).toString()).toBe('PK'); // firma ZIP
    fs.rmSync(path.join(REPORTS_DIR, res.body.archivo), { force: true });
  });
});

describeDb('I-D · versión VULNERABLE con exec (contraste, LAB_VULN=1)', () => {
  const app = createApp({ labVuln: true });

  test('el nombre inyecta un comando que la shell ejecuta', async () => {
    const res = await request(app).post('/vuln/reporte').set('Cookie', admin)
      .send({ tipo: 'notas', nombre: 'x" & echo INYECTADO & echo "' });
    expect(res.status).toBe(200);
    expect(res.body.comando).toContain('& echo INYECTADO &');
    expect(res.body.stdout).toContain('INYECTADO');
  });

  test('path traversal: lee archivos fuera de reports/', async () => {
    const res = await request(app).get('/vuln/reporte/descargar').query({ archivo: '../package.json' }).set('Cookie', admin);
    expect(res.status).toBe(200);
    expect(res.text).toContain('portal-lab-server');
  });
});
