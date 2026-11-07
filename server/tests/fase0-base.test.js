'use strict';
const request = require('supertest');
const { createApp } = require('../src/app');
const { loadSecrets, SecretConfigError } = require('../src/config/secrets');
const { encrypt, decrypt } = require('../src/lib/crypto');

describe('Fase 0 · aplicación base', () => {
  test('GET /api/health responde ok', async () => {
    const res = await request(createApp({ labVuln: false })).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  test('no expone la cabecera X-Powered-By', async () => {
    const res = await request(createApp({ labVuln: false })).get('/api/health');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  test('las rutas /vuln NO existen si LAB_VULN != 1', async () => {
    const res = await request(createApp({ labVuln: false })).get('/vuln/');
    expect(res.status).toBe(404);
  });

  test('las rutas /vuln existen solo con LAB_VULN = 1', async () => {
    const res = await request(createApp({ labVuln: true })).get('/vuln/');
    expect(res.status).toBe(200);
  });
});

describe('Fase 0 · secrets.js', () => {
  test('falla si falta un secreto, nombrando la variable pero no valores', () => {
    const env = { ...process.env };
    delete env.DB_PASSWORD;
    expect(() => loadSecrets(env)).toThrow(SecretConfigError);
    try {
      loadSecrets(env);
    } catch (e) {
      expect(e.message).toContain('DB_PASSWORD');
      expect(e.message).not.toContain(process.env.SESSION_SECRET);
      expect(e.message).not.toContain(process.env.DATA_KEY_V1);
    }
  });

  test('trata el placeholder __CAMBIAR__ como ausente', () => {
    expect(() => loadSecrets({ ...process.env, SESSION_SECRET: '__CAMBIAR__' })).toThrow(/SESSION_SECRET/);
  });

  test('rechaza una clave AES que no mide 32 bytes sin revelarla', () => {
    const corta = Buffer.alloc(16, 7).toString('base64');
    let msg = '';
    try {
      loadSecrets({ ...process.env, DATA_KEY_V1: corta });
    } catch (e) {
      msg = e.message;
    }
    expect(msg).toMatch(/DATA_KEY_V1/);
    expect(msg).not.toContain(corta);
  });
});

describe('Fase 0 · cifrado AES-256-GCM', () => {
  test('cifra y descifra con formato versionado v1:iv:tag:ct', () => {
    const token = encrypt('1000000000101', '2026-0001');
    expect(token).toMatch(/^v1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/);
    expect(token).not.toContain('1000000000101');
    expect(decrypt(token, '2026-0001')).toBe('1000000000101');
  });

  test('IV aleatorio: el mismo texto produce cifrados distintos', () => {
    expect(encrypt('x', 'a')).not.toBe(encrypt('x', 'a'));
  });

  test('GCM detecta manipulación del cifrado o AAD incorrecto', () => {
    const token = encrypt('1000000000101', '2026-0001');
    expect(() => decrypt(token, '2026-0002')).toThrow();
    const [v, iv, tag, ct] = token.split(':');
    const ctAlterado = Buffer.from(ct, 'base64');
    ctAlterado[0] ^= 0xff;
    expect(() => decrypt([v, iv, tag, ctAlterado.toString('base64')].join(':'), '2026-0001')).toThrow();
  });
});
