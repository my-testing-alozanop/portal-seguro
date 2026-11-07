import { useState } from 'react';
import { api } from '../api.js';

const MENSAJES = {
  ERR_CREDENCIALES: 'Correo o contraseña incorrectos.', // genérico: no revela cuál falló
  ERR_VALIDACION: 'Revise los campos marcados.',
  ERR_REGISTRO: 'No fue posible completar el registro.',
  ERR_DEMASIADOS_INTENTOS: 'Demasiados intentos. Espere unos minutos.',
};

export default function Login({ onLogin }) {
  const [modo, setModo] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mensaje, setMensaje] = useState('');

  async function enviar(e) {
    e.preventDefault();
    setMensaje('');
    const ruta = modo === 'login' ? '/api/auth/login' : '/api/auth/registro';
    const r = await api(ruta, { method: 'POST', body: { email, password } });
    setPassword('');
    if (!r.ok) {
      const extra = r.data?.campos ? ` (${r.data.campos.join(', ')})` : '';
      setMensaje((MENSAJES[r.data?.error] ?? 'Error.') + extra);
      return;
    }
    if (modo === 'registro') {
      setModo('login');
      setMensaje('Cuenta creada. Inicie sesión.');
      return;
    }
    onLogin();
  }

  return (
    <section>
      <h2>{modo === 'login' ? 'Iniciar sesión' : 'Crear cuenta'}</h2>
      <form onSubmit={enviar} className="formulario">
        <label>
          Correo
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required maxLength={120}
            autoComplete="username" />
        </label>
        <label>
          Contraseña {modo === 'registro' && <small>(mínimo 10 caracteres)</small>}
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required
            minLength={modo === 'registro' ? 10 : 1} maxLength={128}
            autoComplete={modo === 'login' ? 'current-password' : 'new-password'} />
        </label>
        <button type="submit">{modo === 'login' ? 'Entrar' : 'Registrarme'}</button>
      </form>
      {mensaje && <p className="aviso">{mensaje}</p>}
      <p>
        <button className="enlace" onClick={() => { setModo(modo === 'login' ? 'registro' : 'login'); setMensaje(''); }}>
          {modo === 'login' ? '¿No tiene cuenta? Regístrese' : 'Ya tengo cuenta'}
        </button>
      </p>
    </section>
  );
}
