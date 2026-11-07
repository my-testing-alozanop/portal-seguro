import { useCallback, useEffect, useState } from 'react';
import { api } from './api.js';
import Login from './components/Login.jsx';
import Expediente from './components/Expediente.jsx';
import Comentarios from './components/Comentarios.jsx';
import Busqueda from './components/Busqueda.jsx';
import Reportes from './components/Reportes.jsx';
import Bienvenida from './components/Bienvenida.jsx';
import Laboratorio from './components/vuln/Laboratorio.jsx';

export default function App() {
  const [usuario, setUsuario] = useState(null);
  const [labVuln, setLabVuln] = useState(false);
  const [seccion, setSeccion] = useState('Inicio');

  const cargarUsuario = useCallback(async () => {
    const r = await api('/api/auth/yo');
    setUsuario(r.ok ? r.data : null);
  }, []);

  useEffect(() => {
    cargarUsuario();
    // El modo laboratorio solo existe si el servidor arrancó con LAB_VULN=1.
    api('/vuln/').then((r) => setLabVuln(r.ok)).catch(() => setLabVuln(false));
  }, [cargarUsuario]);

  async function salir() {
    await api('/api/auth/logout', { method: 'POST' });
    setUsuario(null);
    setSeccion('Inicio');
  }

  const secciones = usuario
    ? ['Inicio', 'Expediente', 'Comentarios', 'Búsqueda', ...(usuario.rol === 'admin' ? ['Reportes'] : []),
       ...(labVuln ? ['Laboratorio'] : [])]
    : ['Inicio', 'Comentarios'];

  return (
    <div className="app">
      <header>
        <h1>Portal Universitario</h1>
        <span className="badge">LABORATORIO · datos ficticios</span>
        {labVuln && <span className="badge vuln">LAB_VULN=1 · rutas vulnerables activas</span>}
        <span className="espacio" />
        {usuario && (
          <span className="sesion">
            {usuario.email} ({usuario.rol}) <button onClick={salir}>Salir</button>
          </span>
        )}
      </header>

      <nav>
        {secciones.map((s) => (
          <button key={s} className={s === seccion ? 'activo' : ''} onClick={() => setSeccion(s)}>
            {s}
          </button>
        ))}
      </nav>

      <main>
        {seccion === 'Inicio' && (
          <>
            <Bienvenida />
            {!usuario && <Login onLogin={cargarUsuario} />}
          </>
        )}
        {seccion === 'Expediente' && usuario && <Expediente usuario={usuario} />}
        {seccion === 'Comentarios' && <Comentarios usuario={usuario} />}
        {seccion === 'Búsqueda' && usuario && <Busqueda />}
        {seccion === 'Reportes' && usuario?.rol === 'admin' && <Reportes />}
        {seccion === 'Laboratorio' && labVuln && <Laboratorio usuario={usuario} />}
      </main>
    </div>
  );
}
