import { useEffect, useState } from 'react';
import { api } from '../../api.js';

/**
 * ⚠️ VULNERABLE (XSS almacenado): inserta el contenido guardado como HTML crudo con
 * dangerouslySetInnerHTML. Un comentario como <img src=x onerror=alert(document.domain)>
 * se ejecuta en el navegador de CADA persona que abra esta vista.
 */
export default function VulnComentarios({ usuario }) {
  const [lista, setLista] = useState([]);
  const [texto, setTexto] = useState('<img src=x onerror="alert(\'XSS almacenado: \' + document.domain)">');

  const cargar = () => api('/vuln/comentarios').then((r) => r.ok && setLista(r.data.comentarios));
  useEffect(() => { cargar(); }, []);

  async function publicar(e) {
    e.preventDefault();
    await api('/vuln/comentarios', { method: 'POST', body: { contenido: texto } });
    cargar();
  }

  return (
    <div>
      <h3>XSS almacenado (vulnerable)</h3>
      {usuario && (
        <form onSubmit={publicar} className="formulario">
          <textarea value={texto} onChange={(e) => setTexto(e.target.value)} rows={3} />
          <button>Publicar en /vuln/comentarios</button>
        </form>
      )}
      <ul className="comentarios">
        {lista.map((c) => (
          <li key={c.id}>
            <strong>{c.autor}</strong>: <span dangerouslySetInnerHTML={{ __html: c.contenido }} />
          </li>
        ))}
      </ul>
    </div>
  );
}
