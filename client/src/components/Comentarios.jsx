import { useEffect, useState } from 'react';
import DOMPurify from 'dompurify';
import { api } from '../api.js';

/**
 * Comentarios SEGUROS (Fase I-C · XSS almacenado corregido).
 *  - Por defecto: {c.contenido} -> React lo inserta como TEXTO (escapa < > " ' &).
 *  - Opción "formato básico": DOMPurify con lista blanca mínima de etiquetas y SIN atributos;
 *    elimina <script>, manejadores on*, javascript:, etc. antes de insertar HTML.
 */
const PURIFY_CFG = { ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'u'], ALLOWED_ATTR: [] };

export default function Comentarios({ usuario }) {
  const [lista, setLista] = useState([]);
  const [texto, setTexto] = useState('');
  const [formato, setFormato] = useState(false);
  const [error, setError] = useState('');

  const cargar = () => api('/api/comentarios').then((r) => r.ok && setLista(r.data.comentarios));
  useEffect(() => { cargar(); }, []);

  async function publicar(e) {
    e.preventDefault();
    const r = await api('/api/comentarios', { method: 'POST', body: { contenido: texto } });
    if (!r.ok) return setError(r.data?.error ?? 'Error');
    setTexto('');
    setError('');
    return cargar();
  }

  return (
    <section>
      <h2>Comentarios</h2>
      {usuario && (
        <form onSubmit={publicar} className="formulario">
          <textarea value={texto} onChange={(e) => setTexto(e.target.value)} maxLength={1000} rows={3} required
            placeholder="Escriba un comentario (pruebe con HTML: se mostrará como texto)" />
          <button>Publicar</button>
        </form>
      )}
      {error && <p className="error">{error}</p>}
      <label className="opcion">
        <input type="checkbox" checked={formato} onChange={(e) => setFormato(e.target.checked)} />
        Permitir formato básico (negrita/cursiva) saneado con DOMPurify
      </label>
      <ul className="comentarios">
        {lista.map((c) => (
          <li key={c.id}>
            <strong>{c.autor}</strong>:{' '}
            {formato
              ? <span dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(c.contenido, PURIFY_CFG) }} />
              : <span>{c.contenido}</span>}
          </li>
        ))}
      </ul>
    </section>
  );
}
