-- 002: columna usada SOLO por la ruta vulnerable /vuln/estudiantes (Fase II-B).
-- Demuestra el almacenamiento del DPI en TEXTO PLANO frente a dpi_cifrado (AES-256-GCM).
-- Las rutas seguras nunca leen ni escriben esta columna.
ALTER TABLE estudiantes ADD COLUMN dpi_plano VARCHAR(20) NULL AFTER dpi_cifrado;
