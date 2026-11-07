-- 001: esquema inicial del portal de laboratorio (datos 100% ficticios)

CREATE TABLE IF NOT EXISTS estudiantes (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  carne         CHAR(9)      NOT NULL UNIQUE,          -- formato ####-####
  nombres       VARCHAR(60)  NOT NULL,
  apellidos     VARCHAR(60)  NOT NULL,
  email         VARCHAR(120) NOT NULL UNIQUE,
  carrera       VARCHAR(80)  NOT NULL,
  dpi_cifrado   VARCHAR(255) NULL,                     -- v1:iv:tag:ct (AES-256-GCM)
  creado_en     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS usuarios (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email          VARCHAR(120) NOT NULL UNIQUE,
  password_hash  VARCHAR(255) NOT NULL,
  password_algo  ENUM('argon2id','sha256') NOT NULL DEFAULT 'argon2id',
  rol            ENUM('estudiante','admin') NOT NULL DEFAULT 'estudiante',
  estudiante_id  INT UNSIGNED NULL,
  creado_en      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_usuario_estudiante FOREIGN KEY (estudiante_id) REFERENCES estudiantes(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS notas (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  estudiante_id  INT UNSIGNED NOT NULL,
  curso          VARCHAR(80)  NOT NULL,
  semestre       VARCHAR(10)  NOT NULL,
  nota           TINYINT UNSIGNED NOT NULL,
  actualizado_en TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT chk_nota_rango CHECK (nota BETWEEN 0 AND 100),
  CONSTRAINT fk_nota_estudiante FOREIGN KEY (estudiante_id) REFERENCES estudiantes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS comentarios (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  usuario_id  INT UNSIGNED NOT NULL,
  contenido   TEXT NOT NULL,
  creado_en   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_comentario_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
