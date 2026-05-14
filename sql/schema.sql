-- =============================================================
--  SCHEMA.SQL  –  Sistema de Login Seguro
--  Crea la base de datos, las tablas y los índices necesarios.
-- =============================================================

CREATE DATABASE IF NOT EXISTS login_seguro
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE login_seguro;

-- -------------------------------------------------------------
-- Tabla: users
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id           INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    email        VARCHAR(255)    NOT NULL,
    password_hash VARCHAR(255)   NOT NULL,
    created_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE INDEX uq_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -------------------------------------------------------------
-- Tabla: login_attempts
-- Registra cada intento fallido de inicio de sesión.
-- blocked_until: si no es NULL, el email está bloqueado hasta
--                esa fecha/hora.
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_attempts (
    id           INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    email        VARCHAR(255)    NOT NULL,
    attempted_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address   VARCHAR(45)     NOT NULL,
    blocked_until DATETIME       NULL DEFAULT NULL,
    PRIMARY KEY (id),
    INDEX idx_email_attempt (email, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
