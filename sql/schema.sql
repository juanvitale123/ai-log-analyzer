-- Ejecutar como root de MySQL:  sudo mysql < sql/schema.sql
-- Cambia la contraseña antes de ejecutarlo.

CREATE DATABASE IF NOT EXISTS loganalyzer CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'loganalyzer'@'localhost' IDENTIFIED BY 'CAMBIA_ESTA_CONTRASEÑA';
GRANT SELECT, INSERT ON loganalyzer.* TO 'loganalyzer'@'localhost';

-- Usuario de solo lectura para Grafana (fase 3)
CREATE USER IF NOT EXISTS 'grafana'@'%' IDENTIFIED BY 'CAMBIA_ESTA_CONTRASEÑA';
GRANT SELECT ON loganalyzer.* TO 'grafana'@'%';

USE loganalyzer;

CREATE TABLE IF NOT EXISTS incidents (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    server         VARCHAR(100) NOT NULL,
    source         VARCHAR(20)  NOT NULL,           -- ssh, nginx, mysql, sistema
    type           VARCHAR(40)  NOT NULL,           -- fuerza_bruta_ssh, servicio_caido...
    severity       ENUM('baja','media','alta','critica') NOT NULL,
    title          VARCHAR(150) NOT NULL,
    explanation    TEXT,
    recommendation TEXT,
    ip             VARCHAR(45),
    details        JSON,
    analyzed_by    ENUM('ia','reglas') NOT NULL,
    fingerprint    CHAR(16) NOT NULL,
    notified       TINYINT(1) NOT NULL DEFAULT 0,
    INDEX idx_created (created_at),
    INDEX idx_fingerprint (fingerprint, created_at)
);

FLUSH PRIVILEGES;
