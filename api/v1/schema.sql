CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(254) NOT NULL UNIQUE,
    display_name VARCHAR(120) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS roles (
    id SMALLINT UNSIGNED PRIMARY KEY,
    name VARCHAR(120) NOT NULL UNIQUE
) ENGINE=InnoDB;
INSERT INTO roles (id, name) VALUES
 (1, 'Executive Director'), (2, 'Administrative Directors'),
 (3, 'Medical & Nursing Staff'), (4, 'Behavioral Support Services'),
 (5, 'Accessibility & Adaptive Services'), (6, 'Program Directors'),
 (7, 'Counselors & DSP''s'), (8, 'Facilities & Cabin Maintenance'),
 (9, 'Housekeeping'), (10, 'Catering & Dietary Support'),
 (11, 'Finance & Accounting'), (12, 'Guest')
ON DUPLICATE KEY UPDATE name = VALUES(name);
CREATE TABLE IF NOT EXISTS memberships (
    user_id BIGINT UNSIGNED NOT NULL,
    role_id SMALLINT UNSIGNED NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS api_clients (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    token VARCHAR(64) NOT NULL UNIQUE,
    secret_hash CHAR(64) NOT NULL,
    scopes JSON NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS sessions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    client_id BIGINT UNSIGNED NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX (user_id, expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (client_id) REFERENCES api_clients(id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS records (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    resource VARCHAR(64) NOT NULL,
    owner_id BIGINT UNSIGNED NULL,
    camper_id BIGINT UNSIGNED NULL,
    visibility VARCHAR(32) NOT NULL DEFAULT '',
    payload MEDIUMTEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX (resource, owner_id),
    INDEX (resource, camper_id),
    FOREIGN KEY (owner_id) REFERENCES users(id),
    FOREIGN KEY (camper_id) REFERENCES records(id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS counselor_assignments (
    user_id BIGINT UNSIGNED NOT NULL,
    camper_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (user_id, camper_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (camper_id) REFERENCES records(id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS record_links (
    record_id BIGINT UNSIGNED NOT NULL,
    field_name VARCHAR(64) NOT NULL,
    target_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (record_id, field_name),
    FOREIGN KEY (record_id) REFERENCES records(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES records(id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS activity_enrollments (
    activity_id BIGINT UNSIGNED NOT NULL,
    camper_id BIGINT UNSIGNED NOT NULL,
    record_id BIGINT UNSIGNED NOT NULL UNIQUE,
    PRIMARY KEY (activity_id, camper_id),
    FOREIGN KEY (activity_id) REFERENCES records(id),
    FOREIGN KEY (camper_id) REFERENCES records(id),
    FOREIGN KEY (record_id) REFERENCES records(id) ON DELETE CASCADE
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket CHAR(64) PRIMARY KEY,
    hits INT UNSIGNED NOT NULL DEFAULT 1,
    expires_at DATETIME NOT NULL,
    INDEX (expires_at)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor_id BIGINT UNSIGNED NULL,
    client_id BIGINT UNSIGNED NULL,
    event VARCHAR(64) NOT NULL,
    resource VARCHAR(64) NULL,
    record_id BIGINT UNSIGNED NULL,
    outcome VARCHAR(32) NOT NULL,
    request_id CHAR(32) NOT NULL,
    address_hash CHAR(64) NOT NULL,
    INDEX (occurred_at),
    INDEX (actor_id, occurred_at)
) ENGINE=InnoDB;
