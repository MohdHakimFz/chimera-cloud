-- PROJECT CHIMERA Phase 1 schema
-- INITIALIZATION ONLY: this script drops all 11 CHIMERA tables before recreating them.
-- Never rerun against an established production database without an explicit destructive-reset decision and verified backup.
-- MySQL 8.0+ / MariaDB 10.6+, utf8mb4, InnoDB

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS vulnerability_state_changes;
DROP TABLE IF EXISTS honeytoken_events;
DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS security_score_contributors;
DROP TABLE IF EXISTS security_sessions;
DROP TABLE IF EXISTS vulnerability_modules;
DROP TABLE IF EXISTS honeytokens;
DROP TABLE IF EXISTS decoy_endpoints;
DROP TABLE IF EXISTS user_activity;
DROP TABLE IF EXISTS documents;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(190) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin', 'security_admin') NOT NULL DEFAULT 'user',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    last_login_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_users_email (email),
    KEY idx_users_role_active (role, is_active)
) ENGINE=InnoDB;

CREATE TABLE documents (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    storage_name VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    checksum_sha256 CHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_documents_storage_name (storage_name),
    KEY idx_documents_owner_created (user_id, created_at),
    CONSTRAINT fk_documents_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE user_activity (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NULL,
    activity_type VARCHAR(64) NOT NULL,
    description VARCHAR(255) NOT NULL,
    metadata_json JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_activity_user_created (user_id, created_at),
    KEY idx_activity_type_created (activity_type, created_at),
    CONSTRAINT fk_activity_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE security_sessions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    session_identifier CHAR(36) NOT NULL,
    user_id BIGINT UNSIGNED NULL,
    source_hash CHAR(64) NULL,
    user_agent_hash CHAR(64) NULL,
    threat_score SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    classification ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'LOW',
    request_count INT UNSIGNED NOT NULL DEFAULT 0,
    first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_security_sessions_identifier (session_identifier),
    KEY idx_security_sessions_risk (classification, threat_score),
    KEY idx_security_sessions_last_seen (last_seen_at),
    CONSTRAINT fk_security_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE security_score_contributors (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    security_session_id BIGINT UNSIGNED NOT NULL,
    rule_code VARCHAR(64) NOT NULL,
    label VARCHAR(120) NOT NULL,
    risk_delta SMALLINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_score_session_created (security_session_id, created_at),
    CONSTRAINT fk_score_session FOREIGN KEY (security_session_id) REFERENCES security_sessions(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE decoy_endpoints (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    decoy_identifier VARCHAR(64) NOT NULL,
    path VARCHAR(190) NOT NULL,
    name VARCHAR(120) NOT NULL,
    type VARCHAR(64) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    risk_weight SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    response_mode VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_decoys_identifier (decoy_identifier),
    UNIQUE KEY uq_decoys_path (path),
    KEY idx_decoys_active (is_active)
) ENGINE=InnoDB;

CREATE TABLE honeytokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token_identifier VARCHAR(128) NOT NULL,
    description VARCHAR(255) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    risk_weight SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    triggered_at TIMESTAMP NULL,
    UNIQUE KEY uq_honeytokens_identifier (token_identifier),
    UNIQUE KEY uq_honeytokens_hash (token_hash),
    KEY idx_honeytokens_active (is_active)
) ENGINE=InnoDB;

CREATE TABLE vulnerability_modules (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    vulnerability_identifier VARCHAR(32) NOT NULL,
    name VARCHAR(160) NOT NULL,
    description TEXT NOT NULL,
    affected_component VARCHAR(190) NOT NULL,
    expected_attack_surface TEXT NOT NULL,
    learning_objective TEXT NOT NULL,
    expected_impact TEXT NOT NULL,
    mitigation TEXT NOT NULL,
    state ENUM('VULNERABLE', 'REMEDIATED') NOT NULL DEFAULT 'VULNERABLE',
    is_active TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_vulnerability_identifier (vulnerability_identifier),
    KEY idx_vulnerability_state (state, is_active)
) ENGINE=InnoDB;

CREATE TABLE security_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    security_session_id BIGINT UNSIGNED NULL,
    event_type VARCHAR(64) NOT NULL,
    source_safe_identifier CHAR(64) NULL,
    endpoint VARCHAR(255) NOT NULL,
    http_method VARCHAR(10) NOT NULL,
    user_agent_summary VARCHAR(255) NULL,
    severity ENUM('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    risk_delta SMALLINT NOT NULL DEFAULT 0,
    description VARCHAR(500) NOT NULL,
    metadata_json JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_events_session_created (security_session_id, created_at),
    KEY idx_events_type_created (event_type, created_at),
    KEY idx_events_severity_created (severity, created_at),
    CONSTRAINT fk_events_session FOREIGN KEY (security_session_id) REFERENCES security_sessions(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE honeytoken_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    honeytoken_id BIGINT UNSIGNED NOT NULL,
    security_event_id BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_honeytoken_security_event (honeytoken_id, security_event_id),
    CONSTRAINT fk_honeytoken_events_token FOREIGN KEY (honeytoken_id) REFERENCES honeytokens(id) ON DELETE RESTRICT,
    CONSTRAINT fk_honeytoken_events_event FOREIGN KEY (security_event_id) REFERENCES security_events(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE vulnerability_state_changes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    vulnerability_module_id BIGINT UNSIGNED NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    from_state ENUM('VULNERABLE', 'REMEDIATED') NOT NULL,
    to_state ENUM('VULNERABLE', 'REMEDIATED') NOT NULL,
    reason VARCHAR(500) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_state_changes_module_created (vulnerability_module_id, created_at),
    CONSTRAINT fk_state_changes_module FOREIGN KEY (vulnerability_module_id) REFERENCES vulnerability_modules(id) ON DELETE CASCADE,
    CONSTRAINT fk_state_changes_user FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

SET FOREIGN_KEY_CHECKS = 1;
