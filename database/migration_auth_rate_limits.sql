-- Authentication rate limiter (login, forgot-password, reset-password)
USE wpu_clearance;

CREATE TABLE IF NOT EXISTS auth_rate_limits (
    limiter_key CHAR(64) NOT NULL,
    action VARCHAR(40) NOT NULL,
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    window_started_at DATETIME NOT NULL,
    locked_until DATETIME NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (limiter_key),
    INDEX idx_auth_rate_limits_locked_until (locked_until)
) ENGINE=InnoDB;
