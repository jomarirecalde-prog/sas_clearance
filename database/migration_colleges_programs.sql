-- One-time migration for databases created from an older schema.sql (before colleges/programs).
-- If you see "Duplicate column" or "Duplicate key name", those parts already ran; adjust manually.

CREATE TABLE IF NOT EXISTS colleges (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(40) NOT NULL UNIQUE,
    name VARCHAR(191) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS programs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    college_id BIGINT UNSIGNED NOT NULL,
    code VARCHAR(40) NOT NULL,
    name VARCHAR(191) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_program_code_per_college (college_id, code),
    CONSTRAINT fk_program_college FOREIGN KEY (college_id) REFERENCES colleges(id)
);

ALTER TABLE users ADD COLUMN college_id BIGINT UNSIGNED NULL AFTER role;
ALTER TABLE users ADD COLUMN program_id BIGINT UNSIGNED NULL AFTER college_id;

ALTER TABLE users ADD CONSTRAINT fk_user_college FOREIGN KEY (college_id) REFERENCES colleges(id);
ALTER TABLE users ADD CONSTRAINT fk_user_program FOREIGN KEY (program_id) REFERENCES programs(id);

-- Optional reference data (safe if rows already exist).
INSERT IGNORE INTO colleges (code, name, is_active) VALUES
('CAS', 'College of Arts and Sciences', 1),
('COE', 'College of Education', 1);

INSERT INTO programs (college_id, code, name, is_active)
SELECT c.id, 'BSIS', 'BS Information Systems', 1 FROM colleges c WHERE c.code = 'CAS' LIMIT 1
ON DUPLICATE KEY UPDATE name = VALUES(name);

INSERT INTO programs (college_id, code, name, is_active)
SELECT c.id, 'BSMATH', 'BS Mathematics', 1 FROM colleges c WHERE c.code = 'CAS' LIMIT 1
ON DUPLICATE KEY UPDATE name = VALUES(name);

INSERT INTO programs (college_id, code, name, is_active)
SELECT c.id, 'BEE', 'Bachelor of Elementary Education', 1 FROM colleges c WHERE c.code = 'COE' LIMIT 1
ON DUPLICATE KEY UPDATE name = VALUES(name);
