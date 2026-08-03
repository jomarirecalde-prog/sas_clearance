ALTER TABLE semesters
    ADD COLUMN clearance_window_active TINYINT(1) NOT NULL DEFAULT 1 AFTER ends_at;

CREATE TABLE IF NOT EXISTS semester_deadline_notification_log (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    semester_id BIGINT UNSIGNED NOT NULL,
    notified_on DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_semester_notified_on (semester_id, notified_on),
    CONSTRAINT fk_sdln_semester FOREIGN KEY (semester_id) REFERENCES semesters(id) ON DELETE CASCADE
);
