-- In-app clearance messaging: one private thread per (student, semester, chosen signatory).
-- Tables are auto-created / upgraded on app boot via ClearanceService.

CREATE TABLE IF NOT EXISTS clearance_message_threads (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    semester_id BIGINT UNSIGNED NOT NULL,
    student_id BIGINT UNSIGNED NOT NULL,
    signatory_user_id BIGINT UNSIGNED NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_clearance_msg_thread_recipient (semester_id, student_id, signatory_user_id),
    INDEX idx_clearance_msg_thread_sem (semester_id),
    INDEX idx_clearance_msg_thread_sig (signatory_user_id),
    CONSTRAINT fk_cmt_sem FOREIGN KEY (semester_id) REFERENCES semesters(id),
    CONSTRAINT fk_cmt_stu FOREIGN KEY (student_id) REFERENCES users(id),
    CONSTRAINT fk_cmt_sig FOREIGN KEY (signatory_user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS clearance_messages (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    thread_id BIGINT UNSIGNED NOT NULL,
    sender_user_id BIGINT UNSIGNED NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_clearance_msg_thread_created (thread_id, id),
    CONSTRAINT fk_cm_thread FOREIGN KEY (thread_id) REFERENCES clearance_message_threads(id) ON DELETE CASCADE,
    CONSTRAINT fk_cm_sender FOREIGN KEY (sender_user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS clearance_message_thread_reads (
    thread_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    last_read_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (thread_id, user_id),
    CONSTRAINT fk_cmtr_thread FOREIGN KEY (thread_id) REFERENCES clearance_message_threads(id) ON DELETE CASCADE,
    CONSTRAINT fk_cmtr_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
