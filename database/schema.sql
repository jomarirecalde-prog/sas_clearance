CREATE TABLE colleges (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(40) NOT NULL UNIQUE,
    name VARCHAR(191) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE programs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    college_id BIGINT UNSIGNED NOT NULL,
    code VARCHAR(40) NOT NULL,
    name VARCHAR(191) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_program_code_per_college (college_id, code),
    CONSTRAINT fk_program_college FOREIGN KEY (college_id) REFERENCES colleges(id)
);

CREATE TABLE users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    student_no VARCHAR(30) NULL UNIQUE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(191) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('student', 'signatory', 'admin') NOT NULL,
    college_id BIGINT UNSIGNED NULL,
    program_id BIGINT UNSIGNED NULL,
    campus ENUM('puerto_princesa', 'quezon', 'rio_tuba', 'el_nido', 'canique', 'busuanga', 'aborlan') NULL,
    year_level ENUM('1', '2', '3', '4', '5+') NULL,
    student_account_type ENUM('paying_tuition', 'not_paying_tuition') NULL,
    student_org_position ENUM('president', 'vice_president', 'treasurer', 'secretary', 'auditor', 'na') NULL,
    student_staying ENUM('wpu_dormitory', 'outside_dormitory', 'commuter') NULL,
    profile_photo_path VARCHAR(255) NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    registration_status ENUM('approved', 'pending', 'rejected') NOT NULL DEFAULT 'approved',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_user_college FOREIGN KEY (college_id) REFERENCES colleges(id),
    CONSTRAINT fk_user_program FOREIGN KEY (program_id) REFERENCES programs(id)
);

CREATE TABLE offices (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(40) NOT NULL UNIQUE,
    name VARCHAR(191) NOT NULL,
    sequence_no INT UNSIGNED NOT NULL,
    parent_office_id INT UNSIGNED NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    CONSTRAINT fk_office_parent FOREIGN KEY (parent_office_id) REFERENCES offices(id)
);

CREATE TABLE semesters (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    academic_year VARCHAR(20) NOT NULL,
    term ENUM('1st', '2nd', 'summer') NOT NULL,
    is_open TINYINT(1) NOT NULL DEFAULT 1,
    starts_at DATE NULL,
    ends_at DATE NULL,
    clearance_window_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE semester_deadline_notification_log (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    semester_id BIGINT UNSIGNED NOT NULL,
    notified_on DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_semester_notified_on (semester_id, notified_on),
    CONSTRAINT fk_sdln_semester FOREIGN KEY (semester_id) REFERENCES semesters(id) ON DELETE CASCADE
);

CREATE TABLE office_signatories (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    office_id INT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    semester_id BIGINT UNSIGNED NOT NULL,
    signature_path VARCHAR(255) NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_office_signatory_semester (office_id, user_id, semester_id),
    CONSTRAINT fk_signatory_office FOREIGN KEY (office_id) REFERENCES offices(id),
    CONSTRAINT fk_signatory_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_signatory_semester FOREIGN KEY (semester_id) REFERENCES semesters(id)
);

CREATE TABLE office_requirements (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    semester_id BIGINT UNSIGNED NOT NULL,
    office_id INT UNSIGNED NOT NULL,
    title VARCHAR(191) NOT NULL,
    description TEXT NULL,
    attachment_path VARCHAR(255) NULL,
    attachment_name VARCHAR(255) NULL,
    is_required TINYINT(1) NOT NULL DEFAULT 1,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_requirement_semester FOREIGN KEY (semester_id) REFERENCES semesters(id),
    CONSTRAINT fk_requirement_office FOREIGN KEY (office_id) REFERENCES offices(id)
);

CREATE TABLE student_office_requirements (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    semester_id BIGINT UNSIGNED NOT NULL,
    student_id BIGINT UNSIGNED NOT NULL,
    office_id INT UNSIGNED NOT NULL,
    requirement_text VARCHAR(255) NOT NULL,
    attachment_path VARCHAR(255) NULL,
    attachment_name VARCHAR(255) NULL,
    is_completed TINYINT(1) NOT NULL DEFAULT 0,
    created_by BIGINT UNSIGNED NULL,
    completed_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_sor_lookup (semester_id, student_id, office_id),
    CONSTRAINT fk_sor_semester FOREIGN KEY (semester_id) REFERENCES semesters(id),
    CONSTRAINT fk_sor_student FOREIGN KEY (student_id) REFERENCES users(id),
    CONSTRAINT fk_sor_office FOREIGN KEY (office_id) REFERENCES offices(id),
    CONSTRAINT fk_sor_creator FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE student_clearances (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    semester_id BIGINT UNSIGNED NOT NULL,
    student_id BIGINT UNSIGNED NOT NULL,
    office_id INT UNSIGNED NOT NULL,
    status ENUM('pending', 'for_review', 'cleared', 'rejected') NOT NULL DEFAULT 'pending',
    decided_by BIGINT UNSIGNED NULL,
    decided_at DATETIME NULL,
    rejection_reason TEXT NULL,
    digital_signature_path VARCHAR(255) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_student_office_semester (semester_id, student_id, office_id),
    CONSTRAINT fk_clearance_semester FOREIGN KEY (semester_id) REFERENCES semesters(id),
    CONSTRAINT fk_clearance_student FOREIGN KEY (student_id) REFERENCES users(id),
    CONSTRAINT fk_clearance_office FOREIGN KEY (office_id) REFERENCES offices(id),
    CONSTRAINT fk_clearance_decider FOREIGN KEY (decided_by) REFERENCES users(id)
);

CREATE TABLE student_semester_clearances (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    semester_id BIGINT UNSIGNED NOT NULL,
    student_id BIGINT UNSIGNED NOT NULL,
    overall_status ENUM('pending', 'for_review', 'cleared', 'rejected') NOT NULL DEFAULT 'pending',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_student_semester (semester_id, student_id),
    CONSTRAINT fk_ssc_semester FOREIGN KEY (semester_id) REFERENCES semesters(id),
    CONSTRAINT fk_ssc_student FOREIGN KEY (student_id) REFERENCES users(id)
);

CREATE TABLE signatory_signatures (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    semester_id BIGINT UNSIGNED NOT NULL,
    signatory_user_id BIGINT UNSIGNED NOT NULL,
    signature_file VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_signature_semester_signatory (semester_id, signatory_user_id),
    CONSTRAINT fk_signatory_sig_semester FOREIGN KEY (semester_id) REFERENCES semesters(id),
    CONSTRAINT fk_signatory_sig_user FOREIGN KEY (signatory_user_id) REFERENCES users(id)
);

CREATE TABLE requirement_submissions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    semester_id BIGINT UNSIGNED NOT NULL,
    student_id BIGINT UNSIGNED NOT NULL,
    office_requirement_id BIGINT UNSIGNED NOT NULL,
    file_path VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_size BIGINT UNSIGNED NOT NULL,
    review_status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
    reviewed_by BIGINT UNSIGNED NULL,
    reviewed_at DATETIME NULL,
    review_notes TEXT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_submission_semester FOREIGN KEY (semester_id) REFERENCES semesters(id),
    CONSTRAINT fk_submission_student FOREIGN KEY (student_id) REFERENCES users(id),
    CONSTRAINT fk_submission_requirement FOREIGN KEY (office_requirement_id) REFERENCES office_requirements(id),
    CONSTRAINT fk_submission_reviewer FOREIGN KEY (reviewed_by) REFERENCES users(id)
);

CREATE TABLE notifications (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    type VARCHAR(60) NOT NULL,
    title VARCHAR(191) NOT NULL,
    body TEXT NOT NULL,
    related_office_id INT UNSIGNED NULL,
    related_clearance_id BIGINT UNSIGNED NULL,
    is_read TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_notification_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_notification_office FOREIGN KEY (related_office_id) REFERENCES offices(id),
    CONSTRAINT fk_notification_clearance FOREIGN KEY (related_clearance_id) REFERENCES student_clearances(id)
);
CREATE INDEX idx_notifications_user_id_id ON notifications(user_id, id);

DROP TRIGGER IF EXISTS trg_notifications_fifo_after_insert;
CREATE TRIGGER trg_notifications_fifo_after_insert
AFTER INSERT ON notifications
FOR EACH ROW
BEGIN
    DELETE FROM notifications
    WHERE user_id = NEW.user_id
      AND id NOT IN (
          SELECT keep_id FROM (
              SELECT id AS keep_id
              FROM notifications
              WHERE user_id = NEW.user_id
              ORDER BY id DESC
              LIMIT 5
          ) keep_rows
      );
END;

CREATE TABLE clearance_message_threads (
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

CREATE TABLE clearance_messages (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    thread_id BIGINT UNSIGNED NOT NULL,
    sender_user_id BIGINT UNSIGNED NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_clearance_msg_thread_created (thread_id, id),
    CONSTRAINT fk_cm_thread FOREIGN KEY (thread_id) REFERENCES clearance_message_threads(id) ON DELETE CASCADE,
    CONSTRAINT fk_cm_sender FOREIGN KEY (sender_user_id) REFERENCES users(id)
);

CREATE TABLE clearance_message_thread_reads (
    thread_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    last_read_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (thread_id, user_id),
    CONSTRAINT fk_cmtr_thread FOREIGN KEY (thread_id) REFERENCES clearance_message_threads(id) ON DELETE CASCADE,
    CONSTRAINT fk_cmtr_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE auth_rate_limits (
    limiter_key CHAR(64) NOT NULL,
    action VARCHAR(40) NOT NULL,
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    window_started_at DATETIME NOT NULL,
    locked_until DATETIME NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (limiter_key),
    INDEX idx_auth_rate_limits_locked_until (locked_until)
) ENGINE=InnoDB;

CREATE TABLE password_resets (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    email VARCHAR(255) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_password_resets_user_id (user_id),
    UNIQUE KEY uniq_password_resets_token_hash (token_hash),
    CONSTRAINT fk_password_resets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
