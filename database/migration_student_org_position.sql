-- Student org. position (run once on existing databases).

ALTER TABLE users ADD COLUMN student_org_position ENUM('president', 'vice_president', 'treasurer', 'secretary', 'auditor', 'na') NULL AFTER student_account_type;

UPDATE users SET student_org_position = 'na' WHERE role = 'student' AND student_org_position IS NULL;
