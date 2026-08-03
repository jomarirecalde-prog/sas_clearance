-- Student account type: paying tuition vs not paying tuition (run once on existing databases).

ALTER TABLE users ADD COLUMN student_account_type ENUM('paying_tuition', 'not_paying_tuition') NULL AFTER year_level;

UPDATE users SET student_account_type = 'paying_tuition' WHERE role = 'student' AND student_account_type IS NULL;
