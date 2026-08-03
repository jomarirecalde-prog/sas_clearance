-- Add year level for students (run once on existing databases).

ALTER TABLE users ADD COLUMN year_level ENUM('1', '2', '3', '4', '5+') NULL AFTER program_id;

UPDATE users SET year_level = '1' WHERE role = 'student' AND year_level IS NULL;
