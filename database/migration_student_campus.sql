-- Student campus (WPU sites) on register-students
USE wpu_clearance;
ALTER TABLE users ADD COLUMN campus ENUM(
    'puerto_princesa',
    'quezon',
    'rio_tuba',
    'el_nido',
    'canique',
    'busuanga',
    'aborlan'
) NULL AFTER program_id;

-- Fill campus on seeded demo students (safe if already set).
UPDATE users SET campus = 'puerto_princesa' WHERE role = 'student' AND email = 'student@wpu.edu.ph' AND campus IS NULL;
UPDATE users SET campus = 'canique' WHERE role = 'student' AND email = 'maria.santos@wpu.edu.ph' AND campus IS NULL;
UPDATE users SET campus = 'quezon' WHERE role = 'student' AND email = 'pedro.reyes@wpu.edu.ph' AND campus IS NULL;
UPDATE users SET campus = 'el_nido' WHERE role = 'student' AND email = 'ana.cruz@wpu.edu.ph' AND campus IS NULL;
UPDATE users SET campus = 'rio_tuba' WHERE role = 'student' AND email = 'jose.ramos@wpu.edu.ph' AND campus IS NULL;
UPDATE users SET campus = 'busuanga' WHERE role = 'student' AND email = 'liza.mendoza@wpu.edu.ph' AND campus IS NULL;
