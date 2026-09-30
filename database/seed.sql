INSERT INTO offices (code, name, sequence_no, is_active) VALUES
('SSC', 'Supreme Student Council', 1, 1),
('DORM', 'Dormitory Coordinator', 2, 1),
('ACCT', 'Accounting', 3, 1),
('SOA', 'Students Organization Association', 4, 1),
('LIB', 'University/Campus Library', 5, 1),
('SAS', 'Student Affairs and Services', 6, 1),
('DEAN', 'College Dean / Campus Administrator', 7, 1);

UPDATE offices child
INNER JOIN offices parent ON parent.code = 'SAS'
SET child.parent_office_id = parent.id
WHERE child.code IN ('SSC', 'DORM', 'ACCT', 'SOA');

UPDATE offices child
INNER JOIN offices parent ON parent.code = 'DEAN'
SET child.parent_office_id = parent.id
WHERE child.code = 'LIB';

INSERT INTO semesters (academic_year, term, is_open)
VALUES ('2025-2026', '2nd', 1);

INSERT INTO colleges (code, name, is_active) VALUES
('CAS', 'College of Arts and Sciences', 1),
('COE', 'College of Education', 1);

INSERT INTO programs (college_id, code, name, is_active)
SELECT c.id, 'BSIS', 'BS Information Systems', 1 FROM colleges c WHERE c.code = 'CAS' LIMIT 1;

INSERT INTO programs (college_id, code, name, is_active)
SELECT c.id, 'BSMATH', 'BS Mathematics', 1 FROM colleges c WHERE c.code = 'CAS' LIMIT 1;

INSERT INTO programs (college_id, code, name, is_active)
SELECT c.id, 'BEE', 'Bachelor of Elementary Education', 1 FROM colleges c WHERE c.code = 'COE' LIMIT 1;

INSERT INTO users (student_no, first_name, last_name, email, password_hash, role, college_id, program_id, campus, year_level, is_active)
VALUES
(
    '2025-0001',
    'Juan',
    'Dela Cruz',
    'student@wpu.edu.ph',
    '$2y$10$9wPc.AGdPMU3xuJyOxpi9eKufGHhLA.ZAJn3O77P5cbcY2g5UROb2',
    'student',
    (SELECT id FROM colleges WHERE code = 'CAS' LIMIT 1),
    (SELECT p.id FROM programs p INNER JOIN colleges c ON c.id = p.college_id WHERE c.code = 'CAS' AND p.code = 'BSIS' LIMIT 1),
    'puerto_princesa',
    '2',
    1
),
(NULL, 'Ssc', 'Officer', 'ssc@wpu.edu.ph', '$2y$10$oaANWmHsp5/ycVpD78oz7OX0UjrTj14os0BmeOLBKcU73HG0DzbnO', 'signatory', NULL, NULL, NULL, NULL, 1),
(NULL, 'Library', 'Officer', 'library@wpu.edu.ph', '$2y$10$oaANWmHsp5/ycVpD78oz7OX0UjrTj14os0BmeOLBKcU73HG0DzbnO', 'signatory', NULL, NULL, NULL, NULL, 1),
(NULL, 'Sas', 'Officer', 'sas@wpu.edu.ph', '$2y$10$oaANWmHsp5/ycVpD78oz7OX0UjrTj14os0BmeOLBKcU73HG0DzbnO', 'signatory', NULL, NULL, NULL, NULL, 1),
(NULL, 'Dean', 'Officer', 'dean@wpu.edu.ph', '$2y$10$oaANWmHsp5/ycVpD78oz7OX0UjrTj14os0BmeOLBKcU73HG0DzbnO', 'signatory', NULL, NULL, NULL, NULL, 1),
(NULL, 'System', 'Admin', 'admin@wpu.edu.ph', '$2y$10$QGobjMI8Tegp/r5.7sCSNubQBXAxyaS8oPtkvjwtoRYwPdnIZ/7Wy', 'admin', NULL, NULL, NULL, NULL, 1);

-- Example requirement templates for current open semester.
INSERT INTO office_requirements (semester_id, office_id, title, description, is_required, is_active)
SELECT s.id, o.id, 'Org clearance', 'Student organization dues and status validated.', 1, 1
FROM semesters s
JOIN offices o ON o.code = 'SSC'
WHERE s.is_open = 1
LIMIT 1;

INSERT INTO office_requirements (semester_id, office_id, title, description, is_required, is_active)
SELECT s.id, o.id, 'No overdue fines', 'No unreturned books and unpaid library penalties.', 1, 1
FROM semesters s
JOIN offices o ON o.code = 'LIB'
WHERE s.is_open = 1
LIMIT 1;

INSERT INTO office_requirements (semester_id, office_id, title, description, is_required, is_active)
SELECT s.id, o.id, 'Exit interview', 'Exit interview completion record.', 1, 1
FROM semesters s
JOIN offices o ON o.code = 'SAS'
WHERE s.is_open = 1
LIMIT 1;

INSERT INTO office_requirements (semester_id, office_id, title, description, is_required, is_active)
SELECT s.id, o.id, 'Final grade compliance', 'All academic deliverables and grade-related obligations are complete.', 1, 1
FROM semesters s
JOIN offices o ON o.code = 'DEAN'
WHERE s.is_open = 1
LIMIT 1;

INSERT INTO office_signatories (office_id, user_id, semester_id)
SELECT o.id, u.id, s.id
FROM offices o
JOIN users u ON (
    (o.code = 'SSC' AND u.email = 'ssc@wpu.edu.ph') OR
    (o.code = 'LIB' AND u.email = 'library@wpu.edu.ph') OR
    (o.code = 'SAS' AND u.email = 'sas@wpu.edu.ph') OR
    (o.code = 'DEAN' AND u.email = 'dean@wpu.edu.ph')
)
JOIN semesters s ON s.is_open = 1;

-- Sample students: 3 pending, 2 fully approved (cleared). Dev password: Student!Dev26
INSERT INTO users (
    student_no, first_name, last_name, email, password_hash, role,
    college_id, program_id, campus, year_level,
    student_account_type, student_org_position, student_staying, is_active
)
VALUES
(
    '2025-0002',
    'Maria',
    'Santos',
    'maria.santos@wpu.edu.ph',
    '$2y$10$9wPc.AGdPMU3xuJyOxpi9eKufGHhLA.ZAJn3O77P5cbcY2g5UROb2',
    'student',
    (SELECT id FROM colleges WHERE code = 'CAS' LIMIT 1),
    (SELECT p.id FROM programs p INNER JOIN colleges c ON c.id = p.college_id WHERE c.code = 'CAS' AND p.code = 'BSIS' LIMIT 1),
    'canique',
    '1',
    'paying_tuition',
    'na',
    'commuter',
    1
),
(
    '2025-0003',
    'Pedro',
    'Reyes',
    'pedro.reyes@wpu.edu.ph',
    '$2y$10$9wPc.AGdPMU3xuJyOxpi9eKufGHhLA.ZAJn3O77P5cbcY2g5UROb2',
    'student',
    (SELECT id FROM colleges WHERE code = 'CAS' LIMIT 1),
    (SELECT p.id FROM programs p INNER JOIN colleges c ON c.id = p.college_id WHERE c.code = 'CAS' AND p.code = 'BSMATH' LIMIT 1),
    'quezon',
    '2',
    'paying_tuition',
    'na',
    'commuter',
    1
),
(
    '2025-0004',
    'Ana',
    'Cruz',
    'ana.cruz@wpu.edu.ph',
    '$2y$10$9wPc.AGdPMU3xuJyOxpi9eKufGHhLA.ZAJn3O77P5cbcY2g5UROb2',
    'student',
    (SELECT id FROM colleges WHERE code = 'COE' LIMIT 1),
    (SELECT p.id FROM programs p INNER JOIN colleges c ON c.id = p.college_id WHERE c.code = 'COE' AND p.code = 'BEE' LIMIT 1),
    'el_nido',
    '3',
    'paying_tuition',
    'secretary',
    'outside_dormitory',
    1
),
(
    '2025-0005',
    'Jose',
    'Ramos',
    'jose.ramos@wpu.edu.ph',
    '$2y$10$9wPc.AGdPMU3xuJyOxpi9eKufGHhLA.ZAJn3O77P5cbcY2g5UROb2',
    'student',
    (SELECT id FROM colleges WHERE code = 'CAS' LIMIT 1),
    (SELECT p.id FROM programs p INNER JOIN colleges c ON c.id = p.college_id WHERE c.code = 'CAS' AND p.code = 'BSIS' LIMIT 1),
    'rio_tuba',
    '4',
    'paying_tuition',
    'president',
    'commuter',
    1
),
(
    '2025-0006',
    'Liza',
    'Mendoza',
    'liza.mendoza@wpu.edu.ph',
    '$2y$10$9wPc.AGdPMU3xuJyOxpi9eKufGHhLA.ZAJn3O77P5cbcY2g5UROb2',
    'student',
    (SELECT id FROM colleges WHERE code = 'CAS' LIMIT 1),
    (SELECT p.id FROM programs p INNER JOIN colleges c ON c.id = p.college_id WHERE c.code = 'CAS' AND p.code = 'BSMATH' LIMIT 1),
    'busuanga',
    '4',
    'paying_tuition',
    'na',
    'wpu_dormitory',
    1
);

INSERT INTO student_semester_clearances (semester_id, student_id, overall_status)
SELECT s.id, u.id, 'pending'
FROM semesters s
JOIN users u ON u.email IN (
    'maria.santos@wpu.edu.ph',
    'pedro.reyes@wpu.edu.ph',
    'ana.cruz@wpu.edu.ph'
)
WHERE s.is_open = 1;

INSERT INTO student_semester_clearances (semester_id, student_id, overall_status)
SELECT s.id, u.id, 'cleared'
FROM semesters s
JOIN users u ON u.email IN (
    'jose.ramos@wpu.edu.ph',
    'liza.mendoza@wpu.edu.ph'
)
WHERE s.is_open = 1;

INSERT INTO student_clearances (semester_id, student_id, office_id, status, decided_by, decided_at)
SELECT s.id, u.id, o.id, 'cleared',
    CASE o.code
        WHEN 'SSC' THEN (SELECT id FROM users WHERE email = 'ssc@wpu.edu.ph' LIMIT 1)
        WHEN 'LIB' THEN (SELECT id FROM users WHERE email = 'library@wpu.edu.ph' LIMIT 1)
        WHEN 'SAS' THEN (SELECT id FROM users WHERE email = 'sas@wpu.edu.ph' LIMIT 1)
        WHEN 'DEAN' THEN (SELECT id FROM users WHERE email = 'dean@wpu.edu.ph' LIMIT 1)
        ELSE (SELECT id FROM users WHERE email = 'admin@wpu.edu.ph' LIMIT 1)
    END,
    NOW()
FROM semesters s
JOIN users u ON u.email = 'jose.ramos@wpu.edu.ph'
JOIN offices o ON o.code IN ('SSC', 'ACCT', 'SOA', 'LIB', 'SAS', 'DEAN')
WHERE s.is_open = 1;

INSERT INTO student_clearances (semester_id, student_id, office_id, status, decided_by, decided_at)
SELECT s.id, u.id, o.id, 'cleared',
    CASE o.code
        WHEN 'SSC' THEN (SELECT id FROM users WHERE email = 'ssc@wpu.edu.ph' LIMIT 1)
        WHEN 'LIB' THEN (SELECT id FROM users WHERE email = 'library@wpu.edu.ph' LIMIT 1)
        WHEN 'SAS' THEN (SELECT id FROM users WHERE email = 'sas@wpu.edu.ph' LIMIT 1)
        WHEN 'DEAN' THEN (SELECT id FROM users WHERE email = 'dean@wpu.edu.ph' LIMIT 1)
        ELSE (SELECT id FROM users WHERE email = 'admin@wpu.edu.ph' LIMIT 1)
    END,
    NOW()
FROM semesters s
JOIN users u ON u.email = 'liza.mendoza@wpu.edu.ph'
JOIN offices o ON o.code IN ('SSC', 'DORM', 'ACCT', 'SOA', 'LIB', 'SAS', 'DEAN')
WHERE s.is_open = 1;
