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

INSERT INTO users (student_no, first_name, last_name, email, password_hash, role, college_id, program_id, year_level, is_active)
VALUES
(
    '2025-0001',
    'Juan',
    'Dela Cruz',
    'student@wpu.edu.ph',
    '$2y$10$7DLhUV/MEcDu2ZruV0zDpeYRMzXSAwHFmjyrZmkrqNAPGa2j.2qU.',
    'student',
    (SELECT id FROM colleges WHERE code = 'CAS' LIMIT 1),
    (SELECT p.id FROM programs p INNER JOIN colleges c ON c.id = p.college_id WHERE c.code = 'CAS' AND p.code = 'BSIS' LIMIT 1),
    '2',
    1
),
(NULL, 'Ssc', 'Officer', 'ssc@wpu.edu.ph', '$2y$10$7DLhUV/MEcDu2ZruV0zDpeYRMzXSAwHFmjyrZmkrqNAPGa2j.2qU.', 'signatory', NULL, NULL, NULL, 1),
(NULL, 'Library', 'Officer', 'library@wpu.edu.ph', '$2y$10$7DLhUV/MEcDu2ZruV0zDpeYRMzXSAwHFmjyrZmkrqNAPGa2j.2qU.', 'signatory', NULL, NULL, NULL, 1),
(NULL, 'Sas', 'Officer', 'sas@wpu.edu.ph', '$2y$10$7DLhUV/MEcDu2ZruV0zDpeYRMzXSAwHFmjyrZmkrqNAPGa2j.2qU.', 'signatory', NULL, NULL, NULL, 1),
(NULL, 'Dean', 'Officer', 'dean@wpu.edu.ph', '$2y$10$7DLhUV/MEcDu2ZruV0zDpeYRMzXSAwHFmjyrZmkrqNAPGa2j.2qU.', 'signatory', NULL, NULL, NULL, 1),
(NULL, 'System', 'Admin', 'admin@wpu.edu.ph', '$2y$10$7DLhUV/MEcDu2ZruV0zDpeYRMzXSAwHFmjyrZmkrqNAPGa2j.2qU.', 'admin', NULL, NULL, NULL, 1);

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
