-- Offices required before SAS may approve/sign a student clearance.
INSERT INTO offices (code, name, sequence_no, is_active) VALUES
('DORM', 'Dormitory Coordinator', 2, 1),
('ACCT', 'Accounting', 3, 1),
('SOA', 'Students Organization Association', 4, 1)
ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    is_active = 1;

UPDATE offices SET sequence_no = 1 WHERE code = 'SSC';
UPDATE offices SET sequence_no = 2 WHERE code = 'DORM';
UPDATE offices SET sequence_no = 3 WHERE code = 'ACCT';
UPDATE offices SET sequence_no = 4 WHERE code = 'SOA';
UPDATE offices SET sequence_no = 5 WHERE code = 'LIB';
UPDATE offices SET sequence_no = 6 WHERE code = 'SAS';
UPDATE offices SET sequence_no = 7 WHERE code = 'DEAN';
