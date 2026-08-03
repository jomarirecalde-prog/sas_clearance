-- Student residence / staying option on register-students
USE wpu_clearance;
ALTER TABLE users ADD COLUMN student_staying ENUM('wpu_dormitory', 'outside_dormitory', 'commuter') NULL AFTER student_org_position;
