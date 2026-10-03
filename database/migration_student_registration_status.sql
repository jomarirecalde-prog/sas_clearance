-- Student self-registration stays pending until an admin approves a valid Student ID.
USE wpu_clearance;
ALTER TABLE users
    ADD COLUMN registration_status ENUM('approved', 'pending', 'rejected') NOT NULL DEFAULT 'approved'
    AFTER is_active;
