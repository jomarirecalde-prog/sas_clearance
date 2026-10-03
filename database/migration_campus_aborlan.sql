-- Add Aborlan Main Campus to users.campus
USE wpu_clearance;
ALTER TABLE users MODIFY COLUMN campus ENUM(
    'puerto_princesa',
    'quezon',
    'rio_tuba',
    'el_nido',
    'canique',
    'busuanga',
    'aborlan'
) NULL;
