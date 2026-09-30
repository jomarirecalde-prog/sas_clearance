-- Development-only: rotate seeded demo passwords away from "password".
-- Do not run this against production data.

UPDATE users
SET password_hash = '$2y$10$9wPc.AGdPMU3xuJyOxpi9eKufGHhLA.ZAJn3O77P5cbcY2g5UROb2'
WHERE role = 'student'
  AND email IN (
    'student@wpu.edu.ph',
    'maria.santos@wpu.edu.ph',
    'pedro.reyes@wpu.edu.ph',
    'ana.cruz@wpu.edu.ph',
    'jose.ramos@wpu.edu.ph',
    'liza.mendoza@wpu.edu.ph'
  );

UPDATE users
SET password_hash = '$2y$10$oaANWmHsp5/ycVpD78oz7OX0UjrTj14os0BmeOLBKcU73HG0DzbnO'
WHERE role = 'signatory'
  AND email IN (
    'ssc@wpu.edu.ph',
    'library@wpu.edu.ph',
    'sas@wpu.edu.ph',
    'dean@wpu.edu.ph'
  );

UPDATE users
SET password_hash = '$2y$10$QGobjMI8Tegp/r5.7sCSNubQBXAxyaS8oPtkvjwtoRYwPdnIZ/7Wy'
WHERE role = 'admin'
  AND email = 'admin@wpu.edu.ph';
