# Western Philippines University Clearance System

Web-based University Clearance System starter project for **Western Philippines University - College of Arts and Sciences**.

## What this includes

- Role model for `student`, `signatory`, and `admin`.
- Sequential office workflow:
  1. Supreme Student Council
  2. University/Campus Library
  3. Student Affairs and Services
  4. College Dean / Campus Administrator
- Customizable office requirements per semester.
- Requirement proof uploads and review lifecycle.
- Office sign-off with timestamp and optional digital signature.
- Student progress tracking and notifications.
- Final clearance data model ready for branded PDF generation.

## Suggested stack in this starter

- Backend: PHP 8+ (plain PHP, PDO)
- DB: MySQL 8+
- Frontend: server-rendered HTML + Bootstrap (mobile responsive)
- PDF: Dompdf (plug in once Composer is available)

## Project structure

- `database/schema.sql` - schema for users, semesters, offices, requirements, clearances, uploads, notifications.
- `database/seed.sql` - initial offices and statuses.
- `public/index.php` - lightweight API router.
- `src/Config/Database.php` - PDO connection.
- `src/Controllers/ClearanceController.php` - workflow and office actions.
- `src/Services/ClearanceService.php` - core business logic.
- `docs/IMPLEMENTATION_PLAN.md` - phased build plan and UI modules.

## Quick setup (XAMPP)

1. Create database:
   - `CREATE DATABASE wpu_clearance CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`
2. Import scripts:
   - `database/schema.sql`
   - `database/seed.sql`
3. Configure DB in `src/Config/Database.php`.
4. Ensure upload directory exists:
   - `storage/uploads`
5. Point Apache virtual host/document root to:
   - `c:/xampp/htdocs/CLEARANCE/public`
6. Use seeded demo credentials (all password: `Password123!`):
   - Student: `student@wpu.edu.ph`
   - Signatory (SSC): `ssc@wpu.edu.ph`
   - Signatory (Library): `library@wpu.edu.ph`
   - Signatory (SAS): `sas@wpu.edu.ph`
   - Signatory (Dean): `dean@wpu.edu.ph`
   - Admin: `admin@wpu.edu.ph`

## API starter routes

- `GET /health`
- `GET /students/{studentId}/clearance?semester_id={id}`
- `POST /students/{studentId}/requirements/{requirementId}/upload`
- `POST /offices/{officeId}/students/{studentId}/decision` (`for_review|cleared|rejected`)
- `POST /admin/semesters`
- `POST /admin/requirements`

## Web routes (implemented)

- `GET /login` and `POST /login`
- `POST /logout`
- `GET /dashboard` (role-based dashboard)
- `POST /student/upload` (student proof upload)
- `POST /signatory/decision` (signatory status decision)
- `POST /admin/semester`
- `POST /admin/requirement`
- `POST /admin/assign-signatory`

## Business rules implemented

- Office clearances are independent: any signatory may review and clear students without waiting for other offices.
- Requirement-level decisions roll up to office-level status:
  - any `rejected` => office `rejected`
  - all `approved` => office `cleared`
  - with submissions under review => `for_review`
  - otherwise => `pending`

## PDF output

The schema stores all fields needed for final printable form:

- student profile and course/year
- per-office status, signed timestamp, signatory name/signature
- semestral metadata (AY/Semester)

When your final form template is provided, map values into an HTML blade/template then render via Dompdf.

## Next implementation steps

1. Build authentication (session or token based).
2. Build student dashboard progress UI with red/yellow/green legend.
3. Build signatory queue UI filtered by assigned office.
4. Build admin semester/office/requirements management pages.
5. Add PDF generation endpoint matching your final clearance layout.
