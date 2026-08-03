# Implementation Plan

## Phase 1 - Core foundation

- Implement authentication (session login for student/signatory/admin).
- Add role-based middleware.
- Add student profile fields needed by your clearance form.
- Build initial admin setup screens:
  - Semester management
  - Requirement templates per office per semester
  - Signatory assignment per office

## Phase 2 - Clearance workflow UI

- Student dashboard:
  - Office cards with progress colors (`red`, `yellow`, `green`)
  - Requirement checklist and upload per requirement
  - Notifications panel
- Signatory dashboard:
  - Queue of students for assigned office
  - Open student details and uploaded proofs
  - Mark `for_review`, `cleared`, or `rejected` with reason
- Admin dashboard:
  - Reopen/reset student clearance
  - Semester analytics and office-based bottlenecks

## Phase 3 - Final semestral form and reports

- Build printable HTML template that mirrors your final DOCX layout.
- Map clearance data fields:
  - student identity and academic details
  - office statuses and timestamps
  - signatory names and digital signatures
- Render to PDF via Dompdf.
- Add reports:
  - Cleared vs not cleared
  - By office and by semester
  - Export CSV and PDF

## Security and validation checklist

- Validate uploads (mime type, size, extension allowlist).
- Store files outside public root or serve via signed access route.
- Use CSRF tokens for forms and strict session handling.
- Add audit logs for every status change.
- Restrict office decision endpoints to assigned signatories/admin.

## Optional enhancements

- Parallel workflow mode per semester (toggle in admin).
- SMS/email notifications.
- QR verification on generated clearance PDF.
- Student mobile PWA.
