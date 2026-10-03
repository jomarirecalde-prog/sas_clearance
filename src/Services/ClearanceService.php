<?php

declare(strict_types=1);

namespace App\Services;

use App\Security\Crypto;
use App\Security\PasswordHasher;
use App\Security\RateLimiter;
use App\Support\SignatureImage;
use DateTime;
use PDO;

final class ClearanceService
{
    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureUserProfilePhotoColumn();
        $this->ensureRequirementAttachmentColumns();
        $this->ensureSignatorySignatureTable();
        $this->ensurePasswordResetTable();
        $this->ensureClearanceMessagingTables();
        $this->migrateClearanceMessageThreadsAddRecipient();
        $this->ensureNotificationFifoGuard();
        $this->ensureSasPrerequisiteOffices();
        $this->ensureOfficeParentColumn();
        $this->ensureDefaultOfficeParentLinks();
        $this->ensureStudentOfficeRequirementsTable();
        $this->ensureStudentOfficeRequirementAttachmentColumns();
        $this->ensureSemesterDeadlineColumns();
        $this->ensureSemesterDeadlineNotificationLogTable();
        $this->ensureStudentRegistrationStatusColumn();
        RateLimiter::ensureSchema($this->pdo);
    }

    public function authenticate(string $email, string $password): ?array
    {
        $result = $this->attemptLogin($email, $password);

        return ($result['ok'] ?? false) && is_array($result['user'] ?? null) ? $result['user'] : null;
    }

    /**
     * Password is checked before any approval message, so a wrong password never reveals account status.
     *
     * @return array{ok:bool, user:?array, message:string, count_failure:bool}
     */
    public function attemptLogin(string $email, string $password): array
    {
        $invalid = [
            'ok' => false,
            'user' => null,
            'message' => 'Invalid credentials or inactive account.',
            'count_failure' => true,
        ];
        $email = strtolower(trim($email));
        $stmt = $this->pdo->prepare("
            SELECT id, first_name, last_name, email, role, password_hash, is_active, registration_status
            FROM users
            WHERE email = :email
            LIMIT 1
        ");
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch();
        if (!$user) {
            PasswordHasher::dummyVerify($password);

            return $invalid;
        }

        $hash = (string) $user['password_hash'];
        if (!PasswordHasher::verify($password, $hash)) {
            return $invalid;
        }

        if (PasswordHasher::needsRehash($hash)) {
            $this->upgradePasswordHash((int) $user['id'], $password);
        }

        $role = (string) ($user['role'] ?? '');
        $registrationStatus = (string) ($user['registration_status'] ?? 'approved');
        if ($role === 'student' && $registrationStatus === 'pending') {
            return [
                'ok' => false,
                'user' => null,
                'message' => 'Your registration is waiting for admin approval. You can sign in after your Student ID is approved.',
                'count_failure' => false,
            ];
        }
        if ($role === 'student' && $registrationStatus === 'rejected') {
            return [
                'ok' => false,
                'user' => null,
                'message' => 'Your registration was not approved. Contact the administrator if you need this reviewed again.',
                'count_failure' => false,
            ];
        }
        if ((int) ($user['is_active'] ?? 0) !== 1) {
            return $invalid;
        }

        unset($user['password_hash'], $user['registration_status']);

        return [
            'ok' => true,
            'user' => $user,
            'message' => '',
            'count_failure' => false,
        ];
    }

    private function upgradePasswordHash(int $userId, string $password): void
    {
        if ($userId <= 0) {
            return;
        }
        $update = $this->pdo->prepare('UPDATE users SET password_hash = :password_hash WHERE id = :id LIMIT 1');
        $update->execute([
            'password_hash' => PasswordHasher::hash($password),
            'id' => $userId,
        ]);
    }

    public function createPasswordResetToken(string $email, int $ttlMinutes = 30): ?string
    {
        $stmt = $this->pdo->prepare("
            SELECT id, email, is_active
            FROM users
            WHERE email = :email
            LIMIT 1
        ");
        $stmt->execute(['email' => trim($email)]);
        $user = $stmt->fetch();
        if (!$user || (int) ($user['is_active'] ?? 0) !== 1) {
            return null;
        }

        $token = bin2hex(random_bytes(32));
        $tokenHash = Crypto::hmac($token);
        $expiresAt = (new DateTime('+' . max(5, $ttlMinutes) . ' minutes'))->format('Y-m-d H:i:s');

        // Keep only one active token per user to simplify validation.
        $deactivateStmt = $this->pdo->prepare("
            UPDATE password_resets
            SET used_at = NOW()
            WHERE user_id = :user_id
              AND used_at IS NULL
              AND expires_at > NOW()
        ");
        $deactivateStmt->execute(['user_id' => (int) $user['id']]);

        $insertStmt = $this->pdo->prepare("
            INSERT INTO password_resets (user_id, email, token_hash, expires_at)
            VALUES (:user_id, :email, :token_hash, :expires_at)
        ");
        $insertStmt->execute([
            'user_id' => (int) $user['id'],
            'email' => (string) $user['email'],
            'token_hash' => $tokenHash,
            'expires_at' => $expiresAt,
        ]);

        return $token;
    }

    public function isPasswordResetTokenValid(string $token): bool
    {
        if (trim($token) === '') {
            return false;
        }
        $tokenHash = Crypto::hmac($token);
        $stmt = $this->pdo->prepare("
            SELECT id
            FROM password_resets
            WHERE token_hash = :token_hash
              AND used_at IS NULL
              AND expires_at > NOW()
            LIMIT 1
        ");
        $stmt->execute(['token_hash' => $tokenHash]);
        return (bool) $stmt->fetchColumn();
    }

    public function resetPasswordByToken(string $token, string $newPassword): array
    {
        if (strlen($newPassword) < 8) {
            return ['ok' => false, 'message' => 'New password must be at least 8 characters.'];
        }
        if (trim($token) === '') {
            return ['ok' => false, 'message' => 'Invalid or expired reset link.'];
        }

        $tokenHash = Crypto::hmac($token);
        $selectStmt = $this->pdo->prepare("
            SELECT id, user_id
            FROM password_resets
            WHERE token_hash = :token_hash
              AND used_at IS NULL
              AND expires_at > NOW()
            LIMIT 1
        ");
        $selectStmt->execute(['token_hash' => $tokenHash]);
        $resetRow = $selectStmt->fetch();
        if (!$resetRow) {
            return ['ok' => false, 'message' => 'Invalid or expired reset link.'];
        }

        $hash = PasswordHasher::hash($newPassword);
        $this->pdo->beginTransaction();
        try {
            $updateUserStmt = $this->pdo->prepare("
                UPDATE users
                SET password_hash = :password_hash
                WHERE id = :id
                LIMIT 1
            ");
            $updateUserStmt->execute([
                'password_hash' => $hash,
                'id' => (int) $resetRow['user_id'],
            ]);

            $consumeStmt = $this->pdo->prepare("
                UPDATE password_resets
                SET used_at = NOW()
                WHERE id = :id
                LIMIT 1
            ");
            $consumeStmt->execute(['id' => (int) $resetRow['id']]);
            $this->pdo->commit();
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            return ['ok' => false, 'message' => 'Could not reset password right now. Please try again.'];
        }

        return ['ok' => true, 'message' => 'Password reset successful. You can now sign in with your new password.'];
    }

    /**
     * Adds display_account_name and display_department for header / logout area.
     * Students: program and college; signatories: office for the semester; admins: Administration.
     */
    public function enrichUserForHeader(array $user, ?int $semesterId): array
    {
        $first = trim((string) ($user['first_name'] ?? ''));
        $last = trim((string) ($user['last_name'] ?? ''));
        $user['display_account_name'] = trim($first . ' ' . $last);
        if ($user['display_account_name'] === '') {
            $user['display_account_name'] = trim((string) ($user['email'] ?? '')) ?: 'Account';
        }

        $photoStmt = $this->pdo->prepare('SELECT profile_photo_path FROM users WHERE id = :id LIMIT 1');
        $photoStmt->execute(['id' => (int) ($user['id'] ?? 0)]);
        $photoPath = trim((string) ($photoStmt->fetchColumn() ?: ''));
        $user['profile_photo_path'] = $photoPath !== '' ? $photoPath : null;

        $role = (string) ($user['role'] ?? '');
        if ($role === 'admin') {
            $user['display_department'] = 'Administration';
        } elseif ($role === 'student') {
            $stmt = $this->pdo->prepare('
                SELECT col.name AS college_name, pr.name AS program_name, u.year_level, u.campus,
                       u.student_no, u.student_account_type, u.student_org_position, u.student_staying
                FROM users u
                LEFT JOIN colleges col ON col.id = u.college_id
                LEFT JOIN programs pr ON pr.id = u.program_id
                WHERE u.id = :id
                LIMIT 1
            ');
            $stmt->execute(['id' => (int) $user['id']]);
            $row = $stmt->fetch() ?: [];
            $user['student_no'] = trim((string) ($row['student_no'] ?? ''));
            $user['student_account_type'] = trim((string) ($row['student_account_type'] ?? ''));
            $user['student_org_position'] = trim((string) ($row['student_org_position'] ?? ''));
            $user['student_staying'] = trim((string) ($row['student_staying'] ?? ''));
            $user['campus'] = trim((string) ($row['campus'] ?? ''));
            $college = trim((string) ($row['college_name'] ?? ''));
            $program = trim((string) ($row['program_name'] ?? ''));
            $yl = trim((string) ($row['year_level'] ?? ''));
            $campusLabel = self::campusDisplayLabel($user['campus']);
            $ylSuffix = $yl !== '' ? ' · Yr ' . $yl : '';
            $campusSuffix = $campusLabel !== '' ? ' · ' . $campusLabel : '';
            if ($program !== '' && $college !== '') {
                $user['display_department'] = $program . ' · ' . $college . $ylSuffix . $campusSuffix;
            } elseif ($program !== '') {
                $user['display_department'] = $program . $ylSuffix . $campusSuffix;
            } elseif ($college !== '') {
                $user['display_department'] = $college . $ylSuffix . $campusSuffix;
            } else {
                $user['display_department'] = 'No college / program on file' . ($yl !== '' ? ' · Yr ' . $yl : '') . $campusSuffix;
            }
        } elseif ($role === 'signatory') {
            if ($semesterId !== null) {
                $office = $this->getSignatoryOffice((int) $user['id'], $semesterId);
                $user['display_department'] = $office ? (string) $office['name'] : 'No office assigned this semester';
            } else {
                $user['display_department'] = '—';
            }
        } else {
            $user['display_department'] = '—';
        }

        return $user;
    }

    public function getOpenSemester(): ?array
    {
        $stmt = $this->pdo->query("
            SELECT id, academic_year, term, ends_at, clearance_window_active
            FROM semesters
            WHERE is_open = 1
            ORDER BY id DESC
            LIMIT 1
        ");
        $semester = $stmt->fetch();
        return $semester ?: null;
    }

    public function listSemesters(): array
    {
        $stmt = $this->pdo->query("
            SELECT id, academic_year, term, is_open
            FROM semesters
            ORDER BY academic_year DESC,
                     FIELD(term, 'summer', '2nd', '1st') DESC,
                     id DESC
        ");
        $rows = $stmt->fetchAll();
        return is_array($rows) ? $rows : [];
    }

    public function actorCanViewStudentClearance(int $actorId, string $role, int $studentId, int $semesterId): bool
    {
        if ($actorId <= 0 || $studentId <= 0) {
            return false;
        }
        if ($role === 'admin') {
            return true;
        }
        if ($role === 'student') {
            return $actorId === $studentId;
        }
        if ($role === 'signatory') {
            $office = $this->getSignatoryOffice($actorId, $semesterId);
            if ($office === null) {
                return false;
            }

            return $this->canSignatoryAccessStudent($actorId, (int) $office['id'], $studentId, $semesterId);
        }

        return false;
    }

    /**
     * Object-level authorization for files under /storage/*.
     */
    public function userCanAccessStoredFile(array $user, string $relativePath, int $semesterId): bool
    {
        $role = (string) ($user['role'] ?? '');
        $userId = (int) ($user['id'] ?? 0);
        $relativePath = ltrim(str_replace('\\', '/', $relativePath), '/');
        if ($userId <= 0 || $relativePath === '') {
            return false;
        }

        if (str_starts_with($relativePath, 'storage/requirement-attachments/')) {
            if ($this->pathExistsInTable('office_requirements', 'attachment_path', $relativePath)) {
                return in_array($role, ['admin', 'signatory', 'student'], true);
            }
            $studentId = $this->fetchIntByPath(
                'SELECT student_id FROM student_office_requirements WHERE attachment_path = :path LIMIT 1',
                $relativePath
            );
            if ($studentId === null) {
                return false;
            }

            return $this->actorCanViewStudentClearance($userId, $role, $studentId, $semesterId);
        }

        if (str_starts_with($relativePath, 'storage/uploads/')) {
            $studentId = $this->fetchIntByPath(
                'SELECT student_id FROM requirement_submissions WHERE file_path = :path LIMIT 1',
                $relativePath
            );
            if ($studentId === null) {
                return false;
            }

            return $this->actorCanViewStudentClearance($userId, $role, $studentId, $semesterId);
        }

        if (str_starts_with($relativePath, 'storage/signatory-signatures/')) {
            if ($role === 'admin') {
                return $this->pathExistsInTable('signatory_signatures', 'signature_file', $relativePath)
                    || $this->pathExistsInTable('student_clearances', 'digital_signature_path', $relativePath);
            }
            if ($role === 'signatory') {
                $ownerId = $this->fetchIntByPath(
                    'SELECT signatory_user_id FROM signatory_signatures WHERE signature_file = :path LIMIT 1',
                    $relativePath
                );

                return $ownerId === $userId;
            }

            return false;
        }

        if (str_starts_with($relativePath, 'storage/profile-photos/')) {
            $ownerId = $this->fetchIntByPath(
                'SELECT id FROM users WHERE profile_photo_path = :path LIMIT 1',
                $relativePath
            );
            if ($ownerId === null) {
                return false;
            }

            return $role === 'admin' || $ownerId === $userId;
        }

        return false;
    }

    private function fetchIntByPath(string $sql, string $relativePath): ?int
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(['path' => $relativePath]);
        $value = $stmt->fetchColumn();
        if ($value === false || $value === null) {
            return null;
        }

        return (int) $value;
    }

    private function pathExistsInTable(string $table, string $column, string $relativePath): bool
    {
        $allowed = [
            'office_requirements' => 'attachment_path',
            'student_office_requirements' => 'attachment_path',
            'signatory_signatures' => 'signature_file',
            'student_clearances' => 'digital_signature_path',
            'requirement_submissions' => 'file_path',
            'users' => 'profile_photo_path',
        ];
        if (($allowed[$table] ?? null) !== $column) {
            return false;
        }
        $stmt = $this->pdo->prepare(
            "SELECT 1 FROM {$table} WHERE {$column} = :path LIMIT 1"
        );
        $stmt->execute(['path' => $relativePath]);

        return (bool) $stmt->fetchColumn();
    }

    public function getStudentClearanceOverview(int $studentId, int $semesterId): array
    {
        $sql = "
            SELECT
                o.id AS office_id,
                o.code AS office_code,
                o.name AS office_name,
                o.sequence_no,
                o.parent_office_id,
                p.code AS parent_office_code,
                COALESCE(sc.status, 'pending') AS status,
                sc.decided_at,
                sc.rejection_reason
            FROM offices o
            LEFT JOIN offices p ON p.id = o.parent_office_id
            LEFT JOIN student_clearances sc
                ON sc.office_id = o.id
                AND sc.student_id = :student_id
                AND sc.semester_id = :semester_id
            WHERE o.is_active = 1
            ORDER BY o.sequence_no ASC
        ";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            'student_id' => $studentId,
            'semester_id' => $semesterId,
        ]);

        $rows = $stmt->fetchAll();
        foreach ($rows as &$row) {
            $row['color'] = $this->statusToColor($row['status']);
        }
        unset($row);

        return $this->filterStudentDashboardOffices($rows, $studentId);
    }

    public function getStudentRequirementsByOffice(int $studentId, int $semesterId): array
    {
        $sql = "
            SELECT
                o.id AS office_id,
                o.code AS office_code,
                o.name AS office_name,
                o.sequence_no,
                r.id AS requirement_id,
                r.title,
                r.description,
                r.attachment_path AS requirement_attachment_path,
                r.attachment_name AS requirement_attachment_name,
                rs.review_status,
                rs.review_notes,
                rs.file_path,
                rs.original_filename,
                rs.uploaded_at
            FROM offices o
            JOIN office_requirements r
                ON r.office_id = o.id
               AND r.semester_id = :semester_id
               AND r.is_active = 1
            LEFT JOIN (
                SELECT t1.*
                FROM requirement_submissions t1
                INNER JOIN (
                    SELECT office_requirement_id, MAX(id) AS max_id
                    FROM requirement_submissions
                    WHERE student_id = :student_id_1
                      AND semester_id = :semester_id_1
                    GROUP BY office_requirement_id
                ) t2 ON t1.id = t2.max_id
            ) rs ON rs.office_requirement_id = r.id
            ORDER BY o.sequence_no ASC, r.id ASC
        ";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            'semester_id' => $semesterId,
            'student_id_1' => $studentId,
            'semester_id_1' => $semesterId,
        ]);

        $rows = $stmt->fetchAll();
        $grouped = [];
        foreach ($rows as $row) {
            $officeId = (int) $row['office_id'];
            if (!isset($grouped[$officeId])) {
                $grouped[$officeId] = [
                    'office_id' => $officeId,
                    'office_code' => $row['office_code'],
                    'office_name' => $row['office_name'],
                    'sequence_no' => (int) $row['sequence_no'],
                    'unlocked' => $this->isOfficeUnlocked($officeId, $studentId, $semesterId),
                    'requirements' => [],
                ];
            }
            $grouped[$officeId]['requirements'][] = [
                'requirement_id' => (int) $row['requirement_id'],
                'title' => $row['title'],
                'description' => $row['description'],
                'requirement_attachment_path' => $row['requirement_attachment_path'],
                'requirement_attachment_name' => $row['requirement_attachment_name'],
                'review_status' => $row['review_status'] ?? 'pending',
                'review_notes' => $row['review_notes'],
                'file_path' => $row['file_path'],
                'original_filename' => $row['original_filename'],
                'uploaded_at' => $row['uploaded_at'],
                'is_individual' => false,
            ];
        }

        if ($this->tableExists('student_office_requirements')) {
            $attachedStmt = $this->pdo->prepare("
                SELECT office_id, id, requirement_text, attachment_path, attachment_name, is_completed, completed_at
                FROM student_office_requirements
                WHERE semester_id = :semester_id
                  AND student_id = :student_id
                ORDER BY id ASC
            ");
            $attachedStmt->execute([
                'semester_id' => $semesterId,
                'student_id' => $studentId,
            ]);
            foreach ($attachedStmt->fetchAll() as $attachedRow) {
                $officeId = (int) $attachedRow['office_id'];
                if (!isset($grouped[$officeId])) {
                    continue;
                }
                $isCompleted = (int) ($attachedRow['is_completed'] ?? 0) === 1;
                $grouped[$officeId]['requirements'][] = [
                    'requirement_id' => (int) $attachedRow['id'],
                    'title' => (string) $attachedRow['requirement_text'],
                    'description' => 'Assigned specifically to you by this office.',
                    'requirement_attachment_path' => $attachedRow['attachment_path'] ?? null,
                    'requirement_attachment_name' => $attachedRow['attachment_name'] ?? null,
                    'review_status' => $isCompleted ? 'approved' : 'pending',
                    'review_notes' => null,
                    'file_path' => null,
                    'original_filename' => null,
                    'uploaded_at' => $attachedRow['completed_at'] ?? null,
                    'is_individual' => true,
                ];
            }
        }

        $groups = array_values($grouped);
        $groups = $this->filterStudentDashboardRequirementGroups($groups, $studentId);

        return $groups;
    }

    public function uploadRequirementProof(
        int $studentId,
        int $semesterId,
        int $requirementId,
        array $file
    ): array {
        $stmt = $this->pdo->prepare("
            SELECT office_id
            FROM office_requirements
            WHERE id = :id AND semester_id = :semester_id AND is_active = 1
            LIMIT 1
        ");
        $stmt->execute(['id' => $requirementId, 'semester_id' => $semesterId]);
        $officeId = (int) $stmt->fetchColumn();
        if ($officeId <= 0) {
            return ['ok' => false, 'message' => 'Requirement not found for this semester.'];
        }
        if (!$this->isClearanceWindowOpen($semesterId)) {
            return ['ok' => false, 'message' => 'The clearance completion window is closed. Uploads are not allowed right now.'];
        }
        if ($this->isAccountingOfficeId($officeId) && !$this->studentRequiresAccountingClearance($studentId)) {
            return ['ok' => false, 'message' => 'Accounting clearance does not apply to your student account type.'];
        }
        if ($this->isDormitoryOfficeId($officeId) && !$this->studentRequiresDormitoryClearance($studentId)) {
            return ['ok' => false, 'message' => 'Dormitory clearance applies only to students staying in a WPU dormitory.'];
        }
        if (!$this->isOfficeUnlocked($officeId, $studentId, $semesterId)) {
            return ['ok' => false, 'message' => 'Office is locked until previous office is cleared.'];
        }

        if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            return ['ok' => false, 'message' => 'Upload failed.'];
        }

        $allowed = [
            'application/pdf',
            'image/jpeg',
            'image/png',
            'image/webp',
        ];
        $mime = mime_content_type((string) $file['tmp_name']) ?: '';
        if (!in_array($mime, $allowed, true)) {
            return ['ok' => false, 'message' => 'Invalid file type.'];
        }

        $maxSize = 5 * 1024 * 1024;
        $size = (int) ($file['size'] ?? 0);
        if ($size <= 0 || $size > $maxSize) {
            return ['ok' => false, 'message' => 'File must be <= 5MB.'];
        }

        $storageDir = dirname(__DIR__, 2) . '/storage/uploads';
        if (!is_dir($storageDir)) {
            mkdir($storageDir, 0775, true);
        }

        $originalName = (string) ($file['name'] ?? 'proof');
        $ext = pathinfo($originalName, PATHINFO_EXTENSION);
        $safeName = sprintf(
            'proof_%d_%d_%d_%s.%s',
            $studentId,
            $semesterId,
            $requirementId,
            (new DateTime())->format('YmdHis'),
            preg_replace('/[^a-zA-Z0-9]/', '', $ext) ?: 'bin'
        );
        $targetAbsolute = $storageDir . '/' . $safeName;
        if (!move_uploaded_file((string) $file['tmp_name'], $targetAbsolute)) {
            return ['ok' => false, 'message' => 'Could not store uploaded file.'];
        }

        $relativePath = 'storage/uploads/' . $safeName;
        $insert = $this->pdo->prepare("
            INSERT INTO requirement_submissions
                (semester_id, student_id, office_requirement_id, file_path, original_filename, mime_type, file_size)
            VALUES
                (:semester_id, :student_id, :requirement_id, :file_path, :original_filename, :mime_type, :file_size)
        ");
        $insert->execute([
            'semester_id' => $semesterId,
            'student_id' => $studentId,
            'requirement_id' => $requirementId,
            'file_path' => $relativePath,
            'original_filename' => $originalName,
            'mime_type' => $mime,
            'file_size' => $size,
        ]);

        $this->upsertOfficeStatus($semesterId, $studentId, $officeId, 'for_review');
        $this->syncOverallStatus($studentId, $semesterId);
        return ['ok' => true, 'message' => 'Proof uploaded successfully.'];
    }

    public function decideOfficeClearance(
        int $officeId,
        int $studentId,
        int $semesterId,
        string $status,
        int $signatoryUserId,
        ?string $reason
    ): array {
        $status = strtolower($status);
        if (!in_array($status, ['for_review', 'cleared', 'rejected'], true)) {
            return ['ok' => false, 'message' => 'Invalid status.'];
        }
        if (!$this->isClearanceWindowOpen($semesterId)) {
            return ['ok' => false, 'message' => 'The clearance completion window is closed. Decisions cannot be recorded right now.'];
        }

        if (!$this->isAssignedSignatory($signatoryUserId, $officeId, $semesterId)) {
            return ['ok' => false, 'message' => 'Signatory is not assigned to this office for this semester.'];
        }
        if (!$this->canSignatoryAccessStudent($signatoryUserId, $officeId, $studentId, $semesterId)) {
            return ['ok' => false, 'message' => 'You cannot sign this student because they are outside your assigned college.'];
        }
        if ($this->isAccountingOfficeId($officeId) && !$this->studentRequiresAccountingClearance($studentId)) {
            return ['ok' => false, 'message' => 'Accounting clearance does not apply to this student account type.'];
        }
        if ($this->isDormitoryOfficeId($officeId) && !$this->studentRequiresDormitoryClearance($studentId)) {
            return ['ok' => false, 'message' => 'Dormitory clearance applies only to students staying in a WPU dormitory.'];
        }

        if (!$this->isOfficeUnlocked($officeId, $studentId, $semesterId)) {
            return ['ok' => false, 'message' => 'Previous office has not been cleared yet.'];
        }

        if ($status === 'cleared' && !$this->hasCompletedAllOfficeRequirements($officeId, $studentId, $semesterId)) {
            return ['ok' => false, 'message' => 'Cannot approve yet. Student must upload all required items first.'];
        }
        if ($status === 'cleared' && !$this->hasCompletedAllStudentAttachedRequirements($officeId, $studentId, $semesterId)) {
            return ['ok' => false, 'message' => 'Cannot approve yet. All individual requirements for this student must be marked complete first.'];
        }
        if ($status === 'cleared' && $this->isSasOfficeId($officeId) && !$this->studentMeetsSasSignaturePrerequisites($studentId, $semesterId)) {
            $unitLabels = $this->getSasPrerequisiteOfficeLabels();
            $unitsText = $unitLabels !== [] ? implode(', ', $unitLabels) : 'all units under Student Affairs and Services';

            return [
                'ok' => false,
                'message' => 'Cannot approve yet. Student must be cleared by ' . $unitsText . ', and the student account must be active.',
            ];
        }
        if ($status === 'cleared' && $this->isDeanOfficeId($officeId) && !$this->studentMeetsDeanSignaturePrerequisites($studentId, $semesterId)) {
            $unitLabels = $this->getDeanPrerequisiteOfficeLabels();
            $unitsText = $unitLabels !== [] ? implode(', ', $unitLabels) : 'all units under College Dean / Campus Administrator';

            return [
                'ok' => false,
                'message' => 'Cannot approve yet. Student must be cleared by ' . $unitsText . ', and the student account must be active.',
            ];
        }
        $digitalSignaturePath = null;
        if ($status === 'cleared' && $this->officeRequiresSignatorySignature($officeId)) {
            $digitalSignaturePath = $this->getSignatorySignaturePath($signatoryUserId, $semesterId);
            if ($digitalSignaturePath === null) {
                return ['ok' => false, 'message' => 'Please upload your e-signature first before clearing students.'];
            }
        }

        $sql = "
            INSERT INTO student_clearances
                (semester_id, student_id, office_id, status, decided_by, decided_at, rejection_reason, digital_signature_path)
            VALUES
                (:semester_id, :student_id, :office_id, :status, :decided_by, NOW(), :reason, :digital_signature_path)
            ON DUPLICATE KEY UPDATE
                status = VALUES(status),
                decided_by = VALUES(decided_by),
                decided_at = VALUES(decided_at),
                rejection_reason = VALUES(rejection_reason),
                digital_signature_path = VALUES(digital_signature_path)
        ";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            'semester_id' => $semesterId,
            'student_id' => $studentId,
            'office_id' => $officeId,
            'status' => $status,
            'decided_by' => $signatoryUserId,
            'reason' => $reason,
            'digital_signature_path' => $digitalSignaturePath,
        ]);

        $officeName = $this->getOfficeNameById($officeId) ?? ('Office #' . $officeId);
        $notificationBody = "Your status for {$officeName} is now {$status}.";
        if ($reason !== null && trim($reason) !== '') {
            $notificationBody .= ' Reason: ' . trim($reason);
        }

        $this->createNotification(
            $studentId,
            'clearance_status',
            'Clearance status updated',
            $notificationBody,
            $officeId
        );
        $this->syncOverallStatus($studentId, $semesterId);
        if ($status === 'cleared') {
            $this->primeNextOfficeStep($officeId, $studentId, $semesterId);
        }

        return ['ok' => true, 'message' => 'Office decision saved.'];
    }

    public function getOfficeRequirementsForOffice(int $semesterId, int $officeId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT id, title, description, is_required, attachment_path, attachment_name
            FROM office_requirements
            WHERE semester_id = :semester_id
              AND office_id = :office_id
              AND is_active = 1
            ORDER BY id DESC
        ");
        $stmt->execute([
            'semester_id' => $semesterId,
            'office_id' => $officeId,
        ]);
        return $stmt->fetchAll();
    }

    /**
     * @return list<array{id:int, requirement_text:string, attachment_path:?string, attachment_name:?string, is_completed:bool, completed_at:?string}>
     */
    public function getStudentAttachedRequirements(int $studentId, int $officeId, int $semesterId): array
    {
        if (!$this->tableExists('student_office_requirements') || $studentId <= 0 || $officeId <= 0) {
            return [];
        }
        $stmt = $this->pdo->prepare("
            SELECT id, requirement_text, attachment_path, attachment_name, is_completed, completed_at
            FROM student_office_requirements
            WHERE semester_id = :semester_id
              AND student_id = :student_id
              AND office_id = :office_id
            ORDER BY id ASC
        ");
        $stmt->execute([
            'semester_id' => $semesterId,
            'student_id' => $studentId,
            'office_id' => $officeId,
        ]);
        $rows = $stmt->fetchAll();
        foreach ($rows as &$row) {
            $row['id'] = (int) ($row['id'] ?? 0);
            $row['requirement_text'] = (string) ($row['requirement_text'] ?? '');
            $row['attachment_path'] = isset($row['attachment_path']) && trim((string) $row['attachment_path']) !== ''
                ? (string) $row['attachment_path']
                : null;
            $row['attachment_name'] = isset($row['attachment_name']) && trim((string) $row['attachment_name']) !== ''
                ? (string) $row['attachment_name']
                : null;
            $row['is_completed'] = (int) ($row['is_completed'] ?? 0) === 1;
            $row['completed_at'] = isset($row['completed_at']) ? (string) $row['completed_at'] : null;
        }
        unset($row);

        return $rows;
    }

    /**
     * @param list<int> $studentIds
     * @return array<int, list<array{id:int, requirement_text:string, attachment_path:?string, attachment_name:?string, is_completed:bool, completed_at:?string}>>
     */
    public function getStudentAttachedRequirementsMap(int $officeId, int $semesterId, array $studentIds): array
    {
        $map = [];
        foreach ($studentIds as $studentId) {
            $map[$studentId] = [];
        }
        if (!$this->tableExists('student_office_requirements') || $officeId <= 0 || $studentIds === []) {
            return $map;
        }

        $placeholders = [];
        $bindings = [
            'semester_id' => $semesterId,
            'office_id' => $officeId,
        ];
        foreach ($studentIds as $idx => $studentId) {
            $ph = 'sid_' . $idx;
            $placeholders[] = ':' . $ph;
            $bindings[$ph] = $studentId;
        }

        $sql = '
            SELECT student_id, id, requirement_text, attachment_path, attachment_name, is_completed, completed_at
            FROM student_office_requirements
            WHERE semester_id = :semester_id
              AND office_id = :office_id
              AND student_id IN (' . implode(',', $placeholders) . ')
            ORDER BY id ASC
        ';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($bindings);
        foreach ($stmt->fetchAll() as $row) {
            $sid = (int) ($row['student_id'] ?? 0);
            if (!isset($map[$sid])) {
                continue;
            }
            $map[$sid][] = [
                'id' => (int) ($row['id'] ?? 0),
                'requirement_text' => (string) ($row['requirement_text'] ?? ''),
                'attachment_path' => isset($row['attachment_path']) && trim((string) $row['attachment_path']) !== ''
                    ? (string) $row['attachment_path']
                    : null,
                'attachment_name' => isset($row['attachment_name']) && trim((string) $row['attachment_name']) !== ''
                    ? (string) $row['attachment_name']
                    : null,
                'is_completed' => (int) ($row['is_completed'] ?? 0) === 1,
                'completed_at' => isset($row['completed_at']) ? (string) $row['completed_at'] : null,
            ];
        }

        return $map;
    }

    public function addStudentAttachedRequirements(
        int $studentId,
        int $officeId,
        int $semesterId,
        string $requirementsText,
        int $createdBy,
        ?array $attachmentFile = null
    ): array {
        if (!$this->tableExists('student_office_requirements')) {
            return ['ok' => false, 'message' => 'Individual requirements are not available.'];
        }
        if ($studentId <= 0 || $officeId <= 0) {
            return ['ok' => false, 'message' => 'Invalid student or office.'];
        }
        if (!$this->isAssignedSignatory($createdBy, $officeId, $semesterId)) {
            return ['ok' => false, 'message' => 'You are not assigned to this office for this semester.'];
        }
        if (!$this->canSignatoryAccessStudent($createdBy, $officeId, $studentId, $semesterId)) {
            return ['ok' => false, 'message' => 'You cannot manage requirements for this student.'];
        }

        $lines = preg_split('/\R+/', $requirementsText) ?: [];
        $items = [];
        foreach ($lines as $line) {
            $text = trim($line);
            if ($text !== '') {
                $items[] = $text;
            }
        }
        if ($items === []) {
            return ['ok' => false, 'message' => 'Enter at least one requirement.'];
        }

        $attachment = $this->storeRequirementAttachment($attachmentFile, $officeId, $semesterId);
        if ($attachment['ok'] === false) {
            return $attachment;
        }

        $stmt = $this->pdo->prepare("
            INSERT INTO student_office_requirements (
                semester_id, student_id, office_id, requirement_text, attachment_path, attachment_name, is_completed, created_by
            )
            VALUES (:semester_id, :student_id, :office_id, :requirement_text, :attachment_path, :attachment_name, 0, :created_by)
        ");
        foreach ($items as $text) {
            $stmt->execute([
                'semester_id' => $semesterId,
                'student_id' => $studentId,
                'office_id' => $officeId,
                'requirement_text' => $text,
                'attachment_path' => $attachment['path'],
                'attachment_name' => $attachment['name'],
                'created_by' => $createdBy,
            ]);
        }

        return ['ok' => true, 'message' => count($items) === 1 ? 'Requirement added.' : count($items) . ' requirements added.'];
    }

    public function markStudentAttachedRequirement(
        int $requirementId,
        int $officeId,
        int $semesterId,
        int $signatoryUserId,
        bool $completed
    ): array {
        if (!$this->tableExists('student_office_requirements') || $requirementId <= 0) {
            return ['ok' => false, 'message' => 'Invalid requirement.'];
        }
        if (!$this->isAssignedSignatory($signatoryUserId, $officeId, $semesterId)) {
            return ['ok' => false, 'message' => 'You are not assigned to this office for this semester.'];
        }

        $lookup = $this->pdo->prepare("
            SELECT student_id
            FROM student_office_requirements
            WHERE id = :id
              AND office_id = :office_id
              AND semester_id = :semester_id
            LIMIT 1
        ");
        $lookup->execute([
            'id' => $requirementId,
            'office_id' => $officeId,
            'semester_id' => $semesterId,
        ]);
        $studentId = (int) $lookup->fetchColumn();
        if ($studentId <= 0) {
            return ['ok' => false, 'message' => 'Requirement not found.'];
        }
        if (!$this->canSignatoryAccessStudent($signatoryUserId, $officeId, $studentId, $semesterId)) {
            return ['ok' => false, 'message' => 'You cannot manage requirements for this student.'];
        }

        $stmt = $this->pdo->prepare("
            UPDATE student_office_requirements
            SET is_completed = :is_completed,
                completed_at = CASE WHEN :is_completed_2 = 1 THEN NOW() ELSE NULL END,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :id
              AND office_id = :office_id
              AND semester_id = :semester_id
            LIMIT 1
        ");
        $stmt->execute([
            'is_completed' => $completed ? 1 : 0,
            'is_completed_2' => $completed ? 1 : 0,
            'id' => $requirementId,
            'office_id' => $officeId,
            'semester_id' => $semesterId,
        ]);
        if ($stmt->rowCount() <= 0) {
            return ['ok' => false, 'message' => 'Requirement not found.'];
        }

        return ['ok' => true, 'message' => $completed ? 'Requirement marked complete.' : 'Requirement marked incomplete.'];
    }

    public function deleteStudentAttachedRequirement(
        int $requirementId,
        int $officeId,
        int $semesterId,
        int $signatoryUserId
    ): array {
        if (!$this->tableExists('student_office_requirements') || $requirementId <= 0) {
            return ['ok' => false, 'message' => 'Invalid requirement.'];
        }
        if (!$this->isAssignedSignatory($signatoryUserId, $officeId, $semesterId)) {
            return ['ok' => false, 'message' => 'You are not assigned to this office for this semester.'];
        }

        $lookup = $this->pdo->prepare("
            SELECT student_id, attachment_path
            FROM student_office_requirements
            WHERE id = :id
              AND office_id = :office_id
              AND semester_id = :semester_id
            LIMIT 1
        ");
        $lookup->execute([
            'id' => $requirementId,
            'office_id' => $officeId,
            'semester_id' => $semesterId,
        ]);
        $row = $lookup->fetch();
        if (!$row) {
            return ['ok' => false, 'message' => 'Requirement not found.'];
        }
        $studentId = (int) ($row['student_id'] ?? 0);
        $attachmentPath = isset($row['attachment_path']) && trim((string) $row['attachment_path']) !== ''
            ? trim((string) $row['attachment_path'])
            : '';
        if ($studentId <= 0) {
            return ['ok' => false, 'message' => 'Requirement not found.'];
        }
        if (!$this->canSignatoryAccessStudent($signatoryUserId, $officeId, $studentId, $semesterId)) {
            return ['ok' => false, 'message' => 'You cannot manage requirements for this student.'];
        }

        $stmt = $this->pdo->prepare("
            DELETE FROM student_office_requirements
            WHERE id = :id
              AND office_id = :office_id
              AND semester_id = :semester_id
            LIMIT 1
        ");
        $stmt->execute([
            'id' => $requirementId,
            'office_id' => $officeId,
            'semester_id' => $semesterId,
        ]);
        if ($stmt->rowCount() <= 0) {
            return ['ok' => false, 'message' => 'Requirement not found.'];
        }

        if ($attachmentPath !== '') {
            $this->deleteStudentAttachedRequirementAttachmentIfUnused($attachmentPath);
        }

        return ['ok' => true, 'message' => 'Requirement removed.'];
    }

    private function deleteStudentAttachedRequirementAttachmentIfUnused(string $attachmentPath): void
    {
        if (!$this->tableExists('student_office_requirements')) {
            return;
        }
        $stmt = $this->pdo->prepare('
            SELECT COUNT(*) FROM student_office_requirements WHERE attachment_path = :attachment_path
        ');
        $stmt->execute(['attachment_path' => $attachmentPath]);
        if ((int) $stmt->fetchColumn() > 0) {
            return;
        }
        $this->deleteStoredSubmissionFile($attachmentPath);
    }

    /** Office codes where signatory queue may be filtered by college/program. */
    private const SIGNATORY_COLLEGE_PROGRAM_FILTER_CODES = ['SSC', 'LIB', 'SAS'];

    /** Offices that must clear a student before SAS may sign/approve (default units; dynamic children use parent_office_id). */
    private const SAS_PREREQUISITE_OFFICE_CODES = ['SSC', 'DORM', 'ACCT', 'SOA'];

    /** Offices that must clear a student before Dean may sign/approve (default units; dynamic children use parent_office_id). */
    private const DEAN_PREREQUISITE_OFFICE_CODES = ['LIB'];

    private const ACCOUNTING_OFFICE_CODE = 'ACCT';

    private const DORMITORY_OFFICE_CODE = 'DORM';

    /** Parent offices that may have additional child clearance units configured by admin. */
    private const GROUP_PARENT_OFFICE_CODES = ['SAS', 'DEAN'];

    /** Built-in child offices that cannot be removed by admin. */
    private const PROTECTED_CHILD_OFFICE_CODES = ['SSC', 'DORM', 'ACCT', 'SOA', 'LIB'];

    /** Offices where signatories must upload an e-signature before clearing students. */
    private const SIGNATORY_SIGNATURE_REQUIRED_CODES = ['SAS', 'DEAN'];

    public function signatoryOfficeAllowsCollegeProgramQueueFilter(?array $office): bool
    {
        if ($office === null || !isset($office['code'])) {
            return false;
        }

        return in_array(strtoupper(trim((string) $office['code'])), self::SIGNATORY_COLLEGE_PROGRAM_FILTER_CODES, true);
    }

    /** Any assigned signatory office may filter its student queue by college, program, and year level. */
    public function signatoryOfficeAllowsQueueSearchFilters(?array $office): bool
    {
        return $office !== null
            && isset($office['code'])
            && trim((string) $office['code']) !== '';
    }

    /** All assigned signatory offices use the premium signatory dashboard layout. */
    public function signatoryOfficeUsesPremiumQueueDashboard(?array $office): bool
    {
        return $office !== null
            && isset($office['code'])
            && trim((string) $office['code']) !== '';
    }

    public function signatoryOfficeRequiresSignatureUpload(?array $office): bool
    {
        if ($office === null || !isset($office['code'])) {
            return false;
        }

        return in_array(
            strtoupper(trim((string) $office['code'])),
            self::SIGNATORY_SIGNATURE_REQUIRED_CODES,
            true
        );
    }

    public function getSignatoryOffice(int $signatoryUserId, int $semesterId): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT o.id, o.code, o.name, o.sequence_no
            FROM office_signatories os
            JOIN offices o ON o.id = os.office_id
            WHERE os.user_id = :user_id
              AND os.semester_id = :semester_id
            ORDER BY o.sequence_no
            LIMIT 1
        ");
        $stmt->execute([
            'user_id' => $signatoryUserId,
            'semester_id' => $semesterId,
        ]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /**
     * Office immediately before this one in clearance order (by sequence_no), if any.
     *
     * @return array{id:int,code:string,name:string}|null
     */
    public function getPreviousOfficeInSequence(int $officeId): ?array
    {
        $sequenceStmt = $this->pdo->prepare('SELECT sequence_no FROM offices WHERE id = :office_id');
        $sequenceStmt->execute(['office_id' => $officeId]);
        $currentSequence = (int) $sequenceStmt->fetchColumn();
        if ($currentSequence <= 1) {
            return null;
        }
        $stmt = $this->pdo->prepare('
            SELECT o.id, o.code, o.name
            FROM offices o
            WHERE o.sequence_no = :previous_sequence
            LIMIT 1
        ');
        $stmt->execute(['previous_sequence' => $currentSequence - 1]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function getSignatoryQueue(
        int $signatoryUserId,
        int $semesterId,
        ?int $filterCollegeId = null,
        ?int $filterProgramId = null,
        ?string $filterYearLevel = null,
        ?string $filterSearchName = null,
        ?string $filterStatus = null
    ): array {
        $office = $this->getSignatoryOffice($signatoryUserId, $semesterId);
        if (!$office) {
            return [];
        }
        $officeId = (int) $office['id'];
        if (!$this->signatoryOfficeAllowsQueueSearchFilters($office)) {
            $filterCollegeId = null;
            $filterProgramId = null;
            $filterYearLevel = null;
            $filterSearchName = null;
            $filterStatus = null;
        } else {
            $filterCollegeId = ($filterCollegeId !== null && $filterCollegeId > 0) ? $filterCollegeId : null;
            $filterProgramId = ($filterProgramId !== null && $filterProgramId > 0) ? $filterProgramId : null;
            $filterYearLevel = $this->normalizeQueueYearLevelFilter($filterYearLevel);
            $filterSearchName = $this->normalizeQueueSearchNameFilter($filterSearchName);
            $filterStatus = $this->normalizeQueueStatusFilter($filterStatus);
        }
        $requiredCollegeId = $this->getRequiredCollegeForSignatoryOffice($signatoryUserId, $office);
        if ($requiredCollegeId !== null) {
            $filterCollegeId = $requiredCollegeId;
        }

        $extraWhere = '';
        $bind = [
            'office_id' => $officeId,
            'semester_id' => $semesterId,
            'office_id_2' => $officeId,
            'semester_id_2' => $semesterId,
            'semester_id_3' => $semesterId,
        ];
        if ($filterCollegeId !== null) {
            $extraWhere .= ' AND u.college_id = :filter_college_id';
            $bind['filter_college_id'] = $filterCollegeId;
        }
        if ($filterProgramId !== null) {
            $extraWhere .= ' AND u.program_id = :filter_program_id';
            $bind['filter_program_id'] = $filterProgramId;
        }
        if ($filterYearLevel !== null) {
            $extraWhere .= ' AND u.year_level = :filter_year_level';
            $bind['filter_year_level'] = $filterYearLevel;
        }
        if ($filterSearchName !== null) {
            $namePattern = $this->queueSearchLikePattern($filterSearchName);
            $extraWhere .= ' AND (
                u.first_name LIKE :filter_search_name
                OR u.last_name LIKE :filter_search_name
                OR u.student_no LIKE :filter_search_name
                OR CONCAT(u.first_name, \' \', u.last_name) LIKE :filter_search_name
                OR CONCAT(u.last_name, \', \', u.first_name) LIKE :filter_search_name
            )';
            $bind['filter_search_name'] = $namePattern;
        }
        if ($filterStatus !== null) {
            if ($filterStatus === 'for_review') {
                $extraWhere .= " AND COALESCE(sc.status, 'pending') IN ('pending', 'for_review')";
            } else {
                $extraWhere .= ' AND sc.status = :filter_status';
                $bind['filter_status'] = $filterStatus;
            }
        }

        $stmt = $this->pdo->prepare("
            SELECT
                u.id AS student_id,
                u.student_no,
                u.first_name,
                u.last_name,
                MAX(COALESCE(c.name, '')) AS college_name,
                MAX(COALESCE(p.name, '')) AS program_name,
                MAX(COALESCE(u.year_level, '')) AS year_level,
                MAX(COALESCE(u.campus, '')) AS campus,
                COALESCE(sc.status, 'pending') AS clearance_status,
                MAX(rs.uploaded_at) AS latest_upload_at
            FROM users u
            LEFT JOIN colleges c ON c.id = u.college_id
            LEFT JOIN programs p ON p.id = u.program_id
            LEFT JOIN student_clearances sc
                ON sc.student_id = u.id
               AND sc.office_id = :office_id
               AND sc.semester_id = :semester_id
            LEFT JOIN office_requirements r
                ON r.office_id = :office_id_2
               AND r.semester_id = :semester_id_2
               AND r.is_active = 1
            LEFT JOIN requirement_submissions rs
                ON rs.office_requirement_id = r.id
               AND rs.student_id = u.id
               AND rs.semester_id = :semester_id_3
            WHERE u.role = 'student'
              AND u.is_active = 1
            {$extraWhere}
            GROUP BY u.id, u.student_no, u.first_name, u.last_name, u.year_level, u.campus, sc.status
            ORDER BY latest_upload_at DESC, u.last_name ASC
        ");
        $stmt->execute($bind);
        $rows = $stmt->fetchAll();
        $officeCode = strtoupper(trim((string) ($office['code'] ?? '')));
        $isAccountingOffice = $officeCode === self::ACCOUNTING_OFFICE_CODE;
        $isDormitoryOffice = $officeCode === self::DORMITORY_OFFICE_CODE;
        $filtered = [];
        foreach ($rows as $row) {
            $studentId = (int) $row['student_id'];
            if ($isAccountingOffice && !$this->studentRequiresAccountingClearance($studentId)) {
                continue;
            }
            if ($isDormitoryOffice && !$this->studentRequiresDormitoryClearance($studentId)) {
                continue;
            }
            if (!$this->isOfficeUnlocked($officeId, $studentId, $semesterId)) {
                continue;
            }
            $filtered[] = $row;
        }
        return $filtered;
    }

    /**
     * Clearance status for each office under SAS (not Dean/LIB). Used on the SAS signatory dashboard.
     *
     * @return list<array{office_id:int, office_code:string, office_name:string, status:string}>
     */
    public function getSasSubordinateClearanceStatusForStudent(int $studentId, int $semesterId): array
    {
        return $this->buildSubordinateClearanceStatusForStudent(
            $studentId,
            $semesterId,
            $this->getSasPrerequisiteOfficesForStudent($studentId)
        );
    }

    /**
     * Clearance status for each office under Dean (not SAS). Used on the Dean signatory dashboard.
     *
     * @return list<array{office_id:int, office_code:string, office_name:string, status:string}>
     */
    public function getDeanSubordinateClearanceStatusForStudent(int $studentId, int $semesterId): array
    {
        return $this->buildSubordinateClearanceStatusForStudent(
            $studentId,
            $semesterId,
            $this->getDeanPrerequisiteOfficesForStudent($studentId)
        );
    }

    /**
     * @param list<array{id:int, code:string, name:string}> $offices
     * @return list<array{office_id:int, office_code:string, office_name:string, status:string}>
     */
    private function buildSubordinateClearanceStatusForStudent(int $studentId, int $semesterId, array $offices): array
    {
        if ($studentId <= 0 || $semesterId <= 0 || $offices === []) {
            return [];
        }

        $officeIds = array_values(array_filter(
            array_map(static fn(array $office): int => (int) ($office['id'] ?? 0), $offices),
            static fn(int $id): bool => $id > 0
        ));
        if ($officeIds === []) {
            return [];
        }

        $placeholders = [];
        $bindings = [
            'student_id' => $studentId,
            'semester_id' => $semesterId,
        ];
        foreach ($officeIds as $idx => $officeId) {
            $key = 'office_id_' . $idx;
            $placeholders[] = ':' . $key;
            $bindings[$key] = $officeId;
        }

        $stmt = $this->pdo->prepare('
            SELECT office_id, status
            FROM student_clearances
            WHERE student_id = :student_id
              AND semester_id = :semester_id
              AND office_id IN (' . implode(', ', $placeholders) . ')
        ');
        $stmt->execute($bindings);
        $statusByOfficeId = [];
        foreach ($stmt->fetchAll() as $row) {
            $statusByOfficeId[(int) ($row['office_id'] ?? 0)] = strtolower((string) ($row['status'] ?? 'pending'));
        }

        $result = [];
        foreach ($offices as $office) {
            $officeId = (int) ($office['id'] ?? 0);
            if ($officeId <= 0) {
                continue;
            }
            $result[] = [
                'office_id' => $officeId,
                'office_code' => strtoupper(trim((string) ($office['code'] ?? ''))),
                'office_name' => (string) ($office['name'] ?? ''),
                'status' => $statusByOfficeId[$officeId] ?? 'pending',
            ];
        }

        return $result;
    }

    /**
     * @param list<int> $studentIds
     * @return array<int, list<array{office_id:int, office_code:string, office_name:string, status:string}>>
     */
    public function getSasSubordinateClearanceStatusMap(array $studentIds, int $semesterId): array
    {
        $studentIds = array_values(array_unique(array_filter(
            array_map(static fn($id): int => (int) $id, $studentIds),
            static fn(int $id): bool => $id > 0
        )));
        if ($studentIds === [] || $semesterId <= 0) {
            return [];
        }

        $map = [];
        foreach ($studentIds as $studentId) {
            $map[$studentId] = $this->getSasSubordinateClearanceStatusForStudent($studentId, $semesterId);
        }

        return $map;
    }

    /**
     * @param list<int> $studentIds
     * @return array<int, list<array{office_id:int, office_code:string, office_name:string, status:string}>>
     */
    public function getDeanSubordinateClearanceStatusMap(array $studentIds, int $semesterId): array
    {
        $studentIds = array_values(array_unique(array_filter(
            array_map(static fn($id): int => (int) $id, $studentIds),
            static fn(int $id): bool => $id > 0
        )));
        if ($studentIds === [] || $semesterId <= 0) {
            return [];
        }

        $map = [];
        foreach ($studentIds as $studentId) {
            $map[$studentId] = $this->getDeanSubordinateClearanceStatusForStudent($studentId, $semesterId);
        }

        return $map;
    }

    /**
     * @return list<string>
     */
    public function getSasPrerequisiteOfficeLabels(): array
    {
        $labels = [];
        foreach ($this->getSasPrerequisiteOfficesForStudent(0) as $office) {
            $labels[] = (string) ($office['name'] ?? '');
        }

        return array_values(array_filter($labels, static fn(string $label): bool => $label !== ''));
    }

    /**
     * @return list<array{id:int, code:string, name:string}>
     */
    private function getSasPrerequisiteOfficesForStudent(int $studentId): array
    {
        return $this->getGroupPrerequisiteOfficesForStudent(
            'SAS',
            self::SAS_PREREQUISITE_OFFICE_CODES,
            $studentId,
            true
        );
    }

    /**
     * @return list<array{id:int, code:string, name:string}>
     */
    private function getDeanPrerequisiteOfficesForStudent(int $studentId): array
    {
        return $this->getGroupPrerequisiteOfficesForStudent(
            'DEAN',
            self::DEAN_PREREQUISITE_OFFICE_CODES,
            $studentId,
            false
        );
    }

    /**
     * @param list<string> $fallbackCodes
     * @return list<array{id:int, code:string, name:string}>
     */
    private function getGroupPrerequisiteOfficesForStudent(
        string $parentOfficeCode,
        array $fallbackCodes,
        int $studentId,
        bool $filterAccountingForStudent
    ): array {
        $parentOfficeId = $this->getOfficeIdByCode($parentOfficeCode);
        if ($parentOfficeId <= 0) {
            return [];
        }

        $stmt = $this->pdo->prepare('
            SELECT id, code, name
            FROM offices
            WHERE parent_office_id = :parent_office_id
              AND is_active = 1
            ORDER BY sequence_no ASC, name ASC
        ');
        $stmt->execute(['parent_office_id' => $parentOfficeId]);
        $offices = $stmt->fetchAll();
        if ($offices === []) {
            $placeholders = [];
            $bindings = [];
            foreach ($fallbackCodes as $idx => $code) {
                $key = 'code_' . $idx;
                $placeholders[] = ':' . $key;
                $bindings[$key] = $code;
            }
            $fallback = $this->pdo->prepare('
                SELECT id, code, name
                FROM offices
                WHERE UPPER(code) IN (' . implode(', ', $placeholders) . ')
                  AND is_active = 1
                ORDER BY sequence_no ASC, name ASC
            ');
            $fallback->execute($bindings);
            $offices = $fallback->fetchAll();
        }

        if ($studentId > 0) {
            if ($filterAccountingForStudent && !$this->studentRequiresAccountingClearance($studentId)) {
                $offices = array_values(array_filter(
                    $offices,
                    static fn(array $office): bool => strtoupper(trim((string) ($office['code'] ?? ''))) !== self::ACCOUNTING_OFFICE_CODE
                ));
            }
            if (!$this->studentRequiresDormitoryClearance($studentId)) {
                $offices = array_values(array_filter(
                    $offices,
                    static fn(array $office): bool => strtoupper(trim((string) ($office['code'] ?? ''))) !== self::DORMITORY_OFFICE_CODE
                ));
            }
        }

        return $offices;
    }

    public function getDeanPrerequisiteOfficeLabels(): array
    {
        $labels = [];
        foreach ($this->getDeanPrerequisiteOfficesForStudent(0) as $office) {
            $labels[] = (string) ($office['name'] ?? '');
        }

        return array_values(array_filter($labels, static fn(string $label): bool => $label !== ''));
    }

    public function studentMeetsSasSignaturePrerequisites(int $studentId, int $semesterId): bool
    {
        return $this->studentMeetsGroupSignaturePrerequisites(
            $studentId,
            $semesterId,
            $this->getSasPrerequisiteOfficesForStudent($studentId)
        );
    }

    public function studentMeetsDeanSignaturePrerequisites(int $studentId, int $semesterId): bool
    {
        return $this->studentMeetsGroupSignaturePrerequisites(
            $studentId,
            $semesterId,
            $this->getDeanPrerequisiteOfficesForStudent($studentId)
        );
    }

    /**
     * @param list<array{id:int, code:string, name:string}> $requiredOffices
     */
    private function studentMeetsGroupSignaturePrerequisites(int $studentId, int $semesterId, array $requiredOffices): bool
    {
        if ($studentId <= 0 || $semesterId <= 0) {
            return false;
        }

        $studentStmt = $this->pdo->prepare("
            SELECT is_active
            FROM users
            WHERE id = :student_id
              AND role = 'student'
            LIMIT 1
        ");
        $studentStmt->execute(['student_id' => $studentId]);
        $studentRow = $studentStmt->fetch();
        if (!$studentRow || (int) ($studentRow['is_active'] ?? 0) !== 1) {
            return false;
        }

        if ($requiredOffices === []) {
            return false;
        }

        $officeIds = array_map(static fn(array $office): int => (int) ($office['id'] ?? 0), $requiredOffices);
        $officeIds = array_values(array_filter($officeIds, static fn(int $id): bool => $id > 0));
        if ($officeIds === []) {
            return false;
        }

        $placeholders = [];
        $bindings = [
            'student_id' => $studentId,
            'semester_id' => $semesterId,
        ];
        foreach ($officeIds as $idx => $officeId) {
            $key = 'office_id_' . $idx;
            $placeholders[] = ':' . $key;
            $bindings[$key] = $officeId;
        }

        $stmt = $this->pdo->prepare('
            SELECT COUNT(DISTINCT sc.office_id) AS cleared_count
            FROM student_clearances sc
            INNER JOIN offices o ON o.id = sc.office_id
            WHERE sc.student_id = :student_id
              AND sc.semester_id = :semester_id
              AND sc.status = \'cleared\'
              AND o.is_active = 1
              AND sc.office_id IN (' . implode(', ', $placeholders) . ')
        ');
        $stmt->execute($bindings);

        return (int) $stmt->fetchColumn() === count($officeIds);
    }

    private function isSasOfficeId(int $officeId): bool
    {
        $stmt = $this->pdo->prepare('
            SELECT 1
            FROM offices
            WHERE id = :office_id
              AND UPPER(code) = \'SAS\'
            LIMIT 1
        ');
        $stmt->execute(['office_id' => $officeId]);

        return (bool) $stmt->fetchColumn();
    }

    private function isDeanOfficeId(int $officeId): bool
    {
        $stmt = $this->pdo->prepare('
            SELECT 1
            FROM offices
            WHERE id = :office_id
              AND UPPER(code) = \'DEAN\'
            LIMIT 1
        ');
        $stmt->execute(['office_id' => $officeId]);

        return (bool) $stmt->fetchColumn();
    }

    private function isAccountingOfficeId(int $officeId): bool
    {
        return $this->isOfficeCode($officeId, self::ACCOUNTING_OFFICE_CODE);
    }

    private function isDormitoryOfficeId(int $officeId): bool
    {
        return $this->isOfficeCode($officeId, self::DORMITORY_OFFICE_CODE);
    }

    private function isOfficeCode(int $officeId, string $officeCode): bool
    {
        $stmt = $this->pdo->prepare('
            SELECT 1
            FROM offices
            WHERE id = :office_id
              AND UPPER(code) = :office_code
            LIMIT 1
        ');
        $stmt->execute([
            'office_id' => $officeId,
            'office_code' => strtoupper(trim($officeCode)),
        ]);

        return (bool) $stmt->fetchColumn();
    }

    private function officeRequiresSignatorySignature(int $officeId): bool
    {
        $stmt = $this->pdo->prepare('
            SELECT UPPER(code)
            FROM offices
            WHERE id = :office_id
            LIMIT 1
        ');
        $stmt->execute(['office_id' => $officeId]);
        $code = strtoupper(trim((string) ($stmt->fetchColumn() ?: '')));

        return in_array($code, self::SIGNATORY_SIGNATURE_REQUIRED_CODES, true);
    }

    public function getRequiredCollegeForSignatoryOffice(int $signatoryUserId, ?array $office): ?int
    {
        if ($office === null) {
            return null;
        }
        if (strtoupper(trim((string) ($office['code'] ?? ''))) !== 'DEAN') {
            return null;
        }
        return $this->getSignatoryCollegeId($signatoryUserId);
    }

    public function getSignatoryCollegeId(int $signatoryUserId): ?int
    {
        $stmt = $this->pdo->prepare("
            SELECT college_id
            FROM users
            WHERE id = :user_id
              AND role = 'signatory'
            LIMIT 1
        ");
        $stmt->execute(['user_id' => $signatoryUserId]);
        $collegeId = (int) ($stmt->fetchColumn() ?: 0);
        return $collegeId > 0 ? $collegeId : null;
    }

    private function canSignatoryAccessStudent(int $signatoryUserId, int $officeId, int $studentId, int $semesterId): bool
    {
        $office = $this->getSignatoryOffice($signatoryUserId, $semesterId);
        if ($office === null || (int) ($office['id'] ?? 0) !== $officeId) {
            return false;
        }
        $requiredCollegeId = $this->getRequiredCollegeForSignatoryOffice($signatoryUserId, $office);
        if ($requiredCollegeId === null) {
            return true;
        }
        $stmt = $this->pdo->prepare("
            SELECT 1
            FROM users
            WHERE id = :student_id
              AND role = 'student'
              AND college_id = :college_id
            LIMIT 1
        ");
        $stmt->execute([
            'student_id' => $studentId,
            'college_id' => $requiredCollegeId,
        ]);
        return (bool) $stmt->fetchColumn();
    }

    /**
     * Requirement-level submission visibility for signatory queue students.
     *
     * @param list<int> $studentIds
     * @return array<int, list<array<string,mixed>>>
     */
    public function getSignatoryRequirementProgressMap(int $officeId, int $semesterId, array $studentIds): array
    {
        $studentIds = array_values(array_unique(array_map('intval', $studentIds)));
        if ($studentIds === []) {
            return [];
        }

        $requirements = $this->getOfficeRequirementsForOffice($semesterId, $officeId);
        $map = [];
        foreach ($studentIds as $studentId) {
            $map[$studentId] = [];
            foreach ($requirements as $req) {
                $map[$studentId][] = [
                    'requirement_id' => (int) $req['id'],
                    'title' => (string) $req['title'],
                    'description' => (string) ($req['description'] ?? ''),
                    'is_submitted' => false,
                    'file_path' => null,
                    'original_filename' => null,
                    'uploaded_at' => null,
                ];
            }
        }
        if ($requirements === []) {
            return $map;
        }

        $studentPlaceholders = [];
        $reqPlaceholders = [];
        $bindings = ['semester_id' => $semesterId];
        foreach ($studentIds as $idx => $sid) {
            $ph = 'sid_' . $idx;
            $studentPlaceholders[] = ':' . $ph;
            $bindings[$ph] = $sid;
        }
        foreach (array_values($requirements) as $idx => $req) {
            $ph = 'rid_' . $idx;
            $reqPlaceholders[] = ':' . $ph;
            $bindings[$ph] = (int) $req['id'];
        }

        $sql = '
            SELECT t1.student_id, t1.office_requirement_id, t1.file_path, t1.original_filename, t1.uploaded_at
            FROM requirement_submissions t1
            INNER JOIN (
                SELECT student_id, office_requirement_id, MAX(id) AS max_id
                FROM requirement_submissions
                WHERE semester_id = :semester_id
                  AND student_id IN (' . implode(',', $studentPlaceholders) . ')
                  AND office_requirement_id IN (' . implode(',', $reqPlaceholders) . ')
                GROUP BY student_id, office_requirement_id
            ) t2 ON t1.id = t2.max_id
        ';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($bindings);
        $latestRows = $stmt->fetchAll();

        $latestByStudentAndReq = [];
        foreach ($latestRows as $row) {
            $sid = (int) $row['student_id'];
            $rid = (int) $row['office_requirement_id'];
            $latestByStudentAndReq[$sid . ':' . $rid] = $row;
        }

        foreach ($map as $sid => &$items) {
            foreach ($items as &$item) {
                $rid = (int) $item['requirement_id'];
                $key = $sid . ':' . $rid;
                if (!isset($latestByStudentAndReq[$key])) {
                    continue;
                }
                $latest = $latestByStudentAndReq[$key];
                $item['is_submitted'] = true;
                $item['file_path'] = $latest['file_path'] ?? null;
                $item['original_filename'] = $latest['original_filename'] ?? null;
                $item['uploaded_at'] = $latest['uploaded_at'] ?? null;
            }
        }

        return $map;
    }

    public function getNotifications(int $userId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT id, type, title, body, is_read, created_at
            FROM notifications
            WHERE user_id = :user_id
            ORDER BY id DESC
            LIMIT 5
        ");
        $stmt->execute(['user_id' => $userId]);
        return $stmt->fetchAll();
    }

    public function isSignatoryAssignedThisSemester(int $userId, int $semesterId): bool
    {
        $stmt = $this->pdo->prepare('
            SELECT 1 FROM office_signatories
            WHERE user_id = :user_id AND semester_id = :semester_id
            LIMIT 1
        ');
        $stmt->execute(['user_id' => $userId, 'semester_id' => $semesterId]);

        return (bool) $stmt->fetchColumn();
    }

    /**
     * Active signatories this semester (for student to pick who to message).
     *
     * @return list<array{id:int, first_name:string, last_name:string, offices_label:string}>
     */
    public function listSignatoriesForStudentMessaging(int $semesterId, int $studentId): array
    {
        if ($studentId <= 0) {
            return [];
        }
        $stmt = $this->pdo->prepare("
            SELECT os.user_id AS id, u.first_name, u.last_name,
                   GROUP_CONCAT(DISTINCT o.name ORDER BY o.sequence_no ASC SEPARATOR ' · ') AS offices_label
            FROM office_signatories os
            INNER JOIN users u ON u.id = os.user_id
            INNER JOIN offices o ON o.id = os.office_id
            INNER JOIN users su ON su.id = :student_id
            WHERE os.semester_id = :semester_id
              AND u.role = 'signatory'
              AND u.is_active = 1
              AND su.role = 'student'
              AND su.college_id IS NOT NULL
              AND (
                  u.college_id = su.college_id
                  OR UPPER(COALESCE(o.code, '')) IN ('SSC', 'LIB', 'SAS')
              )
            GROUP BY os.user_id, u.first_name, u.last_name
            ORDER BY u.last_name ASC, u.first_name ASC
        ");
        $stmt->execute([
            'semester_id' => $semesterId,
            'student_id' => $studentId,
        ]);
        $rows = $stmt->fetchAll();
        foreach ($rows as &$r) {
            $r['id'] = (int) ($r['id'] ?? 0);
        }

        return $rows;
    }

    public function isSignatoryAvailableForStudentMessaging(int $semesterId, int $studentId, int $signatoryUserId): bool
    {
        if ($studentId <= 0 || $signatoryUserId <= 0) {
            return false;
        }
        $stmt = $this->pdo->prepare('
            SELECT 1 FROM office_signatories os
            INNER JOIN users u ON u.id = os.user_id
            INNER JOIN users su ON su.id = :student_id
            INNER JOIN offices o ON o.id = os.office_id
            WHERE os.semester_id = :semester_id
              AND os.user_id = :signatory_user_id
              AND u.role = \'signatory\'
              AND u.is_active = 1
              AND su.role = \'student\'
              AND su.college_id IS NOT NULL
              AND (
                  u.college_id = su.college_id
                  OR UPPER(COALESCE(o.code, \'\')) IN (\'SSC\', \'LIB\', \'SAS\')
              )
            LIMIT 1
        ');
        $stmt->execute([
            'semester_id' => $semesterId,
            'student_id' => $studentId,
            'signatory_user_id' => $signatoryUserId,
        ]);

        return (bool) $stmt->fetchColumn();
    }

    public function getOrCreateClearanceMessageThread(int $studentId, int $semesterId, int $signatoryUserId): int
    {
        if (!$this->isSignatoryAvailableForStudentMessaging($semesterId, $studentId, $signatoryUserId)) {
            throw new \InvalidArgumentException('Invalid signatory for messaging.');
        }
        $stmt = $this->pdo->prepare('
            SELECT id FROM clearance_message_threads
            WHERE semester_id = :semester_id
              AND student_id = :student_id
              AND signatory_user_id = :signatory_user_id
            LIMIT 1
        ');
        $stmt->execute([
            'semester_id' => $semesterId,
            'student_id' => $studentId,
            'signatory_user_id' => $signatoryUserId,
        ]);
        $existing = $stmt->fetchColumn();
        if ($existing !== false) {
            return (int) $existing;
        }
        $ins = $this->pdo->prepare('
            INSERT INTO clearance_message_threads (semester_id, student_id, signatory_user_id)
            VALUES (:semester_id, :student_id, :signatory_user_id)
        ');
        $ins->execute([
            'semester_id' => $semesterId,
            'student_id' => $studentId,
            'signatory_user_id' => $signatoryUserId,
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    public function markClearanceMessageThreadRead(int $threadId, int $userId): void
    {
        $stmt = $this->pdo->prepare('
            INSERT INTO clearance_message_thread_reads (thread_id, user_id, last_read_at)
            VALUES (:thread_id, :user_id, NOW())
            ON DUPLICATE KEY UPDATE last_read_at = NOW()
        ');
        $stmt->execute(['thread_id' => $threadId, 'user_id' => $userId]);
    }

    /**
     * @return list<array<string,mixed>>
     */
    public function getClearanceMessagesForStudentThread(int $studentId, int $semesterId, int $signatoryUserId): array
    {
        if (!$this->isSignatoryAvailableForStudentMessaging($semesterId, $studentId, $signatoryUserId)) {
            return [];
        }
        $stmt = $this->pdo->prepare('
            SELECT m.id, m.thread_id, m.sender_user_id, m.body, m.created_at,
                   u.first_name, u.last_name, u.role AS sender_role
            FROM clearance_message_threads t
            INNER JOIN clearance_messages m ON m.thread_id = t.id
            INNER JOIN users u ON u.id = m.sender_user_id
            WHERE t.semester_id = :semester_id
              AND t.student_id = :student_id
              AND t.signatory_user_id = :signatory_user_id
            ORDER BY m.id ASC
        ');
        $stmt->execute([
            'semester_id' => $semesterId,
            'student_id' => $studentId,
            'signatory_user_id' => $signatoryUserId,
        ]);
        $rows = $stmt->fetchAll();
        if ($rows !== []) {
            $tid = (int) ($rows[0]['thread_id'] ?? 0);
            if ($tid > 0) {
                $this->markClearanceMessageThreadRead($tid, $studentId);
            }
        }

        return $rows;
    }

    public function getUnreadClearanceMessageCountForStudent(int $studentId, int $semesterId): int
    {
        $stmt = $this->pdo->prepare('
            SELECT id FROM clearance_message_threads
            WHERE semester_id = :semester_id AND student_id = :student_id
        ');
        $stmt->execute(['semester_id' => $semesterId, 'student_id' => $studentId]);
        $ids = $stmt->fetchAll(PDO::FETCH_COLUMN);
        $sum = 0;
        foreach ($ids as $tid) {
            $sum += $this->countUnreadClearanceMessagesInThread((int) $tid, $studentId);
        }

        return $sum;
    }

    /**
     * @return list<array<string,mixed>>
     */
    public function listClearanceMessageThreadsForSignatory(int $signatoryUserId, int $semesterId): array
    {
        if (!$this->isSignatoryAssignedThisSemester($signatoryUserId, $semesterId)) {
            return [];
        }
        $stmt = $this->pdo->prepare('
            SELECT t.id AS thread_id, t.student_id, t.updated_at,
                   u.student_no, u.first_name, u.last_name,
                   (SELECT m2.body FROM clearance_messages m2
                    WHERE m2.thread_id = t.id ORDER BY m2.id DESC LIMIT 1) AS last_snippet,
                   (SELECT m2.created_at FROM clearance_messages m2
                    WHERE m2.thread_id = t.id ORDER BY m2.id DESC LIMIT 1) AS last_at
            FROM clearance_message_threads t
            INNER JOIN users u ON u.id = t.student_id
            WHERE t.semester_id = :semester_id
              AND t.signatory_user_id = :signatory_user_id
              AND EXISTS (SELECT 1 FROM clearance_messages m WHERE m.thread_id = t.id)
            ORDER BY t.updated_at DESC
        ');
        $stmt->execute([
            'semester_id' => $semesterId,
            'signatory_user_id' => $signatoryUserId,
        ]);
        $threads = $stmt->fetchAll();
        $out = [];
        foreach ($threads as $tr) {
            $tr['unread_count'] = $this->countUnreadClearanceMessagesInThread(
                (int) ($tr['thread_id'] ?? 0),
                $signatoryUserId
            );
            $out[] = $tr;
        }

        return $out;
    }

    /**
     * @return array{thread: array<string,mixed>, messages: list<array<string,mixed>>}|null
     */
    public function getClearanceMessageThreadDetailForSignatory(int $threadId, int $signatoryUserId, int $semesterId): ?array
    {
        if (!$this->isSignatoryAssignedThisSemester($signatoryUserId, $semesterId)) {
            return null;
        }
        $stmt = $this->pdo->prepare('
            SELECT t.id AS thread_id, t.student_id, t.semester_id,
                   u.student_no, u.first_name, u.last_name
            FROM clearance_message_threads t
            INNER JOIN users u ON u.id = t.student_id
            WHERE t.id = :thread_id
              AND t.semester_id = :semester_id
              AND t.signatory_user_id = :signatory_user_id
            LIMIT 1
        ');
        $stmt->execute([
            'thread_id' => $threadId,
            'semester_id' => $semesterId,
            'signatory_user_id' => $signatoryUserId,
        ]);
        $thread = $stmt->fetch();
        if (!$thread) {
            return null;
        }
        $msgStmt = $this->pdo->prepare('
            SELECT m.id, m.thread_id, m.sender_user_id, m.body, m.created_at,
                   u.first_name, u.last_name, u.role AS sender_role
            FROM clearance_messages m
            INNER JOIN users u ON u.id = m.sender_user_id
            WHERE m.thread_id = :thread_id
            ORDER BY m.id ASC
        ');
        $msgStmt->execute(['thread_id' => $threadId]);
        $messages = $msgStmt->fetchAll();
        $this->markClearanceMessageThreadRead($threadId, $signatoryUserId);

        return ['thread' => $thread, 'messages' => $messages];
    }

    /**
     * @return array{ok: bool, message: string}
     */
    public function postClearanceMessageFromStudent(int $studentId, int $semesterId, int $signatoryUserId, string $body): array
    {
        $body = trim($body);
        if ($body === '') {
            return ['ok' => false, 'message' => 'Message cannot be empty.'];
        }
        if (mb_strlen($body) > 4000) {
            return ['ok' => false, 'message' => 'Message is too long (max 4000 characters).'];
        }
        if (!$this->isSignatoryAvailableForStudentMessaging($semesterId, $studentId, $signatoryUserId)) {
            return ['ok' => false, 'message' => 'You can only message signatories from your college this semester.'];
        }
        try {
            $tid = $this->getOrCreateClearanceMessageThread($studentId, $semesterId, $signatoryUserId);
            $ins = $this->pdo->prepare('
                INSERT INTO clearance_messages (thread_id, sender_user_id, body)
                VALUES (:thread_id, :sender_user_id, :body)
            ');
            $ins->execute([
                'thread_id' => $tid,
                'sender_user_id' => $studentId,
                'body' => $body,
            ]);
            $this->pdo->prepare('UPDATE clearance_message_threads SET updated_at = CURRENT_TIMESTAMP WHERE id = :id')
                ->execute(['id' => $tid]);
            $this->markClearanceMessageThreadRead($tid, $studentId);
        } catch (\InvalidArgumentException $e) {
            return ['ok' => false, 'message' => $e->getMessage()];
        } catch (\Throwable) {
            return ['ok' => false, 'message' => 'Could not send message. Please try again.'];
        }

        return ['ok' => true, 'message' => 'Message sent. Only the signatory you chose can see this conversation.'];
    }

    /**
     * @return array{ok: bool, message: string}
     */
    public function postClearanceMessageFromSignatory(int $threadId, int $signatoryUserId, int $semesterId, string $body): array
    {
        $body = trim($body);
        if ($body === '') {
            return ['ok' => false, 'message' => 'Message cannot be empty.'];
        }
        if (mb_strlen($body) > 4000) {
            return ['ok' => false, 'message' => 'Message is too long (max 4000 characters).'];
        }
        if (!$this->isSignatoryAssignedThisSemester($signatoryUserId, $semesterId)) {
            return ['ok' => false, 'message' => 'You are not assigned as a signatory this semester.'];
        }
        $chk = $this->pdo->prepare('
            SELECT id FROM clearance_message_threads
            WHERE id = :thread_id
              AND semester_id = :semester_id
              AND signatory_user_id = :signatory_user_id
            LIMIT 1
        ');
        $chk->execute([
            'thread_id' => $threadId,
            'semester_id' => $semesterId,
            'signatory_user_id' => $signatoryUserId,
        ]);
        if (!$chk->fetchColumn()) {
            return ['ok' => false, 'message' => 'Conversation not found.'];
        }
        try {
            $ins = $this->pdo->prepare('
                INSERT INTO clearance_messages (thread_id, sender_user_id, body)
                VALUES (:thread_id, :sender_user_id, :body)
            ');
            $ins->execute([
                'thread_id' => $threadId,
                'sender_user_id' => $signatoryUserId,
                'body' => $body,
            ]);
            $this->pdo->prepare('UPDATE clearance_message_threads SET updated_at = CURRENT_TIMESTAMP WHERE id = :id')
                ->execute(['id' => $threadId]);
            $this->markClearanceMessageThreadRead($threadId, $signatoryUserId);
        } catch (\Throwable) {
            return ['ok' => false, 'message' => 'Could not send message. Please try again.'];
        }

        return ['ok' => true, 'message' => 'Reply sent.'];
    }

    private function countUnreadClearanceMessagesInThread(int $threadId, int $viewerUserId): int
    {
        $readStmt = $this->pdo->prepare('
            SELECT last_read_at FROM clearance_message_thread_reads
            WHERE thread_id = :thread_id AND user_id = :user_id
            LIMIT 1
        ');
        $readStmt->execute(['thread_id' => $threadId, 'user_id' => $viewerUserId]);
        $lr = $readStmt->fetchColumn();
        $since = $lr !== false && $lr !== null ? (string) $lr : '1970-01-01 00:00:00';
        $cnt = $this->pdo->prepare('
            SELECT COUNT(*) FROM clearance_messages
            WHERE thread_id = :thread_id
              AND sender_user_id != :user_id
              AND created_at > :since
        ');
        $cnt->execute([
            'thread_id' => $threadId,
            'user_id' => $viewerUserId,
            'since' => $since,
        ]);

        return (int) $cnt->fetchColumn();
    }

    public function createSemester(string $academicYear, string $term): array
    {
        $academicYear = trim($academicYear);
        if ($academicYear === '') {
            return ['ok' => false, 'message' => 'Academic year is required.'];
        }
        if (!in_array($term, ['1st', '2nd', 'summer'], true)) {
            return ['ok' => false, 'message' => 'Invalid term.'];
        }
        try {
            $this->pdo->beginTransaction();
            $this->pdo->exec("UPDATE semesters SET is_open = 0 WHERE is_open = 1");
            $stmt = $this->pdo->prepare("
                INSERT INTO semesters (academic_year, term, is_open)
                VALUES (:academic_year, :term, 1)
            ");
            $stmt->execute([
                'academic_year' => $academicYear,
                'term' => $term,
            ]);
            $this->pdo->commit();
        } catch (\Throwable) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            return ['ok' => false, 'message' => 'Could not open semester. Please try again.'];
        }
        return ['ok' => true, 'message' => 'Semester created and opened.'];
    }

    public function openSemesterById(int $semesterId): array
    {
        if ($semesterId <= 0) {
            return ['ok' => false, 'message' => 'Invalid semester selected.'];
        }
        try {
            $this->pdo->beginTransaction();
            $stmt = $this->pdo->prepare('SELECT id FROM semesters WHERE id = :id LIMIT 1');
            $stmt->execute(['id' => $semesterId]);
            if (!$stmt->fetch()) {
                $this->pdo->rollBack();
                return ['ok' => false, 'message' => 'Semester not found.'];
            }
            $this->pdo->exec("UPDATE semesters SET is_open = 0 WHERE is_open = 1");
            $openStmt = $this->pdo->prepare('UPDATE semesters SET is_open = 1 WHERE id = :id');
            $openStmt->execute(['id' => $semesterId]);
            $this->pdo->commit();
        } catch (\Throwable) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            return ['ok' => false, 'message' => 'Could not switch semester. Please try again.'];
        }

        return ['ok' => true, 'message' => 'Semester opened successfully.'];
    }

    public function updateSemesterCompletionDueDate(int $semesterId, ?string $dueDate): array
    {
        if ($semesterId <= 0) {
            return ['ok' => false, 'message' => 'Invalid semester.'];
        }

        $normalizedDueDate = null;
        if ($dueDate !== null && trim($dueDate) !== '') {
            $parsed = DateTime::createFromFormat('Y-m-d', trim($dueDate));
            if ($parsed === false || $parsed->format('Y-m-d') !== trim($dueDate)) {
                return ['ok' => false, 'message' => 'Invalid completion due date.'];
            }
            $normalizedDueDate = $parsed->format('Y-m-d');
        }

        $stmt = $this->pdo->prepare('
            UPDATE semesters
            SET ends_at = :ends_at,
                clearance_window_active = CASE
                    WHEN :ends_at IS NULL THEN 1
                    WHEN :ends_at >= CURDATE() THEN 1
                    ELSE clearance_window_active
                END
            WHERE id = :id
        ');
        $stmt->execute([
            'ends_at' => $normalizedDueDate,
            'id' => $semesterId,
        ]);

        if ($stmt->rowCount() === 0) {
            $check = $this->pdo->prepare('SELECT id FROM semesters WHERE id = :id LIMIT 1');
            $check->execute(['id' => $semesterId]);
            if (!$check->fetch()) {
                return ['ok' => false, 'message' => 'Semester not found.'];
            }
        }

        if ($normalizedDueDate === null) {
            return ['ok' => true, 'message' => 'Completion due date cleared.'];
        }

        return ['ok' => true, 'message' => 'Completion due date saved.'];
    }

    public function setSemesterClearanceWindowActive(int $semesterId, bool $active): array
    {
        if ($semesterId <= 0) {
            return ['ok' => false, 'message' => 'Invalid semester.'];
        }

        $stmt = $this->pdo->prepare('
            SELECT ends_at, clearance_window_active
            FROM semesters
            WHERE id = :id
            LIMIT 1
        ');
        $stmt->execute(['id' => $semesterId]);
        $row = $stmt->fetch();
        if (!$row) {
            return ['ok' => false, 'message' => 'Semester not found.'];
        }

        $dueDate = is_string($row['ends_at'] ?? null) ? trim((string) $row['ends_at']) : '';
        if ($dueDate === '') {
            return ['ok' => false, 'message' => 'Set a completion due date before activating or deactivating the clearance window.'];
        }

        $deadlineStatus = $this->buildSemesterDeadlineStatus($dueDate, (int) ($row['clearance_window_active'] ?? 1));
        if (!$deadlineStatus['is_expired']) {
            return ['ok' => false, 'message' => 'The clearance window can only be activated or deactivated after the due date has passed.'];
        }

        $update = $this->pdo->prepare('
            UPDATE semesters
            SET clearance_window_active = :active
            WHERE id = :id
        ');
        $update->execute([
            'active' => $active ? 1 : 0,
            'id' => $semesterId,
        ]);

        return [
            'ok' => true,
            'message' => $active
                ? 'Clearance window reactivated after the due date.'
                : 'Clearance window deactivated after the due date.',
        ];
    }

    public function syncSemesterDeadlineState(int $semesterId): void
    {
        if ($semesterId <= 0) {
            return;
        }

        $stmt = $this->pdo->prepare('
            SELECT ends_at, clearance_window_active
            FROM semesters
            WHERE id = :id
            LIMIT 1
        ');
        $stmt->execute(['id' => $semesterId]);
        $row = $stmt->fetch();
        if (!$row) {
            return;
        }

        $dueDate = is_string($row['ends_at'] ?? null) ? trim((string) $row['ends_at']) : '';
        if ($dueDate === '') {
            return;
        }

        $deadlineStatus = $this->buildSemesterDeadlineStatus(
            $dueDate,
            (int) ($row['clearance_window_active'] ?? 1)
        );
        if (!$deadlineStatus['is_expired'] || (int) ($row['clearance_window_active'] ?? 1) === 0) {
            return;
        }

        $this->pdo->prepare('
            UPDATE semesters
            SET clearance_window_active = 0
            WHERE id = :id
              AND ends_at < CURDATE()
              AND clearance_window_active = 1
        ')->execute(['id' => $semesterId]);
    }

    /**
     * @param array<string,mixed> $semester
     * @return array{
     *   has_deadline:bool,
     *   due_date:?string,
     *   due_date_label:string,
     *   is_expired:bool,
     *   is_window_open:bool,
     *   days_remaining:?int,
     *   status_label:string,
     *   banner_class:string,
     *   banner_message:string
     * }
     */
    public function getSemesterDeadlineStatus(array $semester): array
    {
        $dueDate = is_string($semester['ends_at'] ?? null) ? trim((string) $semester['ends_at']) : '';
        if ($dueDate === '') {
            return [
                'has_deadline' => false,
                'due_date' => null,
                'due_date_label' => '',
                'is_expired' => false,
                'is_window_open' => true,
                'days_remaining' => null,
                'status_label' => 'No deadline set',
                'banner_class' => 'alert-secondary',
                'banner_message' => 'No completion due date has been set for this semester.',
            ];
        }

        return $this->buildSemesterDeadlineStatus(
            $dueDate,
            (int) ($semester['clearance_window_active'] ?? 1)
        );
    }

    public function isClearanceWindowOpen(int $semesterId): bool
    {
        $stmt = $this->pdo->prepare('
            SELECT ends_at, clearance_window_active
            FROM semesters
            WHERE id = :id
            LIMIT 1
        ');
        $stmt->execute(['id' => $semesterId]);
        $row = $stmt->fetch();
        if (!$row) {
            return false;
        }

        $dueDate = is_string($row['ends_at'] ?? null) ? trim((string) $row['ends_at']) : '';
        if ($dueDate === '') {
            return true;
        }

        return $this->buildSemesterDeadlineStatus(
            $dueDate,
            (int) ($row['clearance_window_active'] ?? 1)
        )['is_window_open'];
    }

    public function processDailyDeadlineNotifications(int $semesterId): void
    {
        if ($semesterId <= 0) {
            return;
        }

        $stmt = $this->pdo->prepare('
            SELECT academic_year, term, ends_at, clearance_window_active
            FROM semesters
            WHERE id = :id
            LIMIT 1
        ');
        $stmt->execute(['id' => $semesterId]);
        $row = $stmt->fetch();
        if (!$row) {
            return;
        }

        $dueDate = is_string($row['ends_at'] ?? null) ? trim((string) $row['ends_at']) : '';
        if ($dueDate === '') {
            return;
        }

        $today = (new DateTime('today'))->format('Y-m-d');
        $logStmt = $this->pdo->prepare('
            SELECT 1
            FROM semester_deadline_notification_log
            WHERE semester_id = :semester_id
              AND notified_on = :notified_on
            LIMIT 1
        ');
        $logStmt->execute([
            'semester_id' => $semesterId,
            'notified_on' => $today,
        ]);
        if ($logStmt->fetchColumn()) {
            return;
        }

        $deadlineStatus = $this->buildSemesterDeadlineStatus(
            $dueDate,
            (int) ($row['clearance_window_active'] ?? 1)
        );
        $semesterLabel = trim((string) ($row['academic_year'] ?? '')) . ' ' . trim((string) ($row['term'] ?? ''));
        $title = 'Clearance completion deadline';
        if ($deadlineStatus['is_expired']) {
            if ($deadlineStatus['is_window_open']) {
                $body = sprintf(
                    'The original clearance deadline for %s was %s. The clearance window has been reactivated—please complete your clearance as soon as possible.',
                    $semesterLabel,
                    $deadlineStatus['due_date_label']
                );
            } else {
                $body = sprintf(
                    'The clearance completion deadline for %s was %s. The clearance window is currently closed.',
                    $semesterLabel,
                    $deadlineStatus['due_date_label']
                );
            }
        } elseif ($deadlineStatus['days_remaining'] === 0) {
            $body = sprintf(
                'Today is the clearance completion deadline for %s (%s). Please finish all pending requirements.',
                $semesterLabel,
                $deadlineStatus['due_date_label']
            );
        } else {
            $body = sprintf(
                'Reminder: complete your clearance for %s by %s (%d day(s) remaining).',
                $semesterLabel,
                $deadlineStatus['due_date_label'],
                (int) $deadlineStatus['days_remaining']
            );
        }

        $recipientIds = $this->listDeadlineNotificationRecipientIds($semesterId);
        foreach ($recipientIds as $recipientId) {
            $this->createNotification($recipientId, 'deadline_reminder', $title, $body, null);
        }

        $insertLog = $this->pdo->prepare('
            INSERT INTO semester_deadline_notification_log (semester_id, notified_on)
            VALUES (:semester_id, :notified_on)
        ');
        $insertLog->execute([
            'semester_id' => $semesterId,
            'notified_on' => $today,
        ]);
    }

    public function addRequirement(
        int $semesterId,
        int $officeId,
        string $title,
        string $description,
        ?array $attachmentFile = null
    ): array
    {
        $title = trim($title);
        if ($title === '') {
            return ['ok' => false, 'message' => 'Title is required.'];
        }
        $attachment = $this->storeRequirementAttachment($attachmentFile, $officeId, $semesterId);
        if ($attachment['ok'] === false) {
            return $attachment;
        }
        $stmt = $this->pdo->prepare("
            INSERT INTO office_requirements (
                semester_id, office_id, title, description, is_required, is_active, attachment_path, attachment_name
            )
            VALUES (:semester_id, :office_id, :title, :description, 1, 1, :attachment_path, :attachment_name)
        ");
        $stmt->execute([
            'semester_id' => $semesterId,
            'office_id' => $officeId,
            'title' => $title,
            'description' => $description,
            'attachment_path' => $attachment['path'],
            'attachment_name' => $attachment['name'],
        ]);
        return ['ok' => true, 'message' => 'Requirement added.'];
    }

    public function updateRequirement(
        int $requirementId,
        int $semesterId,
        int $officeId,
        string $title,
        string $description,
        ?array $attachmentFile = null,
        bool $removeAttachment = false
    ): array {
        $title = trim($title);
        if ($requirementId <= 0) {
            return ['ok' => false, 'message' => 'Invalid requirement.'];
        }
        if ($officeId <= 0) {
            return ['ok' => false, 'message' => 'Invalid office.'];
        }
        if ($title === '') {
            return ['ok' => false, 'message' => 'Title is required.'];
        }

        $attachment = $this->storeRequirementAttachment($attachmentFile, $officeId, $semesterId);
        if ($attachment['ok'] === false) {
            return $attachment;
        }

        $sql = "
            UPDATE office_requirements
            SET office_id = :office_id,
                title = :title,
                description = :description,
                updated_at = CURRENT_TIMESTAMP
        ";
        $bindings = [
            'office_id' => $officeId,
            'title' => $title,
            'description' => $description,
            'id' => $requirementId,
            'semester_id' => $semesterId,
        ];
        if ($removeAttachment) {
            $sql .= ",
                attachment_path = NULL,
                attachment_name = NULL
            ";
        } elseif ($attachment['path'] !== null) {
            $sql .= ",
                attachment_path = :attachment_path,
                attachment_name = :attachment_name
            ";
            $bindings['attachment_path'] = $attachment['path'];
            $bindings['attachment_name'] = $attachment['name'];
        }
        $sql .= "
            WHERE id = :id
              AND semester_id = :semester_id
              AND is_active = 1
            LIMIT 1
        ";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($bindings);
        
        if ($stmt->rowCount() <= 0) {
            return ['ok' => false, 'message' => 'Requirement not found or no changes made.'];
        }

        return ['ok' => true, 'message' => 'Requirement updated.'];
    }

    public function deleteRequirement(int $requirementId, int $semesterId): array
    {
        if ($requirementId <= 0) {
            return ['ok' => false, 'message' => 'Invalid requirement.'];
        }

        $stmt = $this->pdo->prepare("
            UPDATE office_requirements
            SET is_active = 0,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :id
              AND semester_id = :semester_id
              AND is_active = 1
            LIMIT 1
        ");
        $stmt->execute([
            'id' => $requirementId,
            'semester_id' => $semesterId,
        ]);

        if ($stmt->rowCount() <= 0) {
            return ['ok' => false, 'message' => 'Requirement not found.'];
        }

        return ['ok' => true, 'message' => 'Requirement deleted.'];
    }

    public function updateOfficeRequirementByOwner(
        int $requirementId,
        int $semesterId,
        int $officeId,
        string $title,
        string $description,
        ?array $attachmentFile = null,
        bool $removeAttachment = false
    ): array {
        if ($requirementId <= 0 || $officeId <= 0) {
            return ['ok' => false, 'message' => 'Invalid requirement.'];
        }
        $ownershipStmt = $this->pdo->prepare("
            SELECT 1
            FROM office_requirements
            WHERE id = :id
              AND semester_id = :semester_id
              AND office_id = :office_id
              AND is_active = 1
            LIMIT 1
        ");
        $ownershipStmt->execute([
            'id' => $requirementId,
            'semester_id' => $semesterId,
            'office_id' => $officeId,
        ]);
        if (!$ownershipStmt->fetchColumn()) {
            return ['ok' => false, 'message' => 'Requirement not found for your office.'];
        }
        return $this->updateRequirement(
            $requirementId,
            $semesterId,
            $officeId,
            $title,
            $description,
            $attachmentFile,
            $removeAttachment
        );
    }

    public function deleteOfficeRequirementByOwner(int $requirementId, int $semesterId, int $officeId): array
    {
        if ($requirementId <= 0 || $officeId <= 0) {
            return ['ok' => false, 'message' => 'Invalid requirement.'];
        }
        $stmt = $this->pdo->prepare("
            UPDATE office_requirements
            SET is_active = 0,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :id
              AND office_id = :office_id
              AND semester_id = :semester_id
              AND is_active = 1
            LIMIT 1
        ");
        $stmt->execute([
            'id' => $requirementId,
            'office_id' => $officeId,
            'semester_id' => $semesterId,
        ]);
        if ($stmt->rowCount() <= 0) {
            return ['ok' => false, 'message' => 'Requirement not found for your office.'];
        }
        return ['ok' => true, 'message' => 'Requirement deleted.'];
    }

    public function assignSignatory(int $semesterId, int $officeId, int $userId): array
    {
        if ($officeId <= 0 || $userId <= 0) {
            return ['ok' => false, 'message' => 'Choose an office and a signatory.'];
        }
        $roleCheck = $this->pdo->prepare("
            SELECT 1 FROM users WHERE id = :id AND role = 'signatory' AND is_active = 1 LIMIT 1
        ");
        $roleCheck->execute(['id' => $userId]);
        if (!$roleCheck->fetchColumn()) {
            return ['ok' => false, 'message' => 'Invalid signatory user.'];
        }
        $stmt = $this->pdo->prepare("
            INSERT INTO office_signatories (office_id, user_id, semester_id)
            VALUES (:office_id, :user_id, :semester_id)
            ON DUPLICATE KEY UPDATE assigned_at = CURRENT_TIMESTAMP
        ");
        $stmt->execute([
            'office_id' => $officeId,
            'user_id' => $userId,
            'semester_id' => $semesterId,
        ]);
        return ['ok' => true, 'message' => 'Signatory assigned.'];
    }

    public function listActiveColleges(): array
    {
        return $this->pdo->query("
            SELECT id, code, name
            FROM colleges
            WHERE is_active = 1
            ORDER BY name
        ")->fetchAll();
    }

    /**
     * @return array<int, list<array{id:int, code:string, name:string}>>
     */
    public function programsGroupedByCollegeId(): array
    {
        $stmt = $this->pdo->query("
            SELECT id, college_id, code, name
            FROM programs
            WHERE is_active = 1
            ORDER BY name
        ");
        $grouped = [];
        foreach ($stmt->fetchAll() as $row) {
            $collegeId = (int) $row['college_id'];
            $grouped[$collegeId][] = [
                'id' => (int) $row['id'],
                'code' => (string) $row['code'],
                'name' => (string) $row['name'],
            ];
        }
        return $grouped;
    }

    /**
     * @return array{ok:bool, message:string, value:?string}
     */
    private function normalizeStudentYearLevel(string $raw): array
    {
        $v = strtoupper(trim($raw));
        if ($v === '') {
            return ['ok' => false, 'message' => 'Year level is required.', 'value' => null];
        }
        if (preg_match('/^[1-4]$/', $v)) {
            return ['ok' => true, 'message' => '', 'value' => $v];
        }
        if ($v === '5' || $v === '5+') {
            return ['ok' => true, 'message' => '', 'value' => '5+'];
        }

        return ['ok' => false, 'message' => 'Year level must be 1, 2, 3, 4, or 5+.', 'value' => null];
    }

    private function normalizeQueueYearLevelFilter(?string $raw): ?string
    {
        if ($raw === null) {
            return null;
        }
        $v = strtoupper(trim($raw));
        if ($v === '' || $v === '0') {
            return null;
        }
        if (preg_match('/^[1-4]$/', $v)) {
            return $v;
        }
        if ($v === '5' || $v === '5+') {
            return '5+';
        }

        return null;
    }

    private function normalizeQueueSearchNameFilter(?string $raw): ?string
    {
        if ($raw === null) {
            return null;
        }
        $v = trim($raw);
        if ($v === '') {
            return null;
        }
        if (strlen($v) > 100) {
            $v = substr($v, 0, 100);
        }

        return $v;
    }

    private function normalizeQueueStatusFilter(?string $raw): ?string
    {
        if ($raw === null) {
            return null;
        }
        $v = strtolower(trim($raw));
        if ($v === 'approved') {
            $v = 'cleared';
        } elseif ($v === 'disapproved') {
            $v = 'rejected';
        }
        if (in_array($v, ['for_review', 'cleared', 'rejected'], true)) {
            return $v;
        }

        return null;
    }

    private function queueSearchLikePattern(string $term): string
    {
        $escaped = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $term);

        return '%' . $escaped . '%';
    }

    /**
     * @return array{ok:bool, message:string, value:?string}
     */
    private function normalizeStudentAccountType(string $raw): array
    {
        $v = strtolower(trim($raw));
        $v = preg_replace('/[\s\-]+/', '_', $v) ?? $v;
        if ($v === '') {
            return ['ok' => false, 'message' => 'Student account type is required.', 'value' => null];
        }
        if (in_array($v, ['paying_tuition', 'paying', 'paying_tuition_student'], true)) {
            return ['ok' => true, 'message' => '', 'value' => 'paying_tuition'];
        }
        if (in_array($v, ['not_paying_tuition', 'not_paying', 'not_paying_tuition_student'], true)) {
            return ['ok' => true, 'message' => '', 'value' => 'not_paying_tuition'];
        }

        return ['ok' => false, 'message' => 'Student account type must be Paying Tuition or Not Paying Tuition.', 'value' => null];
    }

    /**
     * @return array{ok:bool, message:string, value:?string}
     */
    private function normalizeStudentOrgPosition(string $raw): array
    {
        $v = strtolower(trim($raw));
        $v = preg_replace('/[\s\-]+/', '_', $v) ?? $v;
        if ($v === '') {
            return ['ok' => false, 'message' => 'Student org. position is required.', 'value' => null];
        }
        $map = [
            'president' => 'president',
            'vice_president' => 'vice_president',
            'vicepresident' => 'vice_president',
            'treasurer' => 'treasurer',
            'secretary' => 'secretary',
            'auditor' => 'auditor',
            'na' => 'na',
            'n_a' => 'na',
            'none' => 'na',
        ];
        if (isset($map[$v])) {
            return ['ok' => true, 'message' => '', 'value' => $map[$v]];
        }

        return ['ok' => false, 'message' => 'Student org. position must be President, Vice-President, Treasurer, Secretary, Auditor, or N/A.', 'value' => null];
    }

    /**
     * @return array{ok:bool, message:string, value:?string}
     */
    private function normalizeStudentStaying(string $raw): array
    {
        $v = strtolower(trim($raw));
        $v = preg_replace('/[\s\-]+/', '_', $v) ?? $v;
        if ($v === '') {
            return ['ok' => false, 'message' => 'Students staying is required.', 'value' => null];
        }
        $map = [
            'wpu_dormitory' => 'wpu_dormitory',
            'wpu_dorm' => 'wpu_dormitory',
            'outside_dormitory' => 'outside_dormitory',
            'outside_dorm' => 'outside_dormitory',
            'commuter' => 'commuter',
        ];
        if (isset($map[$v])) {
            return ['ok' => true, 'message' => '', 'value' => $map[$v]];
        }

        return ['ok' => false, 'message' => 'Students staying must be WPU Dormitory, Outside Dormitory, or Commuter.', 'value' => null];
    }

    /**
     * @return array<string, string>
     */
    public static function campusOptions(): array
    {
        return [
            'puerto_princesa' => 'Puerto Princesa City Campus',
            'quezon' => 'Quezon Campus',
            'rio_tuba' => 'Rio Tuba Extension School',
            'el_nido' => 'El Nido Campus',
            'canique' => 'Canique Extension School',
            'busuanga' => 'Busuanga Campus',
            'aborlan' => 'Aborlan Main Campus',
        ];
    }

    public static function campusDisplayLabel(?string $campus): string
    {
        $t = trim((string) $campus);
        $labels = self::campusOptions();

        return $labels[$t] ?? '';
    }

    /**
     * @return array{ok:bool, message:string, value:?string}
     */
    private function normalizeStudentCampus(string $raw): array
    {
        $v = strtolower(trim($raw));
        $v = preg_replace('/[\s\-]+/', '_', $v) ?? $v;
        if ($v === '') {
            return ['ok' => false, 'message' => 'Campus is required.', 'value' => null];
        }
        $map = [
            'puerto_princesa' => 'puerto_princesa',
            'puerto_princesa_city' => 'puerto_princesa',
            'puerto_princesa_city_campus' => 'puerto_princesa',
            'ppc' => 'puerto_princesa',
            'ppc_campus' => 'puerto_princesa',
            'quezon' => 'quezon',
            'quezon_campus' => 'quezon',
            'rio_tuba' => 'rio_tuba',
            'rio_tuba_extension' => 'rio_tuba',
            'rio_tuba_extension_school' => 'rio_tuba',
            'el_nido' => 'el_nido',
            'el_nido_campus' => 'el_nido',
            'canique' => 'canique',
            'canique_extension' => 'canique',
            'canique_extension_school' => 'canique',
            'busuanga' => 'busuanga',
            'busuanga_campus' => 'busuanga',
            'aborlan' => 'aborlan',
            'aborlan_main' => 'aborlan',
            'aborlan_main_campus' => 'aborlan',
            'aborlan_campus' => 'aborlan',
        ];
        if (isset($map[$v])) {
            return ['ok' => true, 'message' => '', 'value' => $map[$v]];
        }

        return ['ok' => false, 'message' => 'Campus must be Puerto Princesa City Campus, Quezon Campus, Rio Tuba Extension School, El Nido Campus, Canique Extension School, Busuanga Campus, or Aborlan Main Campus.', 'value' => null];
    }

    public function registerStudentWithCollegeProgram(
        string $studentNo,
        string $firstName,
        string $lastName,
        string $email,
        string $password,
        int $collegeId,
        int $programId,
        string $yearLevel,
        string $studentAccountType,
        string $studentOrgPosition,
        string $studentStaying,
        string $campus,
        bool $pendingAdminApproval = false
    ): array {
        $studentNo = trim($studentNo);
        $firstName = trim($firstName);
        $lastName = trim($lastName);
        $email = strtolower(trim($email));

        if ($pendingAdminApproval) {
            $idNorm = $this->normalizeStudentId($studentNo);
            if (!$idNorm['ok']) {
                return ['ok' => false, 'message' => $idNorm['message']];
            }
            $studentNo = (string) $idNorm['value'];
        }

        if ($studentNo === '' || $firstName === '' || $lastName === '' || $email === '') {
            return ['ok' => false, 'message' => 'Student number, name fields, and email are required.'];
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['ok' => false, 'message' => 'Invalid email address.'];
        }
        if (strlen($password) < 8) {
            return ['ok' => false, 'message' => 'Password must be at least 8 characters.'];
        }
        if ($collegeId <= 0 || $programId <= 0) {
            return ['ok' => false, 'message' => 'College and program are required.'];
        }
        $ylNorm = $this->normalizeStudentYearLevel($yearLevel);
        if (!$ylNorm['ok']) {
            return ['ok' => false, 'message' => $ylNorm['message']];
        }
        $acctNorm = $this->normalizeStudentAccountType($studentAccountType);
        if (!$acctNorm['ok']) {
            return ['ok' => false, 'message' => $acctNorm['message']];
        }
        $orgNorm = $this->normalizeStudentOrgPosition($studentOrgPosition);
        if (!$orgNorm['ok']) {
            return ['ok' => false, 'message' => $orgNorm['message']];
        }
        $stayingNorm = $this->normalizeStudentStaying($studentStaying);
        if (!$stayingNorm['ok']) {
            return ['ok' => false, 'message' => $stayingNorm['message']];
        }
        $campusNorm = $this->normalizeStudentCampus($campus);
        if (!$campusNorm['ok']) {
            return ['ok' => false, 'message' => $campusNorm['message']];
        }

        $validProgram = $this->pdo->prepare("
            SELECT 1
            FROM programs p
            INNER JOIN colleges c ON c.id = p.college_id AND c.is_active = 1
            WHERE p.id = :program_id
              AND p.college_id = :college_id
              AND p.is_active = 1
            LIMIT 1
        ");
        $validProgram->execute([
            'program_id' => $programId,
            'college_id' => $collegeId,
        ]);
        if (!$validProgram->fetchColumn()) {
            return ['ok' => false, 'message' => 'Program does not match the selected college or is inactive.'];
        }

        $dupEmail = $this->pdo->prepare('SELECT 1 FROM users WHERE email = :email LIMIT 1');
        $dupEmail->execute(['email' => $email]);
        if ($dupEmail->fetchColumn()) {
            return ['ok' => false, 'message' => 'That email is already registered.'];
        }

        $dupNo = $this->pdo->prepare('SELECT 1 FROM users WHERE student_no = :sn LIMIT 1');
        $dupNo->execute(['sn' => $studentNo]);
        if ($dupNo->fetchColumn()) {
            return ['ok' => false, 'message' => 'That student number is already in use.'];
        }

        $hash = PasswordHasher::hash($password);
        $insert = $this->pdo->prepare("
            INSERT INTO users
                (student_no, first_name, last_name, email, password_hash, role, college_id, program_id, campus, year_level, student_account_type, student_org_position, student_staying, is_active, registration_status)
            VALUES
                (:student_no, :first_name, :last_name, :email, :password_hash, 'student', :college_id, :program_id, :campus, :year_level, :student_account_type, :student_org_position, :student_staying, :is_active, :registration_status)
        ");
        $insert->execute([
            'student_no' => $studentNo,
            'first_name' => $firstName,
            'last_name' => $lastName,
            'email' => $email,
            'password_hash' => $hash,
            'college_id' => $collegeId,
            'program_id' => $programId,
            'campus' => $campusNorm['value'],
            'year_level' => $ylNorm['value'],
            'student_account_type' => $acctNorm['value'],
            'student_org_position' => $orgNorm['value'],
            'student_staying' => $stayingNorm['value'],
            'is_active' => $pendingAdminApproval ? 0 : 1,
            'registration_status' => $pendingAdminApproval ? 'pending' : 'approved',
        ]);

        if ($pendingAdminApproval) {
            return ['ok' => true, 'message' => 'Registration submitted. An administrator must approve your Student ID before you can sign in.'];
        }

        return ['ok' => true, 'message' => 'Student registered successfully. They can sign in with the email and password you set.'];
    }

    /**
     * @return array{ok:bool, message:string, value:?string}
     */
    public function normalizeStudentId(string $studentNo): array
    {
        $studentNo = trim($studentNo);
        if (!preg_match('/^(20\d{2})-(\d{4})$/', $studentNo, $matches)) {
            return [
                'ok' => false,
                'message' => 'Enter a valid Student ID such as 2025-0001 (year, a hyphen, then four digits).',
                'value' => null,
            ];
        }
        $year = (int) $matches[1];
        $maxYear = (int) date('Y') + 1;
        if ($year < 2000 || $year > $maxYear) {
            return [
                'ok' => false,
                'message' => 'That Student ID year is not valid.',
                'value' => null,
            ];
        }

        return ['ok' => true, 'message' => '', 'value' => $studentNo];
    }

    public function countPendingStudentRegistrations(): int
    {
        return (int) $this->pdo->query("
            SELECT COUNT(*)
            FROM users
            WHERE role = 'student' AND registration_status = 'pending'
        ")->fetchColumn();
    }

    public function reviewStudentRegistration(int $studentId, bool $approve): array
    {
        if ($studentId <= 0) {
            return ['ok' => false, 'message' => 'Invalid student.'];
        }
        $stmt = $this->pdo->prepare("
            SELECT registration_status
            FROM users
            WHERE id = :id AND role = 'student'
            LIMIT 1
        ");
        $stmt->execute(['id' => $studentId]);
        $status = $stmt->fetchColumn();
        if ($status === false) {
            return ['ok' => false, 'message' => 'Student not found.'];
        }
        $status = (string) $status;
        if ($approve) {
            if ($status === 'approved') {
                return ['ok' => false, 'message' => 'This student is already approved.'];
            }
            $update = $this->pdo->prepare("
                UPDATE users
                SET registration_status = 'approved', is_active = 1
                WHERE id = :id AND role = 'student'
                LIMIT 1
            ");
            $update->execute(['id' => $studentId]);

            return ['ok' => true, 'message' => 'Registration approved. The student can now sign in.'];
        }
        if ($status !== 'pending') {
            return ['ok' => false, 'message' => 'Only a pending registration can be rejected.'];
        }
        $update = $this->pdo->prepare("
            UPDATE users
            SET registration_status = 'rejected', is_active = 0
            WHERE id = :id AND role = 'student' AND registration_status = 'pending'
            LIMIT 1
        ");
        $update->execute(['id' => $studentId]);

        return ['ok' => true, 'message' => 'Registration rejected. The student cannot sign in.'];
    }

    public function registerStudentWithCollegeProgramByCodes(
        string $studentNo,
        string $firstName,
        string $lastName,
        string $email,
        string $password,
        string $collegeCode,
        string $programCode,
        string $yearLevel,
        string $studentAccountType = 'paying_tuition',
        string $studentOrgPosition = 'na',
        string $studentStaying = 'commuter',
        string $campus = ''
    ): array {
        $collegeCode = strtoupper(trim($collegeCode));
        $programCode = strtoupper(trim($programCode));
        $colStmt = $this->pdo->prepare('SELECT id FROM colleges WHERE code = :code AND is_active = 1 LIMIT 1');
        $colStmt->execute(['code' => $collegeCode]);
        $collegeId = (int) $colStmt->fetchColumn();
        if ($collegeId <= 0) {
            return ['ok' => false, 'message' => 'Unknown college code: ' . $collegeCode];
        }
        $progStmt = $this->pdo->prepare("
            SELECT p.id
            FROM programs p
            INNER JOIN colleges c ON c.id = p.college_id AND c.is_active = 1
            WHERE p.college_id = :college_id
              AND p.code = :program_code
              AND p.is_active = 1
            LIMIT 1
        ");
        $progStmt->execute([
            'college_id' => $collegeId,
            'program_code' => $programCode,
        ]);
        $programId = (int) $progStmt->fetchColumn();
        if ($programId <= 0) {
            return ['ok' => false, 'message' => 'Unknown program code "' . $programCode . '" for college ' . $collegeCode];
        }

        return $this->registerStudentWithCollegeProgram(
            $studentNo,
            $firstName,
            $lastName,
            $email,
            $password,
            $collegeId,
            $programId,
            $yearLevel,
            $studentAccountType,
            $studentOrgPosition,
            $studentStaying,
            $campus
        );
    }

    public function listAllStudentsForAdmin(int $semesterId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT
                u.id,
                u.student_no,
                u.first_name,
                u.last_name,
                u.email,
                u.is_active,
                u.registration_status,
                u.created_at,
                u.college_id,
                u.program_id,
                u.year_level,
                u.student_account_type,
                u.student_org_position,
                u.student_staying,
                u.campus,
                c.name AS college_name,
                pr.name AS program_name,
                COALESCE(ssc.overall_status, 'pending') AS overall_status
            FROM users u
            LEFT JOIN colleges c ON c.id = u.college_id
            LEFT JOIN programs pr ON pr.id = u.program_id
            LEFT JOIN student_semester_clearances ssc
                ON ssc.student_id = u.id AND ssc.semester_id = :semester_id
            WHERE u.role = 'student'
            ORDER BY
                CASE u.registration_status
                    WHEN 'pending' THEN 0
                    WHEN 'rejected' THEN 1
                    ELSE 2
                END,
                u.is_active DESC,
                u.last_name,
                u.first_name
        ");
        $stmt->execute(['semester_id' => $semesterId]);

        return $stmt->fetchAll();
    }

    public function getStudentByIdForAdmin(int $id): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT id, student_no, first_name, last_name, email, college_id, program_id, campus, year_level, student_account_type, student_org_position, student_staying, is_active
            FROM users
            WHERE id = :id AND role = 'student'
            LIMIT 1
        ");
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();

        return $row ?: null;
    }

    public function updateStudentByAdmin(
        int $studentId,
        string $studentNo,
        string $firstName,
        string $lastName,
        string $email,
        int $collegeId,
        int $programId,
        string $yearLevel,
        string $studentAccountType,
        string $studentOrgPosition,
        string $studentStaying,
        string $campus,
        ?string $newPassword
    ): array {
        $studentNo = trim($studentNo);
        $firstName = trim($firstName);
        $lastName = trim($lastName);
        $email = strtolower(trim($email));
        if ($studentId <= 0 || $studentNo === '' || $firstName === '' || $lastName === '' || $email === '') {
            return ['ok' => false, 'message' => 'Student number, name fields, and email are required.'];
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['ok' => false, 'message' => 'Invalid email address.'];
        }
        if ($collegeId <= 0 || $programId <= 0) {
            return ['ok' => false, 'message' => 'College and program are required.'];
        }
        $ylNorm = $this->normalizeStudentYearLevel($yearLevel);
        if (!$ylNorm['ok']) {
            return ['ok' => false, 'message' => $ylNorm['message']];
        }
        $acctNorm = $this->normalizeStudentAccountType($studentAccountType);
        if (!$acctNorm['ok']) {
            return ['ok' => false, 'message' => $acctNorm['message']];
        }
        $orgNorm = $this->normalizeStudentOrgPosition($studentOrgPosition);
        if (!$orgNorm['ok']) {
            return ['ok' => false, 'message' => $orgNorm['message']];
        }
        $stayingNorm = $this->normalizeStudentStaying($studentStaying);
        if (!$stayingNorm['ok']) {
            return ['ok' => false, 'message' => $stayingNorm['message']];
        }
        $campusNorm = $this->normalizeStudentCampus($campus);
        if (!$campusNorm['ok']) {
            return ['ok' => false, 'message' => $campusNorm['message']];
        }
        $exists = $this->pdo->prepare("SELECT 1 FROM users WHERE id = :id AND role = 'student' LIMIT 1");
        $exists->execute(['id' => $studentId]);
        if (!$exists->fetchColumn()) {
            return ['ok' => false, 'message' => 'Student not found.'];
        }
        $validProgram = $this->pdo->prepare("
            SELECT 1
            FROM programs p
            INNER JOIN colleges c ON c.id = p.college_id AND c.is_active = 1
            WHERE p.id = :program_id
              AND p.college_id = :college_id
              AND p.is_active = 1
            LIMIT 1
        ");
        $validProgram->execute([
            'program_id' => $programId,
            'college_id' => $collegeId,
        ]);
        if (!$validProgram->fetchColumn()) {
            return ['ok' => false, 'message' => 'Program does not match the selected college or is inactive.'];
        }
        $dupEmail = $this->pdo->prepare('SELECT 1 FROM users WHERE email = :email AND id != :id LIMIT 1');
        $dupEmail->execute(['email' => $email, 'id' => $studentId]);
        if ($dupEmail->fetchColumn()) {
            return ['ok' => false, 'message' => 'That email is already used by another account.'];
        }
        $dupNo = $this->pdo->prepare('SELECT 1 FROM users WHERE student_no = :sn AND id != :id LIMIT 1');
        $dupNo->execute(['sn' => $studentNo, 'id' => $studentId]);
        if ($dupNo->fetchColumn()) {
            return ['ok' => false, 'message' => 'That student number is already in use.'];
        }
        if ($newPassword !== null && $newPassword !== '') {
            if (strlen($newPassword) < 8) {
                return ['ok' => false, 'message' => 'New password must be at least 8 characters.'];
            }
            $hash = PasswordHasher::hash($newPassword);
            $stmt = $this->pdo->prepare("
                UPDATE users SET
                    student_no = :student_no,
                    first_name = :first_name,
                    last_name = :last_name,
                    email = :email,
                    college_id = :college_id,
                    program_id = :program_id,
                    year_level = :year_level,
                    student_account_type = :student_account_type,
                    student_org_position = :student_org_position,
                    student_staying = :student_staying,
                    campus = :campus,
                    password_hash = :ph
                WHERE id = :id AND role = 'student'
                LIMIT 1
            ");
            $stmt->execute([
                'student_no' => $studentNo,
                'first_name' => $firstName,
                'last_name' => $lastName,
                'email' => $email,
                'college_id' => $collegeId,
                'program_id' => $programId,
                'year_level' => $ylNorm['value'],
                'student_account_type' => $acctNorm['value'],
                'student_org_position' => $orgNorm['value'],
                'student_staying' => $stayingNorm['value'],
                'campus' => $campusNorm['value'],
                'ph' => $hash,
                'id' => $studentId,
            ]);
        } else {
            $stmt = $this->pdo->prepare("
                UPDATE users SET
                    student_no = :student_no,
                    first_name = :first_name,
                    last_name = :last_name,
                    email = :email,
                    college_id = :college_id,
                    program_id = :program_id,
                    year_level = :year_level,
                    student_account_type = :student_account_type,
                    student_org_position = :student_org_position,
                    student_staying = :student_staying,
                    campus = :campus
                WHERE id = :id AND role = 'student'
                LIMIT 1
            ");
            $stmt->execute([
                'student_no' => $studentNo,
                'first_name' => $firstName,
                'last_name' => $lastName,
                'email' => $email,
                'college_id' => $collegeId,
                'program_id' => $programId,
                'year_level' => $ylNorm['value'],
                'student_account_type' => $acctNorm['value'],
                'student_org_position' => $orgNorm['value'],
                'student_staying' => $stayingNorm['value'],
                'campus' => $campusNorm['value'],
                'id' => $studentId,
            ]);
        }

        return ['ok' => true, 'message' => 'Student updated.'];
    }

    public function setStudentActive(int $id, bool $active): array
    {
        if ($id <= 0) {
            return ['ok' => false, 'message' => 'Invalid student.'];
        }
        if ($active) {
            $stmt = $this->pdo->prepare("
                UPDATE users
                SET is_active = 1
                WHERE id = :id AND role = 'student' AND registration_status = 'approved'
                LIMIT 1
            ");
            $stmt->execute(['id' => $id]);
            if ($stmt->rowCount() === 0) {
                return ['ok' => false, 'message' => 'Only an approved student can be reactivated. Use Approve for a pending registration.'];
            }

            return ['ok' => true, 'message' => 'Student reactivated.'];
        }
        $stmt = $this->pdo->prepare("
            UPDATE users SET is_active = 0 WHERE id = :id AND role = 'student' LIMIT 1
        ");
        $stmt->execute(['id' => $id]);
        if ($stmt->rowCount() === 0) {
            return ['ok' => false, 'message' => 'Student not found.'];
        }

        return ['ok' => true, 'message' => $active ? 'Student reactivated.' : 'Student deactivated.'];
    }

    /**
     * @param list<int|string> $studentIds
     */
    public function deleteStudentsByAdmin(array $studentIds): array
    {
        $ids = array_values(array_unique(array_filter(
            array_map(static fn ($id): int => (int) $id, $studentIds),
            static fn (int $id): bool => $id > 0
        )));
        if ($ids === []) {
            return ['ok' => false, 'message' => 'No students selected.'];
        }

        $deleted = 0;
        $notFound = 0;
        try {
            $this->pdo->beginTransaction();
            foreach ($ids as $id) {
                if ($this->purgeStudentAccount($id)) {
                    $deleted++;
                } else {
                    $notFound++;
                }
            }
            $this->pdo->commit();
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }

            return ['ok' => false, 'message' => 'Could not delete students. Please try again.'];
        }

        if ($deleted === 0) {
            return ['ok' => false, 'message' => 'No student accounts were deleted.'];
        }

        $message = 'Deleted ' . $deleted . ' student account' . ($deleted === 1 ? '' : 's') . '.';
        if ($notFound > 0) {
            $message .= ' ' . $notFound . ' not found or already removed.';
        }

        return ['ok' => true, 'message' => $message];
    }

    public function deleteAllStudentsByAdmin(): array
    {
        $ids = array_map(
            static fn ($id): int => (int) $id,
            $this->pdo->query("SELECT id FROM users WHERE role = 'student'")->fetchAll(\PDO::FETCH_COLUMN)
        );
        if ($ids === []) {
            return ['ok' => false, 'message' => 'No student accounts to delete.'];
        }

        return $this->deleteStudentsByAdmin($ids);
    }

    private function purgeStudentAccount(int $studentId): bool
    {
        $chk = $this->pdo->prepare("
            SELECT profile_photo_path
            FROM users
            WHERE id = :id AND role = 'student'
            LIMIT 1
        ");
        $chk->execute(['id' => $studentId]);
        $row = $chk->fetch();
        if (!$row) {
            return false;
        }
        $photoPath = trim((string) ($row['profile_photo_path'] ?? ''));

        $clrStmt = $this->pdo->prepare('SELECT id FROM student_clearances WHERE student_id = :sid');
        $clrStmt->execute(['sid' => $studentId]);
        $clearanceIds = array_map(
            static fn ($id): int => (int) $id,
            $clrStmt->fetchAll(\PDO::FETCH_COLUMN)
        );
        if ($clearanceIds !== []) {
            $placeholders = implode(',', array_fill(0, count($clearanceIds), '?'));
            $this->pdo->prepare("DELETE FROM notifications WHERE related_clearance_id IN ($placeholders)")
                ->execute($clearanceIds);
        }

        $this->pdo->prepare('DELETE FROM notifications WHERE user_id = :uid')
            ->execute(['uid' => $studentId]);
        $this->pdo->prepare('DELETE FROM clearance_message_threads WHERE student_id = :sid')
            ->execute(['sid' => $studentId]);
        $this->pdo->prepare('DELETE FROM clearance_message_thread_reads WHERE user_id = :uid')
            ->execute(['uid' => $studentId]);

        $subStmt = $this->pdo->prepare('SELECT file_path FROM requirement_submissions WHERE student_id = :sid');
        $subStmt->execute(['sid' => $studentId]);
        foreach ($subStmt->fetchAll(\PDO::FETCH_COLUMN) as $filePath) {
            $this->deleteStoredSubmissionFile((string) $filePath);
        }
        $this->pdo->prepare('DELETE FROM requirement_submissions WHERE student_id = :sid')
            ->execute(['sid' => $studentId]);

        if ($this->tableExists('student_office_requirements')) {
            $this->pdo->prepare('DELETE FROM student_office_requirements WHERE student_id = :sid')
                ->execute(['sid' => $studentId]);
            $this->pdo->prepare('UPDATE student_office_requirements SET created_by = NULL WHERE created_by = :uid')
                ->execute(['uid' => $studentId]);
        }

        if ($this->tableExists('final_clearance_signatures')) {
            $sigStmt = $this->pdo->prepare('SELECT signature_file FROM final_clearance_signatures WHERE student_id = :sid');
            $sigStmt->execute(['sid' => $studentId]);
            foreach ($sigStmt->fetchAll(\PDO::FETCH_COLUMN) as $filePath) {
                $this->deleteStoredSubmissionFile((string) $filePath);
            }
            $this->pdo->prepare('DELETE FROM final_clearance_signatures WHERE student_id = :sid')
                ->execute(['sid' => $studentId]);
        }

        $this->pdo->prepare('DELETE FROM student_clearances WHERE student_id = :sid')
            ->execute(['sid' => $studentId]);
        $this->pdo->prepare('DELETE FROM student_semester_clearances WHERE student_id = :sid')
            ->execute(['sid' => $studentId]);

        $del = $this->pdo->prepare("DELETE FROM users WHERE id = :id AND role = 'student' LIMIT 1");
        $del->execute(['id' => $studentId]);
        if ($del->rowCount() === 0) {
            return false;
        }

        if ($photoPath !== '') {
            $this->deleteStoredProfilePhoto($photoPath);
        }

        return true;
    }

    private function tableExists(string $table): bool
    {
        static $cache = [];
        if (array_key_exists($table, $cache)) {
            return $cache[$table];
        }
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*) FROM information_schema.TABLES
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :tbl'
        );
        $stmt->execute(['tbl' => $table]);

        return $cache[$table] = (int) $stmt->fetchColumn() > 0;
    }

    public function listCollegesForAdmin(): array
    {
        return $this->pdo->query("
            SELECT id, code, name, is_active
            FROM colleges
            ORDER BY name
        ")->fetchAll();
    }

    public function listProgramsForAdmin(): array
    {
        return $this->pdo->query("
            SELECT p.id, p.college_id, p.code, p.name, p.is_active, c.name AS college_name
            FROM programs p
            INNER JOIN colleges c ON c.id = p.college_id
            ORDER BY c.name, p.name
        ")->fetchAll();
    }

    public function getProgramByIdForAdmin(int $id): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT id, college_id, code, name, is_active
            FROM programs
            WHERE id = :id
            LIMIT 1
        ");
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();

        return $row ?: null;
    }

    public function addCollege(string $code, string $name): array
    {
        $code = strtoupper(trim($code));
        $name = trim($name);
        if ($code === '' || $name === '') {
            return ['ok' => false, 'message' => 'College code and name are required.'];
        }
        if (strlen($code) > 40 || strlen($name) > 191) {
            return ['ok' => false, 'message' => 'Code or name is too long.'];
        }
        $dup = $this->pdo->prepare('SELECT 1 FROM colleges WHERE code = :code LIMIT 1');
        $dup->execute(['code' => $code]);
        if ($dup->fetchColumn()) {
            return ['ok' => false, 'message' => 'A college with that code already exists.'];
        }
        $stmt = $this->pdo->prepare('
            INSERT INTO colleges (code, name, is_active) VALUES (:code, :name, 1)
        ');
        $stmt->execute(['code' => $code, 'name' => $name]);
        return ['ok' => true, 'message' => 'College added.'];
    }

    public function addProgram(int $collegeId, string $code, string $name): array
    {
        $code = strtoupper(trim($code));
        $name = trim($name);
        if ($collegeId <= 0) {
            return ['ok' => false, 'message' => 'Select a college.'];
        }
        if ($code === '' || $name === '') {
            return ['ok' => false, 'message' => 'Program code and name are required.'];
        }
        if (strlen($code) > 40 || strlen($name) > 191) {
            return ['ok' => false, 'message' => 'Code or name is too long.'];
        }
        $collegeOk = $this->pdo->prepare('SELECT 1 FROM colleges WHERE id = :id AND is_active = 1 LIMIT 1');
        $collegeOk->execute(['id' => $collegeId]);
        if (!$collegeOk->fetchColumn()) {
            return ['ok' => false, 'message' => 'College not found or inactive.'];
        }
        $dup = $this->pdo->prepare('
            SELECT 1 FROM programs WHERE college_id = :college_id AND code = :code LIMIT 1
        ');
        $dup->execute(['college_id' => $collegeId, 'code' => $code]);
        if ($dup->fetchColumn()) {
            return ['ok' => false, 'message' => 'That program code already exists for this college.'];
        }
        $stmt = $this->pdo->prepare('
            INSERT INTO programs (college_id, code, name, is_active)
            VALUES (:college_id, :code, :name, 1)
        ');
        $stmt->execute([
            'college_id' => $collegeId,
            'code' => $code,
            'name' => $name,
        ]);
        return ['ok' => true, 'message' => 'Program added.'];
    }

    public function updateProgramByAdmin(int $programId, int $collegeId, string $code, string $name): array
    {
        $code = strtoupper(trim($code));
        $name = trim($name);
        if ($programId <= 0 || $collegeId <= 0) {
            return ['ok' => false, 'message' => 'Invalid program or college.'];
        }
        if ($code === '' || $name === '') {
            return ['ok' => false, 'message' => 'Program code and name are required.'];
        }
        if (strlen($code) > 40 || strlen($name) > 191) {
            return ['ok' => false, 'message' => 'Code or name is too long.'];
        }
        $exists = $this->pdo->prepare('SELECT 1 FROM programs WHERE id = :id LIMIT 1');
        $exists->execute(['id' => $programId]);
        if (!$exists->fetchColumn()) {
            return ['ok' => false, 'message' => 'Program not found.'];
        }
        $collegeOk = $this->pdo->prepare('SELECT 1 FROM colleges WHERE id = :id AND is_active = 1 LIMIT 1');
        $collegeOk->execute(['id' => $collegeId]);
        if (!$collegeOk->fetchColumn()) {
            return ['ok' => false, 'message' => 'College not found or inactive.'];
        }
        $dup = $this->pdo->prepare('
            SELECT 1
            FROM programs
            WHERE college_id = :college_id
              AND code = :code
              AND id <> :id
            LIMIT 1
        ');
        $dup->execute([
            'college_id' => $collegeId,
            'code' => $code,
            'id' => $programId,
        ]);
        if ($dup->fetchColumn()) {
            return ['ok' => false, 'message' => 'That program code already exists for this college.'];
        }
        $stmt = $this->pdo->prepare('
            UPDATE programs
            SET college_id = :college_id,
                code = :code,
                name = :name
            WHERE id = :id
            LIMIT 1
        ');
        $stmt->execute([
            'college_id' => $collegeId,
            'code' => $code,
            'name' => $name,
            'id' => $programId,
        ]);
        return ['ok' => true, 'message' => 'Program updated.'];
    }

    public function setProgramActive(int $programId, bool $active): array
    {
        if ($programId <= 0) {
            return ['ok' => false, 'message' => 'Invalid program.'];
        }
        $stmt = $this->pdo->prepare('
            UPDATE programs
            SET is_active = :active
            WHERE id = :id
            LIMIT 1
        ');
        $stmt->execute([
            'active' => $active ? 1 : 0,
            'id' => $programId,
        ]);
        if ($stmt->rowCount() === 0) {
            return ['ok' => false, 'message' => 'Program not found.'];
        }

        return ['ok' => true, 'message' => $active ? 'Program reactivated.' : 'Program deleted.'];
    }

    public function deleteProgramByAdmin(int $programId): array
    {
        if ($programId <= 0) {
            return ['ok' => false, 'message' => 'Invalid program.'];
        }
        $exists = $this->pdo->prepare('SELECT 1 FROM programs WHERE id = :id LIMIT 1');
        $exists->execute(['id' => $programId]);
        if (!$exists->fetchColumn()) {
            return ['ok' => false, 'message' => 'Program not found.'];
        }

        try {
            $this->pdo->beginTransaction();
            $studentCount = $this->purgeStudentsMatching('program_id = :program_id', ['program_id' => $programId]);
            $this->pdo->prepare('UPDATE users SET program_id = NULL WHERE program_id = :id')
                ->execute(['id' => $programId]);
            $this->pdo->prepare('DELETE FROM programs WHERE id = :id LIMIT 1')
                ->execute(['id' => $programId]);
            $this->pdo->commit();
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }

            return ['ok' => false, 'message' => 'Could not delete this program. Please try again.'];
        }

        $message = 'Program deleted.';
        if ($studentCount > 0) {
            $message .= ' ' . $studentCount . ' student account' . ($studentCount === 1 ? '' : 's')
                . ' and related clearance data were also removed.';
        }

        return ['ok' => true, 'message' => $message];
    }

    public function deleteCollegeByAdmin(int $collegeId): array
    {
        if ($collegeId <= 0) {
            return ['ok' => false, 'message' => 'Invalid college.'];
        }
        $exists = $this->pdo->prepare('SELECT 1 FROM colleges WHERE id = :id LIMIT 1');
        $exists->execute(['id' => $collegeId]);
        if (!$exists->fetchColumn()) {
            return ['ok' => false, 'message' => 'College not found.'];
        }

        try {
            $this->pdo->beginTransaction();
            $programIds = $this->pdo->prepare('SELECT id FROM programs WHERE college_id = :id');
            $programIds->execute(['id' => $collegeId]);
            $ids = array_map(static fn ($id): int => (int) $id, $programIds->fetchAll(\PDO::FETCH_COLUMN));

            $where = 'college_id = :college_id';
            $bind = ['college_id' => $collegeId];
            if ($ids !== []) {
                $placeholders = [];
                foreach ($ids as $index => $programId) {
                    $key = 'pid' . $index;
                    $placeholders[] = ':' . $key;
                    $bind[$key] = $programId;
                }
                $where .= ' OR program_id IN (' . implode(',', $placeholders) . ')';
            }
            $studentCount = $this->purgeStudentsMatching($where, $bind);

            $this->pdo->prepare('UPDATE users SET college_id = NULL WHERE college_id = :id')
                ->execute(['id' => $collegeId]);
            if ($ids !== []) {
                $placeholders = implode(',', array_fill(0, count($ids), '?'));
                $this->pdo->prepare("UPDATE users SET program_id = NULL WHERE program_id IN ($placeholders)")
                    ->execute($ids);
                $this->pdo->prepare('DELETE FROM programs WHERE college_id = :id')
                    ->execute(['id' => $collegeId]);
            }
            $this->pdo->prepare('DELETE FROM colleges WHERE id = :id LIMIT 1')
                ->execute(['id' => $collegeId]);
            $this->pdo->commit();
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }

            return ['ok' => false, 'message' => 'Could not delete this college. Please try again.'];
        }

        $programCount = count($ids ?? []);
        $message = 'College deleted.';
        $parts = [];
        if ($programCount > 0) {
            $parts[] = $programCount . ' program' . ($programCount === 1 ? '' : 's');
        }
        if ($studentCount > 0) {
            $parts[] = $studentCount . ' student account' . ($studentCount === 1 ? '' : 's') . ' and related clearance data';
        }
        if ($parts !== []) {
            $message .= ' Also removed: ' . implode(' and ', $parts) . '.';
        }

        return ['ok' => true, 'message' => $message];
    }

    /**
     * @param array<string, int> $bind
     */
    private function purgeStudentsMatching(string $whereSql, array $bind): int
    {
        $stmt = $this->pdo->prepare("
            SELECT id
            FROM users
            WHERE role = 'student'
              AND ($whereSql)
        ");
        $stmt->execute($bind);
        $deleted = 0;
        foreach ($stmt->fetchAll(\PDO::FETCH_COLUMN) as $id) {
            if ($this->purgeStudentAccount((int) $id)) {
                $deleted++;
            }
        }

        return $deleted;
    }

    public function listOffices(): array
    {
        return $this->pdo->query("
            SELECT o.id, o.code, o.name, o.sequence_no, o.parent_office_id, p.code AS parent_code
            FROM offices o
            LEFT JOIN offices p ON p.id = o.parent_office_id
            WHERE o.is_active = 1
            ORDER BY o.sequence_no, o.name
        ")->fetchAll();
    }

    /**
     * Additional clearance units created by admin under SAS or Dean.
     *
     * @return list<array<string,mixed>>
     */
    public function listAdditionalSignatoryOffices(): array
    {
        $protected = array_map('strtoupper', self::PROTECTED_CHILD_OFFICE_CODES);
        $stmt = $this->pdo->query("
            SELECT o.id, o.code, o.name, o.sequence_no, o.parent_office_id, p.code AS parent_code, p.name AS parent_name
            FROM offices o
            INNER JOIN offices p ON p.id = o.parent_office_id
            WHERE o.is_active = 1
              AND UPPER(p.code) IN ('SAS', 'DEAN')
            ORDER BY p.sequence_no ASC, o.sequence_no ASC, o.name ASC
        ");
        $rows = [];
        foreach ($stmt->fetchAll() as $row) {
            if (in_array(strtoupper(trim((string) ($row['code'] ?? ''))), $protected, true)) {
                continue;
            }
            $rows[] = $row;
        }

        return $rows;
    }

    public function addAdditionalSignatoryOffice(string $parentCode, string $unitName): array
    {
        $parentCode = strtoupper(trim($parentCode));
        if (!in_array($parentCode, self::GROUP_PARENT_OFFICE_CODES, true)) {
            return ['ok' => false, 'message' => 'Choose Student Affairs and Services or College Dean / Campus Administrator.'];
        }

        $unitName = trim($unitName);
        if ($unitName === '') {
            return ['ok' => false, 'message' => 'Unit name is required.'];
        }
        if (strlen($unitName) > 191) {
            return ['ok' => false, 'message' => 'Unit name is too long (max 191 characters).'];
        }

        $parentOfficeId = $this->getOfficeIdByCode($parentCode);
        if ($parentOfficeId <= 0) {
            return ['ok' => false, 'message' => 'Parent office is not configured.'];
        }

        $dupName = $this->pdo->prepare('
            SELECT 1
            FROM offices
            WHERE parent_office_id = :parent_office_id
              AND LOWER(name) = LOWER(:name)
              AND is_active = 1
            LIMIT 1
        ');
        $dupName->execute([
            'parent_office_id' => $parentOfficeId,
            'name' => $unitName,
        ]);
        if ($dupName->fetchColumn()) {
            return ['ok' => false, 'message' => 'That unit name already exists under this group.'];
        }

        $code = $this->generateAdditionalOfficeCode($parentCode, $unitName);
        $sequenceNo = $this->allocateChildOfficeSequenceNo($parentOfficeId);

        $stmt = $this->pdo->prepare('
            INSERT INTO offices (code, name, sequence_no, parent_office_id, is_active)
            VALUES (:code, :name, :sequence_no, :parent_office_id, 1)
        ');
        $stmt->execute([
            'code' => $code,
            'name' => $unitName,
            'sequence_no' => $sequenceNo,
            'parent_office_id' => $parentOfficeId,
        ]);

        return ['ok' => true, 'message' => 'Clearance unit added. Assign a signatory to it below.'];
    }

    public function deactivateAdditionalSignatoryOffice(int $officeId): array
    {
        if ($officeId <= 0) {
            return ['ok' => false, 'message' => 'Invalid clearance unit.'];
        }

        $stmt = $this->pdo->prepare('
            SELECT o.id, o.code, o.parent_office_id, p.code AS parent_code
            FROM offices o
            LEFT JOIN offices p ON p.id = o.parent_office_id
            WHERE o.id = :office_id
              AND o.is_active = 1
            LIMIT 1
        ');
        $stmt->execute(['office_id' => $officeId]);
        $office = $stmt->fetch();
        if (!$office) {
            return ['ok' => false, 'message' => 'Clearance unit not found.'];
        }

        $code = strtoupper(trim((string) ($office['code'] ?? '')));
        if (in_array($code, self::PROTECTED_CHILD_OFFICE_CODES, true)
            || in_array($code, self::GROUP_PARENT_OFFICE_CODES, true)) {
            return ['ok' => false, 'message' => 'Built-in clearance units cannot be removed.'];
        }

        $parentCode = strtoupper(trim((string) ($office['parent_code'] ?? '')));
        if (!in_array($parentCode, self::GROUP_PARENT_OFFICE_CODES, true)) {
            return ['ok' => false, 'message' => 'Only additional units under SAS or Dean may be removed.'];
        }

        $this->pdo->prepare('DELETE FROM office_signatories WHERE office_id = :office_id')
            ->execute(['office_id' => $officeId]);
        $this->pdo->prepare('UPDATE offices SET is_active = 0 WHERE id = :office_id')
            ->execute(['office_id' => $officeId]);

        return ['ok' => true, 'message' => 'Additional clearance unit removed.'];
    }

    public function listSignatoryUsers(): array
    {
        return $this->pdo->query("
            SELECT id, first_name, last_name, email
            FROM users
            WHERE role = 'signatory' AND is_active = 1
            ORDER BY last_name, first_name
        ")->fetchAll();
    }

    public function addSignatoryUser(string $firstName, string $lastName, string $email, string $password): array
    {
        $firstName = trim($firstName);
        $lastName = trim($lastName);
        $email = strtolower(trim($email));
        if ($firstName === '' || $lastName === '' || $email === '') {
            return ['ok' => false, 'message' => 'First name, last name, and email are required.'];
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['ok' => false, 'message' => 'Invalid email address.'];
        }
        if (strlen($password) < 8) {
            return ['ok' => false, 'message' => 'Password must be at least 8 characters.'];
        }
        $dup = $this->pdo->prepare('SELECT 1 FROM users WHERE email = :email LIMIT 1');
        $dup->execute(['email' => $email]);
        if ($dup->fetchColumn()) {
            return ['ok' => false, 'message' => 'That email is already registered.'];
        }
        $hash = PasswordHasher::hash($password);
        $stmt = $this->pdo->prepare("
            INSERT INTO users
                (student_no, first_name, last_name, email, password_hash, role, college_id, program_id, year_level, is_active)
            VALUES
                (NULL, :first_name, :last_name, :email, :password_hash, 'signatory', NULL, NULL, NULL, 1)
        ");
        $stmt->execute([
            'first_name' => $firstName,
            'last_name' => $lastName,
            'email' => $email,
            'password_hash' => $hash,
        ]);

        return ['ok' => true, 'message' => 'Signatory account created. You can assign them to an office below.'];
    }

    public function listAllSignatoryUsersForAdmin(): array
    {
        return $this->pdo->query("
            SELECT u.id, u.first_name, u.last_name, u.email, u.is_active, u.college_id, c.name AS college_name
            FROM users u
            LEFT JOIN colleges c ON c.id = u.college_id
            WHERE u.role = 'signatory'
            ORDER BY u.is_active DESC, u.last_name, u.first_name
        ")->fetchAll();
    }

    public function getSignatoryByIdForAdmin(int $id): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT id, first_name, last_name, email, is_active
            FROM users
            WHERE id = :id AND role = 'signatory'
            LIMIT 1
        ");
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();

        return $row ?: null;
    }

    public function updateSignatoryUser(int $id, string $firstName, string $lastName, string $email, ?string $newPassword): array
    {
        $firstName = trim($firstName);
        $lastName = trim($lastName);
        $email = strtolower(trim($email));
        if ($id <= 0 || $firstName === '' || $lastName === '' || $email === '') {
            return ['ok' => false, 'message' => 'Invalid data.'];
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['ok' => false, 'message' => 'Invalid email address.'];
        }
        $exists = $this->pdo->prepare('SELECT 1 FROM users WHERE id = :id AND role = \'signatory\' LIMIT 1');
        $exists->execute(['id' => $id]);
        if (!$exists->fetchColumn()) {
            return ['ok' => false, 'message' => 'Signatory not found.'];
        }
        $dup = $this->pdo->prepare('SELECT id FROM users WHERE email = :email AND id != :id LIMIT 1');
        $dup->execute(['email' => $email, 'id' => $id]);
        if ($dup->fetchColumn()) {
            return ['ok' => false, 'message' => 'That email is already used by another account.'];
        }
        if ($newPassword !== null && $newPassword !== '') {
            if (strlen($newPassword) < 8) {
                return ['ok' => false, 'message' => 'New password must be at least 8 characters.'];
            }
            $hash = PasswordHasher::hash($newPassword);
            $stmt = $this->pdo->prepare("
                UPDATE users
                SET first_name = :fn, last_name = :ln, email = :em, password_hash = :ph
                WHERE id = :id AND role = 'signatory'
                LIMIT 1
            ");
            $stmt->execute([
                'fn' => $firstName,
                'ln' => $lastName,
                'em' => $email,
                'ph' => $hash,
                'id' => $id,
            ]);
        } else {
            $stmt = $this->pdo->prepare("
                UPDATE users
                SET first_name = :fn, last_name = :ln, email = :em
                WHERE id = :id AND role = 'signatory'
                LIMIT 1
            ");
            $stmt->execute([
                'fn' => $firstName,
                'ln' => $lastName,
                'em' => $email,
                'id' => $id,
            ]);
        }

        return ['ok' => true, 'message' => 'Signatory updated.'];
    }

    public function getAdminProfile(int $userId): ?array
    {
        if ($userId <= 0) {
            return null;
        }
        $stmt = $this->pdo->prepare("
            SELECT id, first_name, last_name, email, profile_photo_path
            FROM users
            WHERE id = :id AND role = 'admin'
            LIMIT 1
        ");
        $stmt->execute(['id' => $userId]);
        $row = $stmt->fetch();

        return $row ?: null;
    }

    /**
     * @return array{ok:bool,message:string,user?:array<string,mixed>}
     */
    public function updateAdminProfile(
        int $userId,
        string $firstName,
        string $lastName,
        string $email,
        ?string $currentPassword,
        ?string $newPassword,
        ?string $confirmPassword
    ): array {
        $firstName = trim($firstName);
        $lastName = trim($lastName);
        $email = strtolower(trim($email));
        if ($userId <= 0 || $firstName === '' || $lastName === '' || $email === '') {
            return ['ok' => false, 'message' => 'Please complete all profile fields.'];
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['ok' => false, 'message' => 'Invalid email address.'];
        }

        $stmt = $this->pdo->prepare("
            SELECT id, password_hash
            FROM users
            WHERE id = :id AND role = 'admin'
            LIMIT 1
        ");
        $stmt->execute(['id' => $userId]);
        $admin = $stmt->fetch();
        if (!$admin) {
            return ['ok' => false, 'message' => 'Admin account not found.'];
        }

        $dup = $this->pdo->prepare('SELECT 1 FROM users WHERE email = :email AND id != :id LIMIT 1');
        $dup->execute(['email' => $email, 'id' => $userId]);
        if ($dup->fetchColumn()) {
            return ['ok' => false, 'message' => 'That email is already used by another account.'];
        }

        $newPassword = $newPassword !== null ? trim($newPassword) : '';
        $confirmPassword = $confirmPassword !== null ? trim($confirmPassword) : '';
        $currentPassword = $currentPassword !== null ? (string) $currentPassword : '';

        if ($newPassword !== '' || $confirmPassword !== '') {
            if ($newPassword === '' || $confirmPassword === '') {
                return ['ok' => false, 'message' => 'Enter and confirm your new password.'];
            }
            if ($newPassword !== $confirmPassword) {
                return ['ok' => false, 'message' => 'New password and confirmation do not match.'];
            }
            if (strlen($newPassword) < 8) {
                return ['ok' => false, 'message' => 'New password must be at least 8 characters.'];
            }
            if ($currentPassword === '' || !PasswordHasher::verify($currentPassword, (string) $admin['password_hash'])) {
                return ['ok' => false, 'message' => 'Current password is incorrect.'];
            }
            $hash = PasswordHasher::hash($newPassword);
            $update = $this->pdo->prepare("
                UPDATE users
                SET first_name = :fn, last_name = :ln, email = :em, password_hash = :ph
                WHERE id = :id AND role = 'admin'
                LIMIT 1
            ");
            $update->execute([
                'fn' => $firstName,
                'ln' => $lastName,
                'em' => $email,
                'ph' => $hash,
                'id' => $userId,
            ]);
        } else {
            $update = $this->pdo->prepare("
                UPDATE users
                SET first_name = :fn, last_name = :ln, email = :em
                WHERE id = :id AND role = 'admin'
                LIMIT 1
            ");
            $update->execute([
                'fn' => $firstName,
                'ln' => $lastName,
                'em' => $email,
                'id' => $userId,
            ]);
        }

        $profile = $this->getAdminProfile($userId);
        if ($profile === null) {
            return ['ok' => false, 'message' => 'Profile updated but could not reload account.'];
        }

        return [
            'ok' => true,
            'message' => $newPassword !== '' ? 'Profile and password updated successfully.' : 'Profile updated successfully.',
            'user' => $profile,
        ];
    }

    public function saveAdminProfilePhoto(int $userId, array $file, bool $removeExisting = false): array
    {
        if ($userId <= 0) {
            return ['ok' => false, 'message' => 'Invalid admin account.'];
        }
        $exists = $this->pdo->prepare("SELECT profile_photo_path FROM users WHERE id = :id AND role = 'admin' LIMIT 1");
        $exists->execute(['id' => $userId]);
        $row = $exists->fetch();
        if (!$row) {
            return ['ok' => false, 'message' => 'Admin account not found.'];
        }
        $existingPath = trim((string) ($row['profile_photo_path'] ?? ''));

        if ($removeExisting && ($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
            if ($existingPath !== '') {
                $this->deleteStoredProfilePhoto($existingPath);
            }
            $this->pdo->prepare("UPDATE users SET profile_photo_path = NULL WHERE id = :id AND role = 'admin' LIMIT 1")
                ->execute(['id' => $userId]);

            return ['ok' => true, 'message' => 'Profile photo removed.'];
        }

        if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            return ['ok' => false, 'message' => 'Please choose a profile photo to upload.'];
        }

        $allowed = ['image/png', 'image/jpeg', 'image/webp'];
        $mime = mime_content_type((string) ($file['tmp_name'] ?? '')) ?: '';
        if (!in_array($mime, $allowed, true)) {
            return ['ok' => false, 'message' => 'Invalid photo type. Allowed: PNG, JPG, WEBP.'];
        }
        $size = (int) ($file['size'] ?? 0);
        if ($size <= 0 || $size > 3 * 1024 * 1024) {
            return ['ok' => false, 'message' => 'Photo must be 3MB or smaller.'];
        }
        $binary = file_get_contents((string) ($file['tmp_name'] ?? ''));
        if ($binary === false || $binary === '') {
            return ['ok' => false, 'message' => 'Could not read uploaded photo.'];
        }
        $imgInfo = @getimagesizefromstring($binary);
        if ($imgInfo === false || !in_array((string) ($imgInfo['mime'] ?? ''), $allowed, true)) {
            return ['ok' => false, 'message' => 'Invalid profile photo image.'];
        }
        $imgWidth = (int) ($imgInfo[0] ?? 0);
        $imgHeight = (int) ($imgInfo[1] ?? 0);
        if ($imgWidth <= 0 || $imgHeight <= 0 || $imgWidth > 1600 || $imgHeight > 1600) {
            return ['ok' => false, 'message' => 'Photo dimensions are not supported (max 1600×1600).'];
        }

        $storageDir = dirname(__DIR__, 2) . '/storage/profile-photos';
        if (!is_dir($storageDir)) {
            mkdir($storageDir, 0775, true);
        }

        $jpegBlob = SignatureImage::rasterBinaryToJpeg($binary);
        if ($jpegBlob !== null) {
            $binary = $jpegBlob;
            $ext = 'jpg';
        } else {
            $ext = match ($mime) {
                'image/jpeg' => 'jpg',
                'image/webp' => 'webp',
                default => 'png',
            };
        }

        $fileName = sprintf(
            'admin_profile_%d_%s.%s',
            $userId,
            (new DateTime())->format('YmdHisv'),
            $ext
        );
        $absolutePath = $storageDir . '/' . $fileName;
        if (file_put_contents($absolutePath, $binary) === false) {
            return ['ok' => false, 'message' => 'Could not store profile photo.'];
        }

        $relativePath = 'storage/profile-photos/' . $fileName;
        $this->pdo->prepare("
            UPDATE users
            SET profile_photo_path = :path
            WHERE id = :id AND role = 'admin'
            LIMIT 1
        ")->execute([
            'path' => $relativePath,
            'id' => $userId,
        ]);

        if ($existingPath !== '' && $existingPath !== $relativePath) {
            $this->deleteStoredProfilePhoto($existingPath);
        }

        return ['ok' => true, 'message' => 'Profile photo uploaded successfully.'];
    }

    public function setSignatoryActive(int $id, bool $active): array
    {
        if ($id <= 0) {
            return ['ok' => false, 'message' => 'Invalid signatory.'];
        }
        $stmt = $this->pdo->prepare("
            UPDATE users SET is_active = :active WHERE id = :id AND role = 'signatory' LIMIT 1
        ");
        $stmt->execute(['active' => $active ? 1 : 0, 'id' => $id]);
        if ($stmt->rowCount() === 0) {
            return ['ok' => false, 'message' => 'Signatory not found.'];
        }
        if (!$active) {
            $del = $this->pdo->prepare('DELETE FROM office_signatories WHERE user_id = :uid');
            $del->execute(['uid' => $id]);
        }

        return ['ok' => true, 'message' => $active ? 'Signatory reactivated. Re-assign offices if needed.' : 'Signatory deactivated; office assignments removed.'];
    }

    public function listOfficeSignatoryAssignments(int $semesterId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT os.id, os.office_id, o.name AS office_name, os.user_id,
                   u.last_name, u.first_name, u.email
            FROM office_signatories os
            JOIN offices o ON o.id = os.office_id
            JOIN users u ON u.id = os.user_id
            WHERE os.semester_id = :semester_id
            ORDER BY o.sequence_no, u.last_name, u.first_name
        ");
        $stmt->execute(['semester_id' => $semesterId]);

        return $stmt->fetchAll();
    }

    public function removeOfficeSignatoryAssignment(int $assignmentId, int $semesterId): array
    {
        if ($assignmentId <= 0) {
            return ['ok' => false, 'message' => 'Invalid assignment.'];
        }
        $stmt = $this->pdo->prepare("
            DELETE FROM office_signatories
            WHERE id = :id AND semester_id = :semester_id
            LIMIT 1
        ");
        $stmt->execute(['id' => $assignmentId, 'semester_id' => $semesterId]);
        if ($stmt->rowCount() === 0) {
            return ['ok' => false, 'message' => 'Assignment not found.'];
        }

        return ['ok' => true, 'message' => 'Office assignment removed.'];
    }

    public function assignDeanToCollege(int $semesterId, int $collegeId, int $signatoryUserId): array
    {
        if ($collegeId <= 0 || $signatoryUserId <= 0) {
            return ['ok' => false, 'message' => 'Choose a college and a dean signatory.'];
        }

        $collegeStmt = $this->pdo->prepare("
            SELECT 1
            FROM colleges
            WHERE id = :college_id AND is_active = 1
            LIMIT 1
        ");
        $collegeStmt->execute(['college_id' => $collegeId]);
        if (!$collegeStmt->fetchColumn()) {
            return ['ok' => false, 'message' => 'Invalid college.'];
        }

        $signatoryStmt = $this->pdo->prepare("
            SELECT 1
            FROM users
            WHERE id = :user_id
              AND role = 'signatory'
              AND is_active = 1
            LIMIT 1
        ");
        $signatoryStmt->execute(['user_id' => $signatoryUserId]);
        if (!$signatoryStmt->fetchColumn()) {
            return ['ok' => false, 'message' => 'Invalid signatory user.'];
        }

        $deanOfficeStmt = $this->pdo->prepare("
            SELECT id
            FROM offices
            WHERE UPPER(code) = 'DEAN'
              AND is_active = 1
            LIMIT 1
        ");
        $deanOfficeStmt->execute();
        $deanOfficeId = (int) $deanOfficeStmt->fetchColumn();
        if ($deanOfficeId <= 0) {
            return ['ok' => false, 'message' => 'DEAN office is not configured.'];
        }

        try {
            $this->pdo->beginTransaction();

            // Ensure exactly one dean-signatory is mapped per college.
            $clearExisting = $this->pdo->prepare("
                UPDATE users
                SET college_id = NULL
                WHERE role = 'signatory'
                  AND college_id = :college_id
                  AND id <> :user_id
            ");
            $clearExisting->execute([
                'college_id' => $collegeId,
                'user_id' => $signatoryUserId,
            ]);

            $assignCollege = $this->pdo->prepare("
                UPDATE users
                SET college_id = :college_id
                WHERE id = :user_id
                  AND role = 'signatory'
                LIMIT 1
            ");
            $assignCollege->execute([
                'college_id' => $collegeId,
                'user_id' => $signatoryUserId,
            ]);

            $assignDeanOffice = $this->pdo->prepare("
                INSERT INTO office_signatories (office_id, user_id, semester_id)
                VALUES (:office_id, :user_id, :semester_id)
                ON DUPLICATE KEY UPDATE assigned_at = CURRENT_TIMESTAMP
            ");
            $assignDeanOffice->execute([
                'office_id' => $deanOfficeId,
                'user_id' => $signatoryUserId,
                'semester_id' => $semesterId,
            ]);

            $this->pdo->commit();
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            return ['ok' => false, 'message' => 'Could not assign dean to college.'];
        }

        return ['ok' => true, 'message' => 'Dean assigned to college successfully.'];
    }

    public function listDeanAssignmentsByCollege(int $semesterId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT
                c.id AS college_id,
                c.code AS college_code,
                c.name AS college_name,
                u.id AS signatory_id,
                u.first_name,
                u.last_name,
                u.email
            FROM colleges c
            LEFT JOIN users u
                ON u.role = 'signatory'
               AND u.is_active = 1
               AND u.college_id = c.id
            LEFT JOIN office_signatories os
                ON os.user_id = u.id
               AND os.semester_id = :semester_id
            LEFT JOIN offices o
                ON o.id = os.office_id
               AND UPPER(o.code) = 'DEAN'
               AND o.is_active = 1
            WHERE c.is_active = 1
              AND (u.id IS NULL OR o.id IS NOT NULL)
            ORDER BY c.name
        ");
        $stmt->execute(['semester_id' => $semesterId]);
        return $stmt->fetchAll();
    }

    public function getAdminRequirements(int $semesterId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT r.id, o.name AS office_name, r.office_id, r.title, r.description, r.attachment_path, r.attachment_name
            FROM office_requirements r
            JOIN offices o ON o.id = r.office_id
            WHERE r.semester_id = :semester_id AND r.is_active = 1
            ORDER BY o.sequence_no, r.id
        ");
        $stmt->execute(['semester_id' => $semesterId]);
        return $stmt->fetchAll();
    }

    public function listStudentsWithOverallStatus(int $semesterId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT
                u.id,
                u.student_no,
                u.first_name,
                u.last_name,
                u.email,
                u.year_level,
                u.campus,
                c.name AS college_name,
                p.name AS program_name,
                COALESCE(ssc.overall_status, 'pending') AS overall_status
            FROM users u
            LEFT JOIN colleges c ON c.id = u.college_id
            LEFT JOIN programs p ON p.id = u.program_id
            LEFT JOIN student_semester_clearances ssc
                ON ssc.student_id = u.id
               AND ssc.semester_id = :semester_id
            WHERE u.role = 'student' AND u.is_active = 1
            ORDER BY u.last_name, u.first_name
        ");
        $stmt->execute(['semester_id' => $semesterId]);
        return $stmt->fetchAll();
    }

    public function getAdminClearanceReport(
        int $semesterId,
        ?string $overallStatus = null,
        ?string $campus = null
    ): array {
        $allowedStatuses = ['pending', 'for_review', 'cleared', 'rejected'];
        $overallFilter = in_array((string) $overallStatus, $allowedStatuses, true) ? $overallStatus : null;
        $campusNorm = $campus !== null && trim($campus) !== '' ? $this->normalizeStudentCampus($campus) : null;
        $campusFilter = ($campusNorm !== null && $campusNorm['ok']) ? $campusNorm['value'] : null;

        $sql = "
            SELECT
                u.id AS student_id,
                u.student_no,
                u.first_name,
                u.last_name,
                u.email,
                COALESCE(col.name, '') AS college_name,
                COALESCE(pr.name, '') AS program_name,
                COALESCE(u.year_level, '') AS year_level,
                COALESCE(u.campus, '') AS campus,
                COALESCE(ssc.overall_status, 'pending') AS overall_status
            FROM users u
            LEFT JOIN colleges col ON col.id = u.college_id
            LEFT JOIN programs pr ON pr.id = u.program_id
            LEFT JOIN student_semester_clearances ssc
                ON ssc.student_id = u.id
               AND ssc.semester_id = :semester_id
            WHERE u.role = 'student' AND u.is_active = 1
        ";

        $bindings = ['semester_id' => $semesterId];
        if ($overallFilter !== null) {
            $sql .= " AND COALESCE(ssc.overall_status, 'pending') = :overall_status";
            $bindings['overall_status'] = $overallFilter;
        }
        if ($campusFilter !== null) {
            $sql .= ' AND u.campus = :campus';
            $bindings['campus'] = $campusFilter;
        }

        $sql .= " ORDER BY u.last_name, u.first_name";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($bindings);
        return $stmt->fetchAll();
    }

    /**
     * Admin monitor: which offices still need to clear each student.
     *
     * @return array{
     *   offices: list<array<string,mixed>>,
     *   students: list<array<string,mixed>>,
     *   stats: array{total_students:int, students_with_pending:int, fully_cleared:int}
     * }
     */
    public function getAdminPendingDepartmentMonitor(
        int $semesterId,
        ?int $officeId = null,
        ?string $campus = null,
        ?int $collegeId = null,
        ?int $programId = null,
        ?string $yearLevel = null,
        ?string $searchName = null,
        ?string $officeStatus = null
    ): array {
        $officeId = ($officeId !== null && $officeId > 0) ? $officeId : null;
        $collegeId = ($collegeId !== null && $collegeId > 0) ? $collegeId : null;
        $programId = ($programId !== null && $programId > 0) ? $programId : null;
        $yearLevel = $this->normalizeQueueYearLevelFilter($yearLevel);
        $searchName = $this->normalizeQueueSearchNameFilter($searchName);
        $officeStatus = $this->normalizePendingOfficeStatusFilter($officeStatus);

        $campusNorm = $campus !== null && trim($campus) !== '' ? $this->normalizeStudentCampus($campus) : null;
        $campusFilter = ($campusNorm !== null && $campusNorm['ok']) ? $campusNorm['value'] : null;

        $officesStmt = $this->pdo->query("
            SELECT
                o.id,
                o.code,
                o.name,
                o.sequence_no,
                o.parent_office_id,
                p.name AS parent_name
            FROM offices o
            LEFT JOIN offices p ON p.id = o.parent_office_id
            WHERE o.is_active = 1
            ORDER BY o.sequence_no ASC, o.name ASC
        ");
        $officeRows = $officesStmt->fetchAll();
        $officeStats = [];
        foreach ($officeRows as $office) {
            $oid = (int) ($office['id'] ?? 0);
            if ($oid <= 0) {
                continue;
            }
            $officeStats[$oid] = [
                'office_id' => $oid,
                'office_code' => (string) ($office['code'] ?? ''),
                'office_name' => (string) ($office['name'] ?? ''),
                'parent_name' => (string) ($office['parent_name'] ?? ''),
                'sequence_no' => (int) ($office['sequence_no'] ?? 0),
                'pending' => 0,
                'for_review' => 0,
                'rejected' => 0,
                'incomplete' => 0,
            ];
        }

        $extraWhere = '';
        $bindings = [
            'semester_id' => $semesterId,
            'semester_id_2' => $semesterId,
            'acct_code' => self::ACCOUNTING_OFFICE_CODE,
            'dorm_code' => self::DORMITORY_OFFICE_CODE,
        ];
        if ($campusFilter !== null) {
            $extraWhere .= ' AND u.campus = :campus';
            $bindings['campus'] = $campusFilter;
        }
        if ($collegeId !== null) {
            $extraWhere .= ' AND u.college_id = :college_id';
            $bindings['college_id'] = $collegeId;
        }
        if ($programId !== null) {
            $extraWhere .= ' AND u.program_id = :program_id';
            $bindings['program_id'] = $programId;
        }
        if ($yearLevel !== null) {
            $extraWhere .= ' AND u.year_level = :year_level';
            $bindings['year_level'] = $yearLevel;
        }
        if ($searchName !== null) {
            $namePattern = $this->queueSearchLikePattern($searchName);
            $extraWhere .= ' AND (
                u.first_name LIKE :search_name
                OR u.last_name LIKE :search_name
                OR u.student_no LIKE :search_name
                OR CONCAT(u.first_name, \' \', u.last_name) LIKE :search_name
                OR CONCAT(u.last_name, \', \', u.first_name) LIKE :search_name
            )';
            $bindings['search_name'] = $namePattern;
        }

        $sql = "
            SELECT
                u.id AS student_id,
                u.student_no,
                u.first_name,
                u.last_name,
                u.email,
                COALESCE(u.year_level, '') AS year_level,
                COALESCE(u.campus, '') AS campus,
                COALESCE(col.name, '') AS college_name,
                COALESCE(pr.name, '') AS program_name,
                COALESCE(ssc.overall_status, 'pending') AS overall_status,
                o.id AS office_id,
                o.code AS office_code,
                o.name AS office_name,
                o.sequence_no,
                COALESCE(p.name, '') AS parent_name,
                COALESCE(sc.status, 'pending') AS office_status
            FROM users u
            LEFT JOIN colleges col ON col.id = u.college_id
            LEFT JOIN programs pr ON pr.id = u.program_id
            LEFT JOIN student_semester_clearances ssc
                ON ssc.student_id = u.id
               AND ssc.semester_id = :semester_id
            INNER JOIN offices o ON o.is_active = 1
            LEFT JOIN offices p ON p.id = o.parent_office_id
            LEFT JOIN student_clearances sc
                ON sc.student_id = u.id
               AND sc.office_id = o.id
               AND sc.semester_id = :semester_id_2
            WHERE u.role = 'student'
              AND u.is_active = 1
              AND NOT (
                    UPPER(o.code) = :acct_code
                AND COALESCE(u.student_account_type, 'paying_tuition') = 'not_paying_tuition'
              )
              AND NOT (
                    UPPER(o.code) = :dorm_code
                AND COALESCE(u.student_staying, '') <> 'wpu_dormitory'
              )
              {$extraWhere}
            ORDER BY u.last_name, u.first_name, o.sequence_no, o.name
        ";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($bindings);

        $students = [];
        foreach ($stmt->fetchAll() as $row) {
            $studentId = (int) ($row['student_id'] ?? 0);
            if ($studentId <= 0) {
                continue;
            }
            if (!isset($students[$studentId])) {
                $students[$studentId] = [
                    'student_id' => $studentId,
                    'student_no' => (string) ($row['student_no'] ?? ''),
                    'first_name' => (string) ($row['first_name'] ?? ''),
                    'last_name' => (string) ($row['last_name'] ?? ''),
                    'email' => (string) ($row['email'] ?? ''),
                    'year_level' => (string) ($row['year_level'] ?? ''),
                    'campus' => (string) ($row['campus'] ?? ''),
                    'college_name' => (string) ($row['college_name'] ?? ''),
                    'program_name' => (string) ($row['program_name'] ?? ''),
                    'overall_status' => (string) ($row['overall_status'] ?? 'pending'),
                    'pending_offices' => [],
                ];
            }

            $status = strtolower(trim((string) ($row['office_status'] ?? 'pending')));
            if ($status === 'cleared') {
                continue;
            }
            if (!in_array($status, ['pending', 'for_review', 'rejected'], true)) {
                $status = 'pending';
            }

            $oid = (int) ($row['office_id'] ?? 0);
            $officeEntry = [
                'office_id' => $oid,
                'office_code' => (string) ($row['office_code'] ?? ''),
                'office_name' => (string) ($row['office_name'] ?? ''),
                'parent_name' => (string) ($row['parent_name'] ?? ''),
                'status' => $status,
            ];
            $students[$studentId]['pending_offices'][] = $officeEntry;

            if (isset($officeStats[$oid])) {
                $officeStats[$oid]['incomplete']++;
                $officeStats[$oid][$status]++;
            }
        }

        $fullyCleared = 0;
        $withPending = 0;
        $filtered = [];
        foreach ($students as $student) {
            $pendingOffices = $student['pending_offices'];
            if ($pendingOffices === []) {
                $fullyCleared++;
                continue;
            }
            $withPending++;
            if ($officeId !== null) {
                $matchesOffice = false;
                foreach ($pendingOffices as $pendingOffice) {
                    if ((int) ($pendingOffice['office_id'] ?? 0) !== $officeId) {
                        continue;
                    }
                    if ($officeStatus !== null && (string) ($pendingOffice['status'] ?? '') !== $officeStatus) {
                        continue;
                    }
                    $matchesOffice = true;
                    break;
                }
                if (!$matchesOffice) {
                    continue;
                }
            } elseif ($officeStatus !== null) {
                $matchesStatus = false;
                foreach ($pendingOffices as $pendingOffice) {
                    if ((string) ($pendingOffice['status'] ?? '') === $officeStatus) {
                        $matchesStatus = true;
                        break;
                    }
                }
                if (!$matchesStatus) {
                    continue;
                }
            }
            $filtered[] = $student;
        }

        return [
            'offices' => array_values($officeStats),
            'students' => $filtered,
            'stats' => [
                'total_students' => count($students),
                'students_with_pending' => $withPending,
                'fully_cleared' => $fullyCleared,
            ],
        ];
    }

    private function normalizePendingOfficeStatusFilter(?string $raw): ?string
    {
        if ($raw === null) {
            return null;
        }
        $v = strtolower(trim($raw));
        if ($v === 'approved') {
            $v = 'cleared';
        } elseif ($v === 'disapproved') {
            $v = 'rejected';
        }

        return in_array($v, ['pending', 'for_review', 'rejected'], true) ? $v : null;
    }

    public function getFinalClearanceData(int $studentId, int $semesterId): ?array
    {
        $studentStmt = $this->pdo->prepare("
            SELECT id, student_no, first_name, last_name, email, year_level, campus
            FROM users
            WHERE id = :student_id AND role = 'student'
            LIMIT 1
        ");
        $studentStmt->execute(['student_id' => $studentId]);
        $student = $studentStmt->fetch();
        if (!$student) {
            return null;
        }

        $semStmt = $this->pdo->prepare("
            SELECT id, academic_year, term
            FROM semesters
            WHERE id = :semester_id
            LIMIT 1
        ");
        $semStmt->execute(['semester_id' => $semesterId]);
        $semester = $semStmt->fetch();
        if (!$semester) {
            return null;
        }

        $officesStmt = $this->pdo->prepare("
            SELECT
                o.id AS office_id,
                o.code AS office_code,
                o.name AS office_name,
                o.sequence_no,
                COALESCE(sc.status, 'pending') AS status,
                sc.decided_at,
                sc.decided_by AS signatory_user_id,
                sc.digital_signature_path,
                CONCAT(u.first_name, ' ', u.last_name) AS signatory_name
            FROM offices o
            LEFT JOIN student_clearances sc
                ON sc.office_id = o.id
               AND sc.student_id = :student_id
               AND sc.semester_id = :semester_id
            LEFT JOIN users u
                ON u.id = sc.decided_by
            WHERE o.is_active = 1
            ORDER BY o.sequence_no ASC
        ");
        $officesStmt->execute([
            'student_id' => $studentId,
            'semester_id' => $semesterId,
        ]);
        $offices = $officesStmt->fetchAll();
        $offices = $this->filterStudentDashboardOffices($offices, $studentId);
        $this->attachResolvedSignaturePaths($offices, $semesterId);
        $this->syncOverallStatus($studentId, $semesterId);

        return [
            'student' => $student,
            'semester' => $semester,
            'offices' => $offices,
            'overall_status' => $this->getOverallStatus($studentId, $semesterId),
            'is_fully_cleared' => $this->isFullyCleared($offices),
        ];
    }

    /**
     * Ensures each office row has a usable signature path for rendering.
     * Older clearance rows may have an empty digital_signature_path even when
     * the signatory has a semester signature saved.
     */
    private function attachResolvedSignaturePaths(array &$offices, int $semesterId): void
    {
        if ($offices === []) {
            return;
        }

        $signatureBySignatory = [];
        foreach ($offices as &$office) {
            $currentPath = trim((string) ($office['digital_signature_path'] ?? ''));
            if ($currentPath !== '') {
                $office['digital_signature_path'] = $currentPath;
                continue;
            }

            $signatoryUserId = (int) ($office['signatory_user_id'] ?? 0);
            if ($signatoryUserId <= 0) {
                $office['digital_signature_path'] = null;
                continue;
            }

            if (!array_key_exists($signatoryUserId, $signatureBySignatory)) {
                $signatureBySignatory[$signatoryUserId] = $this->getSignatorySignaturePath($signatoryUserId, $semesterId);
            }
            $office['digital_signature_path'] = $signatureBySignatory[$signatoryUserId];
        }
        unset($office);
    }

    public function saveSignatorySignature(
        int $signatoryUserId,
        int $semesterId,
        array $file
    ): array {
        $office = $this->getSignatoryOffice($signatoryUserId, $semesterId);
        if (!$this->signatoryOfficeRequiresSignatureUpload($office)) {
            return ['ok' => false, 'message' => 'E-signature upload is not available for your office.'];
        }

        if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            return ['ok' => false, 'message' => 'Please upload a signature image file.'];
        }
        $allowed = ['image/png', 'image/jpeg', 'image/webp'];
        $mime = mime_content_type((string) ($file['tmp_name'] ?? '')) ?: '';
        if (!in_array($mime, $allowed, true)) {
            return ['ok' => false, 'message' => 'Invalid signature file type. Allowed: PNG, JPG, WEBP.'];
        }
        $size = (int) ($file['size'] ?? 0);
        if ($size <= 0 || $size > 2 * 1024 * 1024) {
            return ['ok' => false, 'message' => 'Signature file must be <= 2MB.'];
        }
        $binary = file_get_contents((string) ($file['tmp_name'] ?? ''));
        if ($binary === false || $binary === '') {
            return ['ok' => false, 'message' => 'Could not read uploaded signature file.'];
        }
        $imgInfo = @getimagesizefromstring($binary);
        if ($imgInfo === false || ($imgInfo['mime'] ?? '') !== 'image/png') {
            if (!in_array((string) ($imgInfo['mime'] ?? ''), $allowed, true)) {
                return ['ok' => false, 'message' => 'Invalid signature image.'];
            }
        }
        $imgWidth = (int) ($imgInfo[0] ?? 0);
        $imgHeight = (int) ($imgInfo[1] ?? 0);
        if ($imgWidth <= 0 || $imgHeight <= 0 || $imgWidth > 2200 || $imgHeight > 1200) {
            return ['ok' => false, 'message' => 'Signature size is not supported.'];
        }

        $storageDir = dirname(__DIR__, 2) . '/storage/signatory-signatures';
        if (!is_dir($storageDir)) {
            mkdir($storageDir, 0775, true);
        }
        $jpegBlob = SignatureImage::rasterBinaryToJpeg($binary);
        if ($jpegBlob !== null) {
            $binary = $jpegBlob;
            $ext = 'jpg';
        } else {
            $ext = match ($mime) {
                'image/jpeg' => 'jpg',
                'image/webp' => 'webp',
                default => 'png',
            };
        }

        $fileName = sprintf(
            'signatory_sig_%d_%d_%s.%s',
            $signatoryUserId,
            $semesterId,
            (new DateTime())->format('YmdHisv'),
            $ext
        );
        $absolutePath = $storageDir . '/' . $fileName;
        if (file_put_contents($absolutePath, $binary) === false) {
            return ['ok' => false, 'message' => 'Could not store signature file.'];
        }

        $relativePath = 'storage/signatory-signatures/' . $fileName;
        $existing = $this->getSignatorySignaturePath($signatoryUserId, $semesterId);
        $upsert = $this->pdo->prepare("
            INSERT INTO signatory_signatures
                (semester_id, signatory_user_id, signature_file)
            VALUES
                (:semester_id, :signatory_user_id, :signature_file)
            ON DUPLICATE KEY UPDATE
                signature_file = VALUES(signature_file),
                updated_at = CURRENT_TIMESTAMP
        ");
        $upsert->execute([
            'semester_id' => $semesterId,
            'signatory_user_id' => $signatoryUserId,
            'signature_file' => $relativePath,
        ]);

        if ($existing !== null && $existing !== $relativePath) {
            $oldAbs = dirname(__DIR__, 2) . '/' . ltrim($existing, '/');
            if (is_file($oldAbs)) {
                @unlink($oldAbs);
            }
        }

        return ['ok' => true, 'message' => 'Signatory e-signature uploaded successfully.'];
    }

    public function statusToColor(string $status): string
    {
        return match ($status) {
            'cleared' => 'green',
            'for_review' => 'yellow',
            default => 'red',
        };
    }

    private function isFullyCleared(array $offices): bool
    {
        if ($offices === []) {
            return false;
        }
        foreach ($offices as $office) {
            if (($office['status'] ?? 'pending') !== 'cleared') {
                return false;
            }
        }
        return true;
    }

    private function getOverallStatus(int $studentId, int $semesterId): string
    {
        $stmt = $this->pdo->prepare("
            SELECT overall_status
            FROM student_semester_clearances
            WHERE semester_id = :semester_id AND student_id = :student_id
            LIMIT 1
        ");
        $stmt->execute([
            'semester_id' => $semesterId,
            'student_id' => $studentId,
        ]);
        return (string) ($stmt->fetchColumn() ?: 'pending');
    }

    private function syncOverallStatus(int $studentId, int $semesterId): void
    {
        $excludeAccounting = !$this->studentRequiresAccountingClearance($studentId);
        $excludeDormitory = !$this->studentRequiresDormitoryClearance($studentId);
        $sql = "
            SELECT COALESCE(sc.status, 'pending') AS status
            FROM offices o
            LEFT JOIN student_clearances sc
                ON sc.office_id = o.id
               AND sc.student_id = :student_id
               AND sc.semester_id = :semester_id
            WHERE o.is_active = 1
        ";
        if ($excludeAccounting) {
            $sql .= " AND UPPER(o.code) <> '" . self::ACCOUNTING_OFFICE_CODE . "'";
        }
        if ($excludeDormitory) {
            $sql .= " AND UPPER(o.code) <> '" . self::DORMITORY_OFFICE_CODE . "'";
        }
        $sql .= ' ORDER BY o.sequence_no ASC';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            'student_id' => $studentId,
            'semester_id' => $semesterId,
        ]);
        $statuses = array_map(
            static fn (array $row): string => (string) ($row['status'] ?? 'pending'),
            $stmt->fetchAll()
        );

        $overall = 'pending';
        if ($statuses !== []) {
            if (in_array('rejected', $statuses, true)) {
                $overall = 'rejected';
            } elseif (count(array_unique($statuses)) === 1 && $statuses[0] === 'cleared') {
                $overall = 'cleared';
            } elseif (in_array('for_review', $statuses, true) || in_array('cleared', $statuses, true)) {
                $overall = 'for_review';
            }
        }

        $upsert = $this->pdo->prepare("
            INSERT INTO student_semester_clearances (semester_id, student_id, overall_status)
            VALUES (:semester_id, :student_id, :overall_status)
            ON DUPLICATE KEY UPDATE overall_status = VALUES(overall_status), updated_at = CURRENT_TIMESTAMP
        ");
        $upsert->execute([
            'semester_id' => $semesterId,
            'student_id' => $studentId,
            'overall_status' => $overall,
        ]);
    }

    private function isOfficeUnlocked(int $officeId, int $studentId, int $semesterId): bool
    {
        return true;
    }

    public function studentRequiresAccountingClearance(int $studentId): bool
    {
        if ($studentId <= 0) {
            return true;
        }

        $stmt = $this->pdo->prepare("
            SELECT student_account_type
            FROM users
            WHERE id = :student_id
              AND role = 'student'
            LIMIT 1
        ");
        $stmt->execute(['student_id' => $studentId]);

        return (string) ($stmt->fetchColumn() ?: 'paying_tuition') !== 'not_paying_tuition';
    }

    public function studentRequiresDormitoryClearance(int $studentId): bool
    {
        if ($studentId <= 0) {
            return true;
        }

        $stmt = $this->pdo->prepare("
            SELECT student_staying
            FROM users
            WHERE id = :student_id
              AND role = 'student'
            LIMIT 1
        ");
        $stmt->execute(['student_id' => $studentId]);

        return (string) ($stmt->fetchColumn() ?: '') === 'wpu_dormitory';
    }

    /**
     * @param list<array<string, mixed>> $groups
     * @return list<array<string, mixed>>
     */
    private function filterStudentDashboardRequirementGroups(array $groups, int $studentId): array
    {
        return array_values(array_filter(
            $groups,
            function (array $group) use ($studentId): bool {
                $code = strtoupper(trim((string) ($group['office_code'] ?? '')));
                if ($code === self::ACCOUNTING_OFFICE_CODE && !$this->studentRequiresAccountingClearance($studentId)) {
                    return false;
                }
                if ($code === self::DORMITORY_OFFICE_CODE && !$this->studentRequiresDormitoryClearance($studentId)) {
                    return false;
                }

                return true;
            }
        ));
    }

    /**
     * @param list<array<string, mixed>> $offices
     * @return list<array<string, mixed>>
     */
    private function filterStudentDashboardOffices(array $offices, int $studentId): array
    {
        return array_values(array_filter(
            $offices,
            function (array $office) use ($studentId): bool {
                $code = strtoupper(trim((string) ($office['office_code'] ?? '')));
                if ($code === self::ACCOUNTING_OFFICE_CODE && !$this->studentRequiresAccountingClearance($studentId)) {
                    return false;
                }
                if ($code === self::DORMITORY_OFFICE_CODE && !$this->studentRequiresDormitoryClearance($studentId)) {
                    return false;
                }

                return true;
            }
        ));
    }

    /**
     * @return list<string>
     */
    private function getSasPrerequisiteOfficeCodesForStudent(int $studentId): array
    {
        return array_map(
            static fn(array $office): string => strtoupper(trim((string) ($office['code'] ?? ''))),
            $this->getSasPrerequisiteOfficesForStudent($studentId)
        );
    }

    private function getOfficeIdByCode(string $code): int
    {
        $stmt = $this->pdo->prepare('
            SELECT id
            FROM offices
            WHERE UPPER(code) = :code
              AND is_active = 1
            LIMIT 1
        ');
        $stmt->execute(['code' => strtoupper(trim($code))]);

        return (int) ($stmt->fetchColumn() ?: 0);
    }

    private function generateAdditionalOfficeCode(string $parentCode, string $unitName): string
    {
        $prefix = $parentCode === 'SAS' ? 'SASU' : 'DEANU';
        $slug = preg_replace('/[^A-Z0-9]+/', '_', strtoupper($unitName)) ?? '';
        $slug = trim((string) $slug, '_');
        if ($slug === '') {
            $slug = 'UNIT';
        }
        $slug = substr($slug, 0, 24);
        $base = $prefix . '_' . $slug;
        $candidate = $base;
        $suffix = 1;
        $check = $this->pdo->prepare('SELECT 1 FROM offices WHERE UPPER(code) = :code LIMIT 1');
        while (true) {
            $check->execute(['code' => strtoupper($candidate)]);
            if (!$check->fetchColumn()) {
                return strtoupper(substr($candidate, 0, 40));
            }
            $candidate = $base . '_' . $suffix;
            $suffix++;
        }
    }

    private function allocateChildOfficeSequenceNo(int $parentOfficeId): int
    {
        $parentStmt = $this->pdo->prepare('SELECT sequence_no, code FROM offices WHERE id = :id LIMIT 1');
        $parentStmt->execute(['id' => $parentOfficeId]);
        $parent = $parentStmt->fetch();
        if (!$parent) {
            return 100;
        }

        $parentSeq = (int) ($parent['sequence_no'] ?? 0);
        $maxStmt = $this->pdo->prepare('
            SELECT MAX(sequence_no)
            FROM offices
            WHERE parent_office_id = :parent_office_id
              AND is_active = 1
        ');
        $maxStmt->execute(['parent_office_id' => $parentOfficeId]);
        $maxChildSeq = (int) ($maxStmt->fetchColumn() ?: 0);

        if ($maxChildSeq <= 0) {
            $parentCode = strtoupper(trim((string) ($parent['code'] ?? '')));
            $legacyChildCodes = match ($parentCode) {
                'SAS' => self::SAS_PREREQUISITE_OFFICE_CODES,
                'DEAN' => ['LIB'],
                default => [],
            };
            if ($legacyChildCodes !== []) {
                $placeholders = [];
                $bindings = [];
                foreach ($legacyChildCodes as $idx => $code) {
                    $key = 'code_' . $idx;
                    $placeholders[] = ':' . $key;
                    $bindings[$key] = $code;
                }
                $legacyStmt = $this->pdo->prepare('
                    SELECT MAX(sequence_no)
                    FROM offices
                    WHERE UPPER(code) IN (' . implode(', ', $placeholders) . ')
                      AND is_active = 1
                ');
                $legacyStmt->execute($bindings);
                $maxChildSeq = (int) ($legacyStmt->fetchColumn() ?: 0);
            }
        }

        $newSeq = $maxChildSeq > 0 ? $maxChildSeq + 1 : max(1, $parentSeq - 1);
        if ($parentSeq > 0 && $newSeq >= $parentSeq) {
            $newSeq = max(1, $parentSeq - 1);
        }

        $this->pdo->prepare('
            UPDATE offices
            SET sequence_no = sequence_no + 1
            WHERE sequence_no >= :sequence_no
              AND is_active = 1
        ')->execute(['sequence_no' => $newSeq]);

        return $newSeq;
    }

    private function ensureOfficeParentColumn(): void
    {
        try {
            $this->pdo->exec('
                ALTER TABLE offices
                ADD COLUMN parent_office_id INT UNSIGNED NULL AFTER sequence_no
            ');
        } catch (\Throwable) {
        }

        try {
            $this->pdo->exec('
                ALTER TABLE offices
                ADD CONSTRAINT fk_office_parent
                FOREIGN KEY (parent_office_id) REFERENCES offices(id)
            ');
        } catch (\Throwable) {
        }
    }

    private function ensureDefaultOfficeParentLinks(): void
    {
        static $checked = false;
        if ($checked) {
            return;
        }
        $checked = true;

        $links = [
            'SAS' => ['SSC', 'DORM', 'ACCT', 'SOA'],
            'DEAN' => ['LIB'],
        ];
        $parentStmt = $this->pdo->prepare('SELECT id FROM offices WHERE UPPER(code) = :code LIMIT 1');
        $childStmt = $this->pdo->prepare('
            UPDATE offices
            SET parent_office_id = :parent_office_id
            WHERE UPPER(code) = :code
              AND (parent_office_id IS NULL OR parent_office_id = 0)
        ');
        foreach ($links as $parentCode => $childCodes) {
            $parentStmt->execute(['code' => $parentCode]);
            $parentOfficeId = (int) ($parentStmt->fetchColumn() ?: 0);
            if ($parentOfficeId <= 0) {
                continue;
            }
            foreach ($childCodes as $childCode) {
                $childStmt->execute([
                    'parent_office_id' => $parentOfficeId,
                    'code' => $childCode,
                ]);
            }
        }
    }

    private function isAssignedSignatory(int $userId, int $officeId, int $semesterId): bool
    {
        $stmt = $this->pdo->prepare("
            SELECT 1
            FROM office_signatories
            WHERE user_id = :user_id
              AND office_id = :office_id
              AND semester_id = :semester_id
            LIMIT 1
        ");
        $stmt->execute([
            'user_id' => $userId,
            'office_id' => $officeId,
            'semester_id' => $semesterId,
        ]);
        return (bool) $stmt->fetchColumn();
    }

    private function hasCompletedAllOfficeRequirements(int $officeId, int $studentId, int $semesterId): bool
    {
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) AS required_count
            FROM office_requirements
            WHERE office_id = :office_id
              AND semester_id = :semester_id
              AND is_active = 1
        ");
        $stmt->execute([
            'office_id' => $officeId,
            'semester_id' => $semesterId,
        ]);
        $requiredCount = (int) $stmt->fetchColumn();
        if ($requiredCount <= 0) {
            return true;
        }

        $submittedStmt = $this->pdo->prepare("
            SELECT COUNT(*) AS submitted_count
            FROM office_requirements r
            WHERE r.office_id = :office_id
              AND r.semester_id = :semester_id
              AND r.is_active = 1
              AND EXISTS (
                    SELECT 1
                    FROM requirement_submissions rs
                    WHERE rs.office_requirement_id = r.id
                      AND rs.student_id = :student_id
                      AND rs.semester_id = :semester_id_2
                )
        ");
        $submittedStmt->execute([
            'office_id' => $officeId,
            'semester_id' => $semesterId,
            'student_id' => $studentId,
            'semester_id_2' => $semesterId,
        ]);
        $submittedCount = (int) $submittedStmt->fetchColumn();
        return $submittedCount >= $requiredCount;
    }

    private function hasCompletedAllStudentAttachedRequirements(int $officeId, int $studentId, int $semesterId): bool
    {
        if (!$this->tableExists('student_office_requirements')) {
            return true;
        }
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) AS total_count,
                   SUM(CASE WHEN is_completed = 1 THEN 1 ELSE 0 END) AS completed_count
            FROM student_office_requirements
            WHERE office_id = :office_id
              AND student_id = :student_id
              AND semester_id = :semester_id
        ");
        $stmt->execute([
            'office_id' => $officeId,
            'student_id' => $studentId,
            'semester_id' => $semesterId,
        ]);
        $row = $stmt->fetch();
        $totalCount = (int) ($row['total_count'] ?? 0);
        if ($totalCount <= 0) {
            return true;
        }
        $completedCount = (int) ($row['completed_count'] ?? 0);

        return $completedCount >= $totalCount;
    }

    private function primeNextOfficeStep(int $officeId, int $studentId, int $semesterId): void
    {
        $sequenceStmt = $this->pdo->prepare('SELECT sequence_no FROM offices WHERE id = :office_id LIMIT 1');
        $sequenceStmt->execute(['office_id' => $officeId]);
        $currentSequence = (int) $sequenceStmt->fetchColumn();
        if ($currentSequence <= 0) {
            return;
        }

        $nextStmt = $this->pdo->prepare('
            SELECT id
            FROM offices
            WHERE is_active = 1
              AND sequence_no = :next_sequence
            LIMIT 1
        ');
        $nextStmt->execute(['next_sequence' => $currentSequence + 1]);
        $nextOfficeId = (int) $nextStmt->fetchColumn();
        if ($nextOfficeId <= 0) {
            return;
        }

        $checkStmt = $this->pdo->prepare('
            SELECT 1
            FROM student_clearances
            WHERE semester_id = :semester_id
              AND student_id = :student_id
              AND office_id = :office_id
            LIMIT 1
        ');
        $checkStmt->execute([
            'semester_id' => $semesterId,
            'student_id' => $studentId,
            'office_id' => $nextOfficeId,
        ]);
        if ($checkStmt->fetchColumn()) {
            return;
        }
        $this->upsertOfficeStatus($semesterId, $studentId, $nextOfficeId, 'pending');
    }

    private function upsertOfficeStatus(int $semesterId, int $studentId, int $officeId, string $status): void
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO student_clearances
                (semester_id, student_id, office_id, status, decided_at)
            VALUES
                (:semester_id, :student_id, :office_id, :status, NOW())
            ON DUPLICATE KEY UPDATE
                status = VALUES(status),
                decided_at = VALUES(decided_at)
        ");
        $stmt->execute([
            'semester_id' => $semesterId,
            'student_id' => $studentId,
            'office_id' => $officeId,
            'status' => $status,
        ]);
    }

    private function createNotification(
        int $userId,
        string $type,
        string $title,
        string $body,
        ?int $officeId = null
    ): void {
        $sql = "
            INSERT INTO notifications (user_id, type, title, body, related_office_id)
            VALUES (:user_id, :type, :title, :body, :office_id)
        ";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            'user_id' => $userId,
            'type' => $type,
            'title' => $title,
            'body' => $body,
            'office_id' => $officeId,
        ]);

        // FIFO retention: keep only the 5 most recent notifications per user.
        $trimStmt = $this->pdo->prepare("
            DELETE FROM notifications
            WHERE user_id = :user_id
              AND id IN (
                  SELECT id_to_delete FROM (
                      SELECT id AS id_to_delete
                      FROM notifications
                      WHERE user_id = :user_id
                      ORDER BY id DESC
                      LIMIT 18446744073709551615 OFFSET 5
                  ) old_rows
              )
        ");
        $trimStmt->execute(['user_id' => $userId]);
    }

    private function getOfficeNameById(int $officeId): ?string
    {
        if ($officeId <= 0) {
            return null;
        }

        $stmt = $this->pdo->prepare('
            SELECT name
            FROM offices
            WHERE id = :office_id
            LIMIT 1
        ');
        $stmt->execute(['office_id' => $officeId]);
        $value = $stmt->fetchColumn();
        if (!is_string($value) || trim($value) === '') {
            return null;
        }

        return trim($value);
    }

    private function storeRequirementAttachment(?array $file, int $officeId, int $semesterId): array
    {
        if ($file === null || !isset($file['error']) || (int) $file['error'] === UPLOAD_ERR_NO_FILE) {
            return ['ok' => true, 'path' => null, 'name' => null];
        }
        if ((int) $file['error'] !== UPLOAD_ERR_OK) {
            return ['ok' => false, 'message' => 'Failed to upload requirement attachment.'];
        }

        $size = (int) ($file['size'] ?? 0);
        if ($size <= 0 || $size > 10 * 1024 * 1024) {
            return ['ok' => false, 'message' => 'Attachment must be up to 10MB.'];
        }

        $storageDir = dirname(__DIR__, 2) . '/storage/requirement-attachments';
        if (!is_dir($storageDir)) {
            mkdir($storageDir, 0775, true);
        }

        $originalName = (string) ($file['name'] ?? 'attachment');
        $ext = pathinfo($originalName, PATHINFO_EXTENSION);
        $safeExt = preg_replace('/[^a-zA-Z0-9]/', '', $ext) ?: 'bin';
        $safeName = sprintf(
            'req_%d_%d_%s.%s',
            $officeId,
            $semesterId,
            (new DateTime())->format('YmdHisv'),
            $safeExt
        );
        $targetAbsolute = $storageDir . '/' . $safeName;
        if (!move_uploaded_file((string) ($file['tmp_name'] ?? ''), $targetAbsolute)) {
            return ['ok' => false, 'message' => 'Could not store requirement attachment.'];
        }

        return [
            'ok' => true,
            'path' => 'storage/requirement-attachments/' . $safeName,
            'name' => $originalName,
        ];
    }

    private function deleteStoredProfilePhoto(string $relativePath): void
    {
        $relativePath = ltrim(str_replace('\\', '/', $relativePath), '/');
        if ($relativePath === '' || !str_starts_with($relativePath, 'storage/profile-photos/')) {
            return;
        }
        $absolute = dirname(__DIR__, 2) . '/' . $relativePath;
        if (is_file($absolute)) {
            @unlink($absolute);
        }
    }

    private function deleteStoredSubmissionFile(string $relativePath): void
    {
        $relativePath = ltrim(str_replace('\\', '/', $relativePath), '/');
        if ($relativePath === '' || !str_starts_with($relativePath, 'storage/')) {
            return;
        }
        $absolute = dirname(__DIR__, 2) . '/' . $relativePath;
        if (is_file($absolute)) {
            @unlink($absolute);
        }
    }

    private function ensureStudentRegistrationStatusColumn(): void
    {
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*) FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :tbl AND COLUMN_NAME = :col'
        );
        $stmt->execute(['tbl' => 'users', 'col' => 'registration_status']);
        if ((int) $stmt->fetchColumn() > 0) {
            return;
        }
        $this->pdo->exec("
            ALTER TABLE users
            ADD COLUMN registration_status ENUM('approved', 'pending', 'rejected') NOT NULL DEFAULT 'approved'
            AFTER is_active
        ");
    }

    private function ensureUserProfilePhotoColumn(): void
    {
        try {
            $this->pdo->exec('ALTER TABLE users ADD COLUMN profile_photo_path VARCHAR(255) NULL AFTER year_level');
        } catch (\Throwable) {
        }
    }

    private function ensureRequirementAttachmentColumns(): void
    {
        try {
            $this->pdo->exec("
                ALTER TABLE office_requirements
                ADD COLUMN attachment_path VARCHAR(255) NULL AFTER description
            ");
        } catch (\Throwable $e) {
        }

        try {
            $this->pdo->exec("
                ALTER TABLE office_requirements
                ADD COLUMN attachment_name VARCHAR(255) NULL AFTER attachment_path
            ");
        } catch (\Throwable $e) {
        }
    }

    private function ensureStudentOfficeRequirementsTable(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS student_office_requirements (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                semester_id BIGINT UNSIGNED NOT NULL,
                student_id BIGINT UNSIGNED NOT NULL,
                office_id INT UNSIGNED NOT NULL,
                requirement_text VARCHAR(255) NOT NULL,
                attachment_path VARCHAR(255) NULL,
                attachment_name VARCHAR(255) NULL,
                is_completed TINYINT(1) NOT NULL DEFAULT 0,
                created_by BIGINT UNSIGNED NULL,
                completed_at DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_sor_lookup (semester_id, student_id, office_id),
                CONSTRAINT fk_sor_semester FOREIGN KEY (semester_id) REFERENCES semesters(id),
                CONSTRAINT fk_sor_student FOREIGN KEY (student_id) REFERENCES users(id),
                CONSTRAINT fk_sor_office FOREIGN KEY (office_id) REFERENCES offices(id),
                CONSTRAINT fk_sor_creator FOREIGN KEY (created_by) REFERENCES users(id)
            )
        ");
    }

    private function ensureStudentOfficeRequirementAttachmentColumns(): void
    {
        if (!$this->tableExists('student_office_requirements')) {
            return;
        }

        try {
            $this->pdo->exec("
                ALTER TABLE student_office_requirements
                ADD COLUMN attachment_path VARCHAR(255) NULL AFTER requirement_text
            ");
        } catch (\Throwable) {
        }

        try {
            $this->pdo->exec("
                ALTER TABLE student_office_requirements
                ADD COLUMN attachment_name VARCHAR(255) NULL AFTER attachment_path
            ");
        } catch (\Throwable) {
        }
    }

    public function getSignatorySignaturePath(int $signatoryUserId, int $semesterId): ?string
    {
        $stmt = $this->pdo->prepare("
            SELECT signature_file
            FROM signatory_signatures
            WHERE signatory_user_id = :signatory_user_id AND semester_id = :semester_id
            LIMIT 1
        ");
        $stmt->execute([
            'signatory_user_id' => $signatoryUserId,
            'semester_id' => $semesterId,
        ]);
        $value = $stmt->fetchColumn();
        if (!is_string($value) || trim($value) === '') {
            return null;
        }
        return trim($value);
    }

    private function ensureClearanceMessagingTables(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS clearance_message_threads (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                semester_id BIGINT UNSIGNED NOT NULL,
                student_id BIGINT UNSIGNED NOT NULL,
                signatory_user_id BIGINT UNSIGNED NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_clearance_msg_thread_recipient (semester_id, student_id, signatory_user_id),
                INDEX idx_clearance_msg_thread_sem (semester_id),
                INDEX idx_clearance_msg_thread_sig (signatory_user_id),
                CONSTRAINT fk_cmt_sem FOREIGN KEY (semester_id) REFERENCES semesters(id),
                CONSTRAINT fk_cmt_stu FOREIGN KEY (student_id) REFERENCES users(id),
                CONSTRAINT fk_cmt_sig FOREIGN KEY (signatory_user_id) REFERENCES users(id)
            )
        ");
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS clearance_messages (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                thread_id BIGINT UNSIGNED NOT NULL,
                sender_user_id BIGINT UNSIGNED NOT NULL,
                body TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_clearance_msg_thread_created (thread_id, id),
                CONSTRAINT fk_cm_thread FOREIGN KEY (thread_id) REFERENCES clearance_message_threads(id) ON DELETE CASCADE,
                CONSTRAINT fk_cm_sender FOREIGN KEY (sender_user_id) REFERENCES users(id)
            )
        ");
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS clearance_message_thread_reads (
                thread_id BIGINT UNSIGNED NOT NULL,
                user_id BIGINT UNSIGNED NOT NULL,
                last_read_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (thread_id, user_id),
                CONSTRAINT fk_cmtr_thread FOREIGN KEY (thread_id) REFERENCES clearance_message_threads(id) ON DELETE CASCADE,
                CONSTRAINT fk_cmtr_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ");
    }

    /**
     * Upgrade older installs where clearance_message_threads had no signatory_user_id (broadcast model).
     */
    private function migrateClearanceMessageThreadsAddRecipient(): void
    {
        try {
            $tbl = $this->pdo->query("SHOW TABLES LIKE 'clearance_message_threads'");
            if (!$tbl || !$tbl->fetch()) {
                return;
            }
            $chk = $this->pdo->query("SHOW COLUMNS FROM clearance_message_threads LIKE 'signatory_user_id'");
            if ($chk && $chk->fetch()) {
                return;
            }
        } catch (\Throwable) {
            return;
        }

        $this->pdo->exec('SET FOREIGN_KEY_CHECKS=0');
        try {
            $this->pdo->exec('TRUNCATE TABLE clearance_message_thread_reads');
            $this->pdo->exec('TRUNCATE TABLE clearance_messages');
            $this->pdo->exec('TRUNCATE TABLE clearance_message_threads');
        } catch (\Throwable) {
            // continue; table may be empty or engine-specific
        }
        $this->pdo->exec('SET FOREIGN_KEY_CHECKS=1');

        try {
            $this->pdo->exec('ALTER TABLE clearance_message_threads DROP INDEX uniq_clearance_msg_thread');
        } catch (\Throwable) {
            // index may not exist
        }

        try {
            $this->pdo->exec('
                ALTER TABLE clearance_message_threads
                ADD COLUMN signatory_user_id BIGINT UNSIGNED NOT NULL AFTER student_id
            ');
        } catch (\Throwable) {
            // column may already exist
        }

        try {
            $this->pdo->exec('
                ALTER TABLE clearance_message_threads
                ADD UNIQUE KEY uniq_clearance_msg_thread_recipient (semester_id, student_id, signatory_user_id)
            ');
        } catch (\Throwable) {
            // already added
        }

        try {
            $this->pdo->exec('ALTER TABLE clearance_message_threads ADD INDEX idx_clearance_msg_thread_sig (signatory_user_id)');
        } catch (\Throwable) {
        }

        try {
            $this->pdo->exec('
                ALTER TABLE clearance_message_threads
                ADD CONSTRAINT fk_cmt_sig FOREIGN KEY (signatory_user_id) REFERENCES users(id)
            ');
        } catch (\Throwable) {
        }
    }

    private function ensureSignatorySignatureTable(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS signatory_signatures (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                semester_id BIGINT UNSIGNED NOT NULL,
                signatory_user_id BIGINT UNSIGNED NOT NULL,
                signature_file VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_signature_semester_signatory (semester_id, signatory_user_id),
                CONSTRAINT fk_signatory_sig_semester FOREIGN KEY (semester_id) REFERENCES semesters(id),
                CONSTRAINT fk_signatory_sig_user FOREIGN KEY (signatory_user_id) REFERENCES users(id)
            )
        ");
    }

    private function ensurePasswordResetTable(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS password_resets (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT UNSIGNED NOT NULL,
                email VARCHAR(255) NOT NULL,
                token_hash CHAR(64) NOT NULL,
                expires_at DATETIME NOT NULL,
                used_at DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_password_resets_user_id (user_id),
                UNIQUE KEY uniq_password_resets_token_hash (token_hash),
                CONSTRAINT fk_password_resets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ");
    }

    private function ensureNotificationFifoGuard(): void
    {
        try {
            $this->pdo->exec('
                ALTER TABLE notifications
                ADD INDEX idx_notifications_user_id_id (user_id, id)
            ');
        } catch (\Throwable) {
            // index may already exist
        }

        try {
            $this->pdo->exec('DROP TRIGGER IF EXISTS trg_notifications_fifo_after_insert');
        } catch (\Throwable) {
            // skip if trigger drop is not permitted in this environment
        }
    }

    private function ensureSasPrerequisiteOffices(): void
    {
        static $checked = false;
        if ($checked) {
            return;
        }
        $checked = true;

        $definitions = [
            ['DORM', 'Dormitory Coordinator', 2],
            ['ACCT', 'Accounting', 3],
            ['SOA', 'Students Organization Association', 4],
        ];

        $upsert = $this->pdo->prepare('
            INSERT INTO offices (code, name, sequence_no, is_active)
            VALUES (:code, :name, :sequence_no, 1)
            ON DUPLICATE KEY UPDATE
                name = VALUES(name),
                is_active = 1
        ');
        foreach ($definitions as [$code, $name, $sequenceNo]) {
            $upsert->execute([
                'code' => $code,
                'name' => $name,
                'sequence_no' => $sequenceNo,
            ]);
        }

        $sequenceByCode = [
            'SSC' => 1,
            'DORM' => 2,
            'ACCT' => 3,
            'SOA' => 4,
            'LIB' => 5,
            'SAS' => 6,
            'DEAN' => 7,
        ];
        $update = $this->pdo->prepare('UPDATE offices SET sequence_no = :sequence_no WHERE code = :code');
        foreach ($sequenceByCode as $code => $sequenceNo) {
            $update->execute([
                'code' => $code,
                'sequence_no' => $sequenceNo,
            ]);
        }
    }

    /**
     * @return array{
     *   has_deadline:bool,
     *   due_date:string,
     *   due_date_label:string,
     *   is_expired:bool,
     *   is_window_open:bool,
     *   days_remaining:int,
     *   status_label:string,
     *   banner_class:string,
     *   banner_message:string
     * }
     */
    private function buildSemesterDeadlineStatus(string $dueDate, int $clearanceWindowActive): array
    {
        $due = DateTime::createFromFormat('Y-m-d', $dueDate) ?: new DateTime($dueDate);
        $today = new DateTime('today');
        $due->setTime(0, 0, 0);
        $daysRemaining = (int) $today->diff($due)->format('%r%a');
        $isExpired = $daysRemaining < 0;
        $isWindowOpen = !$isExpired || $clearanceWindowActive === 1;
        $dueDateLabel = $due->format('F j, Y');

        if ($isExpired) {
            if ($isWindowOpen) {
                $statusLabel = 'Reactivated after deadline';
                $bannerClass = 'alert-warning';
                $bannerMessage = sprintf(
                    'The completion deadline was %s. The clearance window has been reactivated—please finish pending items as soon as possible.',
                    $dueDateLabel
                );
            } else {
                $statusLabel = 'Closed after deadline';
                $bannerClass = 'alert-danger';
                $bannerMessage = sprintf(
                    'The completion deadline was %s. The clearance window is currently closed.',
                    $dueDateLabel
                );
            }
        } elseif ($daysRemaining === 0) {
            $statusLabel = 'Due today';
            $bannerClass = 'alert-warning';
            $bannerMessage = sprintf('Today is the clearance completion deadline (%s).', $dueDateLabel);
        } else {
            $statusLabel = 'Active';
            $bannerClass = 'alert-info';
            $bannerMessage = sprintf(
                'Complete your clearance by %s (%d day(s) remaining).',
                $dueDateLabel,
                $daysRemaining
            );
        }

        return [
            'has_deadline' => true,
            'due_date' => $dueDate,
            'due_date_label' => $dueDateLabel,
            'is_expired' => $isExpired,
            'is_window_open' => $isWindowOpen,
            'days_remaining' => max(0, $daysRemaining),
            'status_label' => $statusLabel,
            'banner_class' => $bannerClass,
            'banner_message' => $bannerMessage,
        ];
    }

    /**
     * @return list<int>
     */
    private function listDeadlineNotificationRecipientIds(int $semesterId): array
    {
        $studentStmt = $this->pdo->query("
            SELECT id
            FROM users
            WHERE role = 'student'
              AND is_active = 1
        ");
        $studentRows = $studentStmt ? $studentStmt->fetchAll() : [];
        $signatoryStmt = $this->pdo->prepare("
            SELECT DISTINCT u.id
            FROM users u
            INNER JOIN office_signatories os ON os.user_id = u.id
            WHERE os.semester_id = :semester_id
              AND u.role = 'signatory'
              AND u.is_active = 1
        ");
        $signatoryStmt->execute(['semester_id' => $semesterId]);
        $signatoryRows = $signatoryStmt->fetchAll();

        $recipientIds = [];
        foreach (array_merge(is_array($studentRows) ? $studentRows : [], is_array($signatoryRows) ? $signatoryRows : []) as $row) {
            $recipientIds[(int) ($row['id'] ?? 0)] = true;
        }

        return array_map('intval', array_keys($recipientIds));
    }

    private function ensureSemesterDeadlineColumns(): void
    {
        try {
            $this->pdo->exec('
                ALTER TABLE semesters
                ADD COLUMN clearance_window_active TINYINT(1) NOT NULL DEFAULT 1 AFTER ends_at
            ');
        } catch (\Throwable) {
            // column may already exist
        }
    }

    private function ensureSemesterDeadlineNotificationLogTable(): void
    {
        $this->pdo->exec('
            CREATE TABLE IF NOT EXISTS semester_deadline_notification_log (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                semester_id BIGINT UNSIGNED NOT NULL,
                notified_on DATE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_semester_notified_on (semester_id, notified_on),
                CONSTRAINT fk_sdln_semester FOREIGN KEY (semester_id) REFERENCES semesters(id) ON DELETE CASCADE
            )
        ');
    }
}
