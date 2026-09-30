<?php

declare(strict_types=1);

if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php';
}
require_once __DIR__ . '/../src/Config/LoadLocalEnv.php';
\App\Config\LoadLocalEnv::load(dirname(__DIR__) . '/.env');
require_once __DIR__ . '/../src/Config/Database.php';
require_once __DIR__ . '/../src/Services/ClearanceService.php';
require_once __DIR__ . '/../src/Services/StudentCsvImporter.php';
require_once __DIR__ . '/../src/Support/StudentPwa.php';

use App\Config\Database;
use App\Mail\PasswordResetEmail;
use App\Security\AuthLayer;
use App\Security\RateLimiter;
use App\Services\ClearanceService;
use App\Services\StudentCsvImporter;
use App\Support\SignatureImage;
use App\Support\StudentPwa;

AuthLayer::boot();

$pdo = Database::pdo();
$service = new ClearanceService($pdo);
$rateLimiter = new RateLimiter($pdo);

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$scriptName = str_replace('\\', '/', (string) ($_SERVER['SCRIPT_NAME'] ?? '/index.php'));
$appBasePath = rtrim(dirname($scriptName), '/');
if ($appBasePath === '' || $appBasePath === '/' || $appBasePath === '.') {
    $appBasePath = '';
}

function app_path(string $path): string
{
    global $appBasePath;
    $path = str_replace('\\', '/', $path);
    if ($path === '' || $path[0] !== '/') {
        $path = '/' . ltrim($path, '/');
    }

    return $appBasePath . $path;
}

function hpath(string $path): string
{
    return htmlspecialchars(app_path($path), ENT_QUOTES, 'UTF-8');
}

function asset_path(string $file): string
{
    global $appBasePath;
    $file = ltrim(str_replace('\\', '/', $file), '/');
    if ($appBasePath !== '' && str_ends_with($appBasePath, '/public')) {
        return app_path('/assets/' . $file);
    }

    return app_path('/public/assets/' . $file);
}

function hasset(string $file): string
{
    return htmlspecialchars(asset_path($file), ENT_QUOTES, 'UTF-8');
}

function csrf_field(): string
{
    return AuthLayer::csrfField();
}

function capitalizeInputStart(string $value, bool $multiline = false): string
{
    if ($value === '') {
        return $value;
    }

    if ($multiline) {
        return (string) preg_replace_callback(
            '/(^|[\r\n]+)(\s*)([a-z])/u',
            static fn (array $m): string => $m[1] . $m[2] . mb_strtoupper((string) $m[3], 'UTF-8'),
            $value
        );
    }

    return (string) preg_replace_callback(
        '/^(\s*)([a-z])/u',
        static fn (array $m): string => $m[1] . mb_strtoupper((string) $m[2], 'UTF-8'),
        $value
    );
}

function postCapitalized(string $key, bool $multiline = false): string
{
    return capitalizeInputStart(trim((string) ($_POST[$key] ?? '')), $multiline);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
$path = str_replace('\\', '/', (string) $path);
if ($appBasePath !== '' && str_starts_with($path, $appBasePath)) {
    $path = substr($path, strlen($appBasePath));
    if ($path === '') {
        $path = '/';
    }
}

if (str_starts_with($path, '/index.php')) {
    $path = substr($path, strlen('/index.php'));
    $path = $path === '' ? '/' : $path;
}

// Normalize trailing slash so "/dashboard/" matches "/dashboard" routes.
if ($path !== '/') {
    $path = rtrim($path, '/');
    if ($path === '') {
        $path = '/';
    }
}

$GLOBALS['_app_request_path'] = $path;

if ($method === 'POST' && !AuthLayer::csrfIsValid()) {
    $csrfError = AuthLayer::expired()
        ? 'Your session expired. Please sign in again.'
        : 'Your session expired or this request could not be verified. Please try again.';
    if (isJsonApiPath($path) || requestWantsJson()) {
        http_response_code(403);
        json(['ok' => false, 'error' => $csrfError]);
        exit;
    }
    if ($path === '/app') {
        renderPage('Student App', renderStudentAppLogin($csrfError));
        exit;
    }
    if ($path === '/forgot-password') {
        renderPage('Forgot Password', renderForgotPasswordForm($csrfError, null));
        exit;
    }
    if ($path === '/reset-password') {
        renderPage('Reset Password', renderResetPasswordForm(trim((string) ($_POST['token'] ?? '')), $csrfError, null));
        exit;
    }
    if ($path === '/login' || !isset($_SESSION['user'])) {
        renderPage('Login', renderLoginForm($csrfError, buildLoginStats($service)));
        exit;
    }
    $_SESSION['flash'] = $csrfError;
    header('Location: ' . app_path('/dashboard'));
    exit;
}

if ($path === '/manifest.webmanifest' && $method === 'GET') {
    header('Content-Type: application/manifest+json; charset=utf-8');
    header('Cache-Control: no-cache');
    echo json_encode(StudentPwa::manifest($appBasePath, 'app_path'), JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

if ($path === '/sw.js' && $method === 'GET') {
    header('Content-Type: application/javascript; charset=utf-8');
    header('Service-Worker-Allowed: ' . StudentPwa::scope($appBasePath));
    header('Cache-Control: no-cache');
    echo StudentPwa::serviceWorker($appBasePath, 'app_path');
    exit;
}

if ($method === 'GET' && preg_match('#^/app/icon/(192|512)$#', $path, $iconMatch) === 1) {
    $iconFile = StudentPwa::iconPath((int) $iconMatch[1]);
    header('Content-Type: image/png');
    header('Cache-Control: public, max-age=86400');
    header('Content-Length: ' . (string) filesize($iconFile));
    readfile($iconFile);
    exit;
}

if ($path === '/app/offline' && $method === 'GET') {
    header('Content-Type: text/html; charset=UTF-8');
    echo StudentPwa::offlinePage('SAFE Student', app_path('/app'));
    exit;
}

if ($path === '/app' && $method === 'GET') {
    if (isset($_SESSION['user'])) {
        if ((string) ($_SESSION['user']['role'] ?? '') === 'student') {
            header('Location: ' . app_path('/dashboard'));
            exit;
        }
        renderPage('Student App', renderStudentAppStaffBlocked($_SESSION['user']));
        exit;
    }
    renderPage('Student App', renderStudentAppLogin(null));
    exit;
}

if ($path === '/app' && $method === 'POST') {
    if (isset($_SESSION['user']) && (string) ($_SESSION['user']['role'] ?? '') === 'student') {
        header('Location: ' . app_path('/dashboard'));
        exit;
    }
    $email = trim((string) ($_POST['email'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $ip = AuthLayer::clientIp();
    $blocked = $rateLimiter->loginBlocked($ip, $email);
    if ($blocked !== null) {
        renderPage('Student App', renderStudentAppLogin($blocked));
        exit;
    }
    $user = $service->authenticate($email, $password);
    if (!$user) {
        $rateLimiter->recordLoginFailure($ip, $email);
        renderPage('Student App', renderStudentAppLogin('Invalid credentials or inactive account.'));
        exit;
    }
    if ((string) ($user['role'] ?? '') !== 'student') {
        renderPage(
            'Student App',
            renderStudentAppLogin('This app is for student accounts only. Signatories and admins should use the staff web portal.')
        );
        exit;
    }
    $rateLimiter->clearLoginFailures($email);
    AuthLayer::login($user);
    header('Location: ' . app_path('/dashboard'));
    exit;
}

if ($path === '/' && $method === 'GET') {
    if (!isset($_SESSION['user'])) {
        header('Location: ' . app_path('/login'));
        exit;
    }
    header('Location: ' . app_path('/dashboard'));
    exit;
}

if ($path === '/login' && $method === 'GET') {
    renderPage('Login', renderLoginForm(null, buildLoginStats($service)));
    exit;
}

if ($path === '/login' && $method === 'POST') {
    $email = trim((string) ($_POST['email'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $ip = AuthLayer::clientIp();
    $blocked = $rateLimiter->loginBlocked($ip, $email);
    if ($blocked !== null) {
        renderPage('Login', renderLoginForm($blocked, buildLoginStats($service)));
        exit;
    }
    $user = $service->authenticate($email, $password);
    if (!$user) {
        $rateLimiter->recordLoginFailure($ip, $email);
        renderPage('Login', renderLoginForm('Invalid credentials or inactive account.', buildLoginStats($service)));
        exit;
    }
    $rateLimiter->clearLoginFailures($email);
    AuthLayer::login($user);
    header('Location: ' . app_path('/dashboard'));
    exit;
}

if ($path === '/logout' && $method === 'POST') {
    $logoutRole = (string) ($_SESSION['user']['role'] ?? '');
    AuthLayer::logout();
    header('Location: ' . app_path($logoutRole === 'student' ? '/app' : '/login'));
    exit;
}

if ($path === '/forgot-password' && $method === 'GET') {
    renderPage('Forgot Password', renderForgotPasswordForm(null, null));
    exit;
}

if ($path === '/forgot-password' && $method === 'POST') {
    $email = trim((string) ($_POST['email'] ?? ''));
    if ($email === '') {
        renderPage('Forgot Password', renderForgotPasswordForm('Please enter your account email.', $email));
        exit;
    }
    $ip = AuthLayer::clientIp();
    $blocked = $rateLimiter->forgotPasswordBlocked($ip, $email);
    if ($blocked !== null) {
        renderPage('Forgot Password', renderForgotPasswordForm($blocked, $email));
        exit;
    }
    $rateLimiter->recordForgotPassword($ip, $email);
    $token = $service->createPasswordResetToken($email, 30);
    $debugResetUrl = null;
    $emailNotice = null;
    if ($token !== null) {
        $resetUrl = buildAppUrl('/reset-password?token=' . urlencode($token));
        $mailSent = sendPasswordResetEmail($email, $resetUrl);
        if (!$mailSent) {
            error_log('Password reset email could not be sent.');
            if (AuthLayer::allowsAuthDebugOutput()) {
                $debugResetUrl = $resetUrl;
                $emailNotice = 'Email is not configured or failed to send. Use the reset link below for local testing only.';
            }
        }
    }
    renderPage(
        'Forgot Password',
        renderForgotPasswordForm(
            null,
            '',
            'If the email exists and is active, a password reset link has been generated.',
            $debugResetUrl,
            $emailNotice
        )
    );
    exit;
}

if ($path === '/reset-password' && $method === 'GET') {
    $token = trim((string) ($_GET['token'] ?? ''));
    renderPage('Reset Password', renderResetPasswordForm($token, null, null));
    exit;
}

if ($path === '/reset-password' && $method === 'POST') {
    $token = trim((string) ($_POST['token'] ?? ''));
    $newPassword = trim((string) ($_POST['new_password'] ?? ''));
    $confirmPassword = trim((string) ($_POST['confirm_password'] ?? ''));
    $ip = AuthLayer::clientIp();
    $blocked = $rateLimiter->resetPasswordBlocked($ip);
    if ($blocked !== null) {
        renderPage('Reset Password', renderResetPasswordForm($token, $blocked, null));
        exit;
    }

    if ($newPassword === '' || $confirmPassword === '') {
        $rateLimiter->recordResetPasswordFailure($ip);
        renderPage('Reset Password', renderResetPasswordForm($token, 'Please complete all password fields.', null));
        exit;
    }
    if ($newPassword !== $confirmPassword) {
        $rateLimiter->recordResetPasswordFailure($ip);
        renderPage('Reset Password', renderResetPasswordForm($token, 'New password and confirm password do not match.', null));
        exit;
    }
    $result = $service->resetPasswordByToken($token, $newPassword);
    if (!($result['ok'] ?? false)) {
        $rateLimiter->recordResetPasswordFailure($ip);
        renderPage('Reset Password', renderResetPasswordForm($token, (string) ($result['message'] ?? 'Unable to reset password.'), null));
        exit;
    }
    renderPage('Reset Password', renderResetPasswordForm('', null, (string) $result['message']));
    exit;
}

if ($method === 'GET' && $path === '/health') {
    json(['ok' => true, 'service' => 'wpu-clearance']);
    exit;
}

if (!isset($_SESSION['user'])) {
    header('Location: ' . app_path('/login'));
    exit;
}

$user = $_SESSION['user'];
$semester = $service->getOpenSemester();
if ($semester !== null) {
    $service->syncSemesterDeadlineState((int) $semester['id']);
    $semester = $service->getOpenSemester();
    $service->processDailyDeadlineNotifications((int) $semester['id']);
}
$user = $service->enrichUserForHeader($user, $semester ? (int) $semester['id'] : null);
AuthLayer::refreshUser($user);

if ($user['role'] === 'admin') {
    $settingsSemester = $semester ?? ['academic_year' => 'N/A', 'term' => 'N/A'];
    if ($path === '/admin/settings' && $method === 'GET') {
        $profile = $service->getAdminProfile((int) $user['id']);
        if ($profile === null) {
            $_SESSION['flash'] = 'Admin profile not found.';
            header('Location: ' . app_path('/dashboard'));
            exit;
        }
        renderPage('Account Settings', renderAdminSettingsPage($settingsSemester, $profile));
        exit;
    }
    if ($path === '/admin/settings/profile' && $method === 'POST') {
        $result = $service->updateAdminProfile(
            (int) $user['id'],
            postCapitalized('first_name'),
            postCapitalized('last_name'),
            (string) ($_POST['email'] ?? ''),
            isset($_POST['current_password']) ? (string) $_POST['current_password'] : null,
            isset($_POST['new_password']) ? (string) $_POST['new_password'] : null,
            isset($_POST['confirm_password']) ? (string) $_POST['confirm_password'] : null
        );
        $_SESSION['flash'] = (string) ($result['message'] ?? 'Unable to update profile.');
        if (($result['ok'] ?? false) && isset($result['user']) && is_array($result['user'])) {
            $updated = $result['user'];
            $_SESSION['user']['first_name'] = $updated['first_name'];
            $_SESSION['user']['last_name'] = $updated['last_name'];
            $_SESSION['user']['email'] = $updated['email'];
            $_SESSION['user'] = $service->enrichUserForHeader($_SESSION['user'], $semester ? (int) $semester['id'] : null);
        }
        header('Location: ' . app_path('/admin/settings'));
        exit;
    }
    if ($path === '/admin/settings/photo' && $method === 'POST') {
        $removePhoto = isset($_POST['remove_photo']) && (string) $_POST['remove_photo'] === '1';
        $result = $service->saveAdminProfilePhoto(
            (int) $user['id'],
            $_FILES['profile_photo'] ?? [],
            $removePhoto
        );
        $_SESSION['flash'] = (string) ($result['message'] ?? 'Unable to update profile photo.');
        if ($result['ok'] ?? false) {
            $refreshed = $service->getAdminProfile((int) $user['id']);
            if ($refreshed !== null) {
                $_SESSION['user']['profile_photo_path'] = $refreshed['profile_photo_path'] ?? null;
            }
            $_SESSION['user'] = $service->enrichUserForHeader($_SESSION['user'], $semester ? (int) $semester['id'] : null);
        }
        header('Location: ' . app_path('/admin/settings'));
        exit;
    }
}

if (!$semester) {
    if ($path === '/admin/semester' && $user['role'] === 'admin') {
        if ($method === 'POST' && $path === '/admin/semester') {
            $result = $service->createSemester(
                trim((string) ($_POST['academic_year'] ?? '')),
                (string) ($_POST['term'] ?? '1st')
            );
            $_SESSION['flash'] = $result['message'];
            header('Location: ' . app_path('/admin/semester'));
            exit;
        }
        $emptySemester = ['academic_year' => 'N/A', 'term' => 'N/A'];
        renderPage('Admin - Semester', renderAdminSemesterPage($emptySemester));
        exit;
    }
    renderPage('No Open Semester', '<div class="alert alert-warning">No open semester configured yet. Ask admin to create one in Create/Open Semester.</div>');
    exit;
}
$semesterId = (int) $semester['id'];

if (
    $method === 'GET'
    && (
        str_starts_with($path, '/storage/requirement-attachments/')
        || str_starts_with($path, '/storage/uploads/')
        ||         str_starts_with($path, '/storage/signatory-signatures/')
        || str_starts_with($path, '/storage/profile-photos/')
    )
) {
    $relativeStoragePath = ltrim($path, '/');
    $storageRoot = realpath(dirname(__DIR__) . '/storage');
    $targetPath = realpath(dirname(__DIR__) . '/' . $relativeStoragePath);

    $canReadStoredFile = $service->userCanAccessStoredFile($user, $relativeStoragePath, $semesterId);
    if (
        !$canReadStoredFile
        || $storageRoot === false
        || $targetPath === false
        || !str_starts_with($targetPath, $storageRoot . DIRECTORY_SEPARATOR)
        || !is_file($targetPath)
        || !is_readable($targetPath)
    ) {
        http_response_code(404);
        echo 'File not found.';
        exit;
    }

    $mime = mime_content_type($targetPath);
    if ($mime === false || $mime === '') {
        $mime = 'application/octet-stream';
    }

    header('Content-Type: ' . $mime);
    header('Content-Length: ' . (string) filesize($targetPath));
    header('Content-Disposition: inline; filename="' . basename($targetPath) . '"');
    readfile($targetPath);
    exit;
}

if ($path === '/dashboard' && $method === 'GET') {
    if ($user['role'] === 'student') {
        $overview = $service->getStudentClearanceOverview((int) $user['id'], $semesterId);
        $requirements = $service->getStudentRequirementsByOffice((int) $user['id'], $semesterId);
        $deadlineStatus = $service->getSemesterDeadlineStatus($semester);
        $clearanceUnread = $service->getUnreadClearanceMessageCountForStudent((int) $user['id'], $semesterId);
        renderPage(
            'Student Dashboard',
            renderStudentDashboard(
                $user,
                $semester,
                $overview,
                $requirements,
                $clearanceUnread,
                $deadlineStatus
            )
        );
        exit;
    }
    if ($user['role'] === 'signatory') {
        $office = $service->getSignatoryOffice((int) $user['id'], $semesterId);
        $allowQueueCollegeProgram = $office !== null
            && $service->signatoryOfficeAllowsQueueSearchFilters($office);
        $requiredCollegeId = $service->getRequiredCollegeForSignatoryOffice((int) $user['id'], $office);
        $filterCollege = 0;
        $filterProgram = 0;
        $filterYearLevel = '';
        $filterSearchName = '';
        $filterSearchStatus = '';
        if ($allowQueueCollegeProgram) {
            $filterCollege = isset($_GET['college_id']) ? (int) $_GET['college_id'] : 0;
            $filterProgram = isset($_GET['program_id']) ? (int) $_GET['program_id'] : 0;
            $filterYearLevel = trim((string) ($_GET['year_level'] ?? ''));
            $filterSearchName = trim((string) ($_GET['search_name'] ?? ''));
            $filterSearchStatus = signatoryQueueStatusFilterValue((string) ($_GET['search_status'] ?? ''));
            if ($requiredCollegeId !== null) {
                $filterCollege = $requiredCollegeId;
            }
        }
        $queue = $service->getSignatoryQueue(
            (int) $user['id'],
            $semesterId,
            $filterCollege > 0 ? $filterCollege : null,
            $filterProgram > 0 ? $filterProgram : null,
            $filterYearLevel !== '' ? $filterYearLevel : null,
            $filterSearchName !== '' ? $filterSearchName : null,
            $filterSearchStatus !== '' ? $filterSearchStatus : null
        );
        $queueCollegeProgramFilter = null;
        if ($allowQueueCollegeProgram) {
            $colleges = $service->listActiveColleges();
            $programsByCollege = $service->programsGroupedByCollegeId();
            if ($requiredCollegeId !== null) {
                $colleges = array_values(array_filter(
                    $colleges,
                    static fn(array $college): bool => (int) ($college['id'] ?? 0) === $requiredCollegeId
                ));
                $programsByCollege = [$requiredCollegeId => $programsByCollege[$requiredCollegeId] ?? []];
            }
            $queueCollegeProgramFilter = [
                'college_id' => $filterCollege,
                'program_id' => $filterProgram,
                'year_level' => $filterYearLevel,
                'search_name' => $filterSearchName,
                'search_status' => $filterSearchStatus,
                'colleges' => $colleges,
                'programs_by_college' => $programsByCollege,
                'premium_layout' => $service->signatoryOfficeUsesPremiumQueueDashboard($office),
                'lock_college' => $requiredCollegeId !== null,
            ];
        }
        $officeRequirements = [];
        $editRequirementId = isset($_GET['edit_requirement_id']) ? (int) $_GET['edit_requirement_id'] : 0;
        if ($office !== null) {
            $officeRequirements = $service->getOfficeRequirementsForOffice($semesterId, (int) $office['id']);
        }
        $studentRequirementMap = [];
        $studentAttachedRequirementsMap = [];
        $groupSubordinateStatusMap = [];
        if ($office !== null && $queue !== []) {
            $queueStudentIds = array_map(
                static fn(array $row): int => (int) ($row['student_id'] ?? 0),
                $queue
            );
            $studentRequirementMap = $service->getSignatoryRequirementProgressMap(
                (int) $office['id'],
                $semesterId,
                $queueStudentIds
            );
            $studentAttachedRequirementsMap = $service->getStudentAttachedRequirementsMap(
                (int) $office['id'],
                $semesterId,
                $queueStudentIds
            );
            $officeCode = strtoupper(trim((string) ($office['code'] ?? '')));
            if ($officeCode === 'SAS') {
                $groupSubordinateStatusMap = $service->getSasSubordinateClearanceStatusMap($queueStudentIds, $semesterId);
            } elseif ($officeCode === 'DEAN') {
                $groupSubordinateStatusMap = $service->getDeanSubordinateClearanceStatusMap($queueStudentIds, $semesterId);
            }
        }
        $signatorySignaturePath = $service->getSignatorySignaturePath((int) $user['id'], $semesterId);
        $requiresSignatureUpload = $office !== null
            && $service->signatoryOfficeRequiresSignatureUpload($office);
        $msgThreadId = isset($_GET['msg_thread']) ? (int) $_GET['msg_thread'] : 0;
        $clearanceMessageThreads = $office !== null
            ? $service->listClearanceMessageThreadsForSignatory((int) $user['id'], $semesterId)
            : [];
        $clearanceMessageActiveDetail = null;
        if ($office !== null && $msgThreadId > 0) {
            $clearanceMessageActiveDetail = $service->getClearanceMessageThreadDetailForSignatory(
                $msgThreadId,
                (int) $user['id'],
                $semesterId
            );
        }
        $deadlineStatus = $service->getSemesterDeadlineStatus($semester);
        renderPage(
            'Signatory Dashboard',
            renderSignatoryDashboard(
                $user,
                $semester,
                $office,
                $queue,
                $officeRequirements,
                $editRequirementId,
                $queueCollegeProgramFilter,
                $studentRequirementMap,
                $studentAttachedRequirementsMap,
                $signatorySignaturePath,
                $clearanceMessageThreads,
                $clearanceMessageActiveDetail,
                $msgThreadId,
                $requiresSignatureUpload,
                $groupSubordinateStatusMap,
                $deadlineStatus
            )
        );
        exit;
    }
    $requirements = $service->getAdminRequirements($semesterId);
    $students = $service->listStudentsWithOverallStatus($semesterId);
    $deadlineStatus = $service->getSemesterDeadlineStatus($semester);
    renderPage('Admin Dashboard', renderAdminDashboard($semester, $requirements, $students, $deadlineStatus));
    exit;
}

if ($path === '/student/messages' && $method === 'GET' && $user['role'] === 'student') {
    $signatoryMsgChoices = $service->listSignatoriesForStudentMessaging($semesterId, (int) $user['id']);
    $validSigIds = array_map(static fn(array $r): int => (int) ($r['id'] ?? 0), $signatoryMsgChoices);
    $msgSignatory = isset($_GET['msg_signatory']) ? (int) $_GET['msg_signatory'] : 0;
    if ($msgSignatory <= 0 || !in_array($msgSignatory, $validSigIds, true)) {
        $msgSignatory = $validSigIds[0] ?? 0;
    }
    $clearanceUnread = $service->getUnreadClearanceMessageCountForStudent((int) $user['id'], $semesterId);
    $clearanceMessages = $msgSignatory > 0
        ? $service->getClearanceMessagesForStudentThread((int) $user['id'], $semesterId, $msgSignatory)
        : [];
    renderPage(
        'Student Messages',
        renderStudentMessagesPage(
            $user,
            $semester,
            $clearanceMessages,
            $clearanceUnread,
            $signatoryMsgChoices,
            $msgSignatory
        )
    );
    exit;
}

if ($path === '/student/account' && $method === 'GET' && $user['role'] === 'student') {
    renderPage('My Account', renderStudentAccountPage($user, $semester));
    exit;
}

if ($path === '/student/deadline-countdown' && $method === 'GET' && $user['role'] === 'student') {
    $deadlineStatus = $service->getSemesterDeadlineStatus($semester);
    renderPage(
        'Deadline Countdown',
        renderStudentDeadlineCountdownPage($semester, $deadlineStatus)
    );
    exit;
}

if ($path === '/signatory/messages' && $method === 'GET' && $user['role'] === 'signatory') {
    $office = $service->getSignatoryOffice((int) $user['id'], $semesterId);
    $allowQueueCollegeProgram = $office !== null
        && $service->signatoryOfficeAllowsQueueSearchFilters($office);
    $requiredCollegeId = $service->getRequiredCollegeForSignatoryOffice((int) $user['id'], $office);

    $returnCollege = 0;
    $returnProgram = 0;
    $returnYearLevel = '';
    $returnSearchName = '';
    $returnSearchStatus = '';
    if ($allowQueueCollegeProgram) {
        $returnCollege = isset($_GET['college_id']) ? (int) $_GET['college_id'] : 0;
        $returnProgram = isset($_GET['program_id']) ? (int) $_GET['program_id'] : 0;
        $returnYearLevel = trim((string) ($_GET['year_level'] ?? ''));
        $returnSearchName = trim((string) ($_GET['search_name'] ?? ''));
        $returnSearchStatus = signatoryQueueStatusFilterValue((string) ($_GET['search_status'] ?? ''));
        if ($requiredCollegeId !== null) {
            $returnCollege = $requiredCollegeId;
        }
    }

    $msgThreadId = isset($_GET['msg_thread']) ? (int) $_GET['msg_thread'] : 0;
    $clearanceMessageThreads = $office !== null
        ? $service->listClearanceMessageThreadsForSignatory((int) $user['id'], $semesterId)
        : [];
    $clearanceMessageActiveDetail = null;
    if ($office !== null && $msgThreadId > 0) {
        $clearanceMessageActiveDetail = $service->getClearanceMessageThreadDetailForSignatory(
            $msgThreadId,
            (int) $user['id'],
            $semesterId
        );
    }

    renderPage(
        'Signatory Messages',
        renderSignatoryMessagesPage(
            $semester,
            $office,
            $clearanceMessageThreads,
            $clearanceMessageActiveDetail,
            $msgThreadId,
            $returnCollege,
            $returnProgram,
            $returnYearLevel,
            $returnSearchName,
            $returnSearchStatus,
            $allowQueueCollegeProgram,
            (int) $user['id']
        )
    );
    exit;
}

if ($path === '/admin/semester' && $method === 'GET' && $user['role'] === 'admin') {
    $deadlineStatus = $service->getSemesterDeadlineStatus($semester);
    renderPage('Admin - Semester', renderAdminSemesterPage($semester, $deadlineStatus));
    exit;
}

if ($path === '/admin/add-requirement' && $method === 'GET' && $user['role'] === 'admin') {
    $offices = $service->listOffices();
    renderPage('Admin - Add Requirement', renderAdminAddRequirementPage($semester, $offices));
    exit;
}

if ($path === '/admin/current-requirements' && $method === 'GET' && $user['role'] === 'admin') {
    $offices = $service->listOffices();
    $requirements = $service->getAdminRequirements($semesterId);
    $editRequirementId = isset($_GET['edit_requirement_id']) ? (int) $_GET['edit_requirement_id'] : null;
    renderPage('Admin - Current Requirements', renderAdminCurrentRequirementsPage($semester, $offices, $requirements, $editRequirementId));
    exit;
}

if ($path === '/admin/signatories' && $method === 'GET' && $user['role'] === 'admin') {
    $offices = $service->listOffices();
    $colleges = $service->listActiveColleges();
    $signatories = $service->listSignatoryUsers();
    $signatoriesAll = $service->listAllSignatoryUsersForAdmin();
    $assignments = $service->listOfficeSignatoryAssignments($semesterId);
    $deanAssignments = $service->listDeanAssignmentsByCollege($semesterId);
    $additionalOffices = $service->listAdditionalSignatoryOffices();
    $editSignatoryId = isset($_GET['edit_signatory_id']) ? (int) $_GET['edit_signatory_id'] : 0;
    $editUser = null;
    if ($editSignatoryId > 0) {
        $editUser = $service->getSignatoryByIdForAdmin($editSignatoryId);
        if (!$editUser) {
            $_SESSION['flash'] = 'Signatory not found.';
            header('Location: ' . app_path('/admin/signatories'));
            exit;
        }
    }
    renderPage(
        'Admin - Add / Assign Signatory',
        renderAdminSignatoriesPage($semester, $offices, $colleges, $signatories, $signatoriesAll, $editUser, $assignments, $deanAssignments, $additionalOffices)
    );
    exit;
}

if ($path === '/admin/final-clearance-tools' && $method === 'GET' && $user['role'] === 'admin') {
    $students = $service->listStudentsWithOverallStatus($semesterId);
    renderPage('Admin - Final Clearance', renderAdminFinalClearancePage($semester, $students));
    exit;
}

if ($path === '/student/upload' && $method === 'POST' && $user['role'] === 'student') {
    $result = $service->uploadRequirementProof(
        (int) $user['id'],
        $semesterId,
        (int) ($_POST['requirement_id'] ?? 0),
        $_FILES['proof'] ?? []
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/dashboard'));
    exit;
}

if ($path === '/student/clearance-message/send' && $method === 'POST' && $user['role'] === 'student') {
    $toSig = (int) ($_POST['signatory_user_id'] ?? 0);
    $result = $service->postClearanceMessageFromStudent(
        (int) $user['id'],
        $semesterId,
        $toSig,
        postCapitalized('body', true)
    );
    $_SESSION['flash'] = $result['message'];
    if (($result['ok'] ?? false) && $toSig > 0) {
        header('Location: ' . app_path('/student/messages') . '?' . http_build_query(['msg_signatory' => (string) $toSig]));
    } else {
        header('Location: ' . app_path('/student/messages'));
    }
    exit;
}

if ($path === '/signatory/clearance-message/send' && $method === 'POST' && $user['role'] === 'signatory') {
    $threadId = (int) ($_POST['thread_id'] ?? 0);
    $result = $service->postClearanceMessageFromSignatory(
        $threadId,
        (int) $user['id'],
        $semesterId,
        postCapitalized('body', true)
    );
    $_SESSION['flash'] = $result['message'];
    if (($result['ok'] ?? false) && $threadId > 0) {
        $q = ['msg_thread' => (string) $threadId];
        $q = array_merge($q, signatoryQueueFilterQueryFromPost($_POST, true));
        header('Location: ' . app_path('/signatory/messages') . '?' . http_build_query($q));
    } else {
        header('Location: ' . app_path('/signatory/messages'));
    }
    exit;
}

if ($path === '/signatory/signature/upload' && $method === 'POST' && $user['role'] === 'signatory') {
    $result = $service->saveSignatorySignature(
        (int) $user['id'],
        $semesterId,
        $_FILES['signature_file'] ?? []
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/dashboard'));
    exit;
}

if ($path === '/student/final-clearance' && $method === 'GET' && $user['role'] === 'student') {
    $clearance = $service->getFinalClearanceData((int) $user['id'], $semesterId);
    if (!$clearance) {
        http_response_code(404);
        echo 'Clearance data not found.';
        exit;
    }
    if (!$clearance['is_fully_cleared']) {
        $_SESSION['flash'] = 'Final clearance PDF is only available when all offices are cleared.';
        header('Location: ' . app_path('/dashboard'));
        exit;
    }
    $useDompdf = class_exists('\Dompdf\Dompdf');
    $html = renderFinalClearanceDocument($clearance, $useDompdf, finalClearanceSignatureOfficeCodes());
    if ($useDompdf) {
        $dompdf = createClearanceDompdf();
        $dompdf->loadHtml($html);
        $dompdf->setPaper('A4', 'portrait');
        $dompdf->render();
        $forceDownload = isset($_GET['download']) && (string) $_GET['download'] === '1';
        $dompdf->stream('wpu-final-clearance.pdf', ['Attachment' => $forceDownload]);
        exit;
    }

    header('Content-Type: text/html; charset=UTF-8');
    echo $html;
    exit;
}

if ($path === '/admin/final-clearance' && $method === 'GET' && $user['role'] === 'admin') {
    $studentId = (int) ($_GET['student_id'] ?? 0);
    if ($studentId <= 0) {
        $_SESSION['flash'] = 'Select a student first.';
        header('Location: ' . app_path('/dashboard'));
        exit;
    }
    $clearance = $service->getFinalClearanceData($studentId, $semesterId);
    if (!$clearance) {
        $_SESSION['flash'] = 'Student clearance data not found.';
        header('Location: ' . app_path('/dashboard'));
        exit;
    }
    if (!$clearance['is_fully_cleared']) {
        $_SESSION['flash'] = 'Student is not yet fully cleared for final PDF.';
        header('Location: ' . app_path('/dashboard'));
        exit;
    }
    $useDompdf = class_exists('\Dompdf\Dompdf');
    $html = renderFinalClearanceDocument($clearance, $useDompdf, finalClearanceSignatureOfficeCodes());
    if ($useDompdf) {
        $dompdf = createClearanceDompdf();
        $dompdf->loadHtml($html);
        $dompdf->setPaper('A4', 'portrait');
        $dompdf->render();
        $forceDownload = isset($_GET['download']) && (string) $_GET['download'] === '1';
        $dompdf->stream('wpu-final-clearance-student-' . $studentId . '.pdf', ['Attachment' => $forceDownload]);
        exit;
    }
    header('Content-Type: text/html; charset=UTF-8');
    echo $html;
    exit;
}

if ($path === '/signatory/decision' && $method === 'POST' && $user['role'] === 'signatory') {
    $result = $service->decideOfficeClearance(
        (int) ($_POST['office_id'] ?? 0),
        (int) ($_POST['student_id'] ?? 0),
        $semesterId,
        (string) ($_POST['status'] ?? 'for_review'),
        (int) $user['id'],
        postCapitalized('reason') ?: null
    );
    $_SESSION['flash'] = $result['message'];
    $redirect = app_path('/dashboard');
    $sigOffice = $service->getSignatoryOffice((int) $user['id'], $semesterId);
    if ($sigOffice !== null && $service->signatoryOfficeAllowsQueueSearchFilters($sigOffice)) {
        $qs = signatoryQueueFilterQueryFromPost($_POST);
        if ($qs !== []) {
            $redirect .= '?' . http_build_query($qs);
        }
    }
    header('Location: ' . $redirect);
    exit;
}

if ($path === '/signatory/office-requirement/add' && $method === 'POST' && $user['role'] === 'signatory') {
    $office = $service->getSignatoryOffice((int) $user['id'], $semesterId);
    if ($office === null) {
        $_SESSION['flash'] = 'No assigned office for this semester.';
        header('Location: ' . app_path('/dashboard'));
        exit;
    }
    $result = $service->addRequirement(
        $semesterId,
        (int) $office['id'],
        postCapitalized('title'),
        postCapitalized('description'),
        $_FILES['attachment'] ?? null
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/dashboard'));
    exit;
}

if ($path === '/signatory/office-requirement/update' && $method === 'POST' && $user['role'] === 'signatory') {
    $office = $service->getSignatoryOffice((int) $user['id'], $semesterId);
    if ($office === null) {
        $_SESSION['flash'] = 'No assigned office for this semester.';
        header('Location: ' . app_path('/dashboard'));
        exit;
    }
    $result = $service->updateOfficeRequirementByOwner(
        (int) ($_POST['requirement_id'] ?? 0),
        $semesterId,
        (int) $office['id'],
        postCapitalized('title'),
        postCapitalized('description'),
        $_FILES['attachment'] ?? null,
        isset($_POST['remove_attachment']) && (string) $_POST['remove_attachment'] === '1'
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/dashboard'));
    exit;
}

if ($path === '/signatory/office-requirement/delete' && $method === 'POST' && $user['role'] === 'signatory') {
    $office = $service->getSignatoryOffice((int) $user['id'], $semesterId);
    if ($office === null) {
        $_SESSION['flash'] = 'No assigned office for this semester.';
        header('Location: ' . app_path('/dashboard'));
        exit;
    }
    $result = $service->deleteOfficeRequirementByOwner(
        (int) ($_POST['requirement_id'] ?? 0),
        $semesterId,
        (int) $office['id']
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/dashboard'));
    exit;
}

if ($path === '/signatory/student-requirement/add' && $method === 'POST' && $user['role'] === 'signatory') {
    $office = $service->getSignatoryOffice((int) $user['id'], $semesterId);
    if ($office === null) {
        $_SESSION['flash'] = 'No assigned office for this semester.';
        header('Location: ' . app_path('/dashboard'));
        exit;
    }
    $result = $service->addStudentAttachedRequirements(
        (int) ($_POST['student_id'] ?? 0),
        (int) $office['id'],
        $semesterId,
        postCapitalized('requirements_text', true),
        (int) $user['id'],
        $_FILES['attachment'] ?? null
    );
    $_SESSION['flash'] = $result['message'];
    $redirect = app_path('/dashboard');
    $qs = signatoryQueueFilterQueryFromPost($_POST);
    if ($qs !== []) {
        $redirect .= '?' . http_build_query($qs);
    }
    header('Location: ' . $redirect);
    exit;
}

if ($path === '/signatory/student-requirement/toggle' && $method === 'POST' && $user['role'] === 'signatory') {
    $office = $service->getSignatoryOffice((int) $user['id'], $semesterId);
    if ($office === null) {
        $_SESSION['flash'] = 'No assigned office for this semester.';
        header('Location: ' . app_path('/dashboard'));
        exit;
    }
    $completed = isset($_POST['completed']) && (string) $_POST['completed'] === '1';
    $result = $service->markStudentAttachedRequirement(
        (int) ($_POST['requirement_id'] ?? 0),
        (int) $office['id'],
        $semesterId,
        (int) $user['id'],
        $completed
    );
    $_SESSION['flash'] = $result['message'];
    $redirect = app_path('/dashboard');
    $qs = signatoryQueueFilterQueryFromPost($_POST);
    if ($qs !== []) {
        $redirect .= '?' . http_build_query($qs);
    }
    header('Location: ' . $redirect);
    exit;
}

if ($path === '/signatory/student-requirement/delete' && $method === 'POST' && $user['role'] === 'signatory') {
    $office = $service->getSignatoryOffice((int) $user['id'], $semesterId);
    if ($office === null) {
        $_SESSION['flash'] = 'No assigned office for this semester.';
        header('Location: ' . app_path('/dashboard'));
        exit;
    }
    $result = $service->deleteStudentAttachedRequirement(
        (int) ($_POST['requirement_id'] ?? 0),
        (int) $office['id'],
        $semesterId,
        (int) $user['id']
    );
    $_SESSION['flash'] = $result['message'];
    $redirect = app_path('/dashboard');
    $qs = signatoryQueueFilterQueryFromPost($_POST);
    if ($qs !== []) {
        $redirect .= '?' . http_build_query($qs);
    }
    header('Location: ' . $redirect);
    exit;
}

if ($path === '/admin/semester' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->createSemester(
        trim((string) ($_POST['academic_year'] ?? '')),
        (string) ($_POST['term'] ?? '1st')
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/semester'));
    exit;
}

if ($path === '/admin/semester/deadline' && $method === 'POST' && $user['role'] === 'admin') {
    $dueDate = trim((string) ($_POST['completion_due_date'] ?? ''));
    $result = $service->updateSemesterCompletionDueDate(
        $semesterId,
        $dueDate !== '' ? $dueDate : null
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/semester'));
    exit;
}

if ($path === '/admin/semester/clearance-window' && $method === 'POST' && $user['role'] === 'admin') {
    $action = trim((string) ($_POST['action'] ?? ''));
    $result = $service->setSemesterClearanceWindowActive(
        $semesterId,
        $action === 'activate'
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/semester'));
    exit;
}

if ($path === '/admin/requirement' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->addRequirement(
        $semesterId,
        (int) ($_POST['office_id'] ?? 0),
        postCapitalized('title'),
        postCapitalized('description'),
        $_FILES['attachment'] ?? null
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/add-requirement'));
    exit;
}

if ($path === '/admin/requirement/update' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->updateRequirement(
        (int) ($_POST['requirement_id'] ?? 0),
        $semesterId,
        (int) ($_POST['office_id'] ?? 0),
        postCapitalized('title'),
        postCapitalized('description'),
        $_FILES['attachment'] ?? null,
        isset($_POST['remove_attachment']) && (string) $_POST['remove_attachment'] === '1'
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/current-requirements'));
    exit;
}

if ($path === '/admin/requirement/delete' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->deleteRequirement(
        (int) ($_POST['requirement_id'] ?? 0),
        $semesterId
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/current-requirements'));
    exit;
}

if ($path === '/admin/add-signatory' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->addSignatoryUser(
        postCapitalized('first_name'),
        postCapitalized('last_name'),
        (string) ($_POST['email'] ?? ''),
        (string) ($_POST['password'] ?? '')
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/signatories'));
    exit;
}

if ($path === '/admin/signatory-office/add' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->addAdditionalSignatoryOffice(
        (string) ($_POST['parent_code'] ?? ''),
        postCapitalized('unit_name')
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/signatories'));
    exit;
}

if ($path === '/admin/signatory-office/deactivate' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->deactivateAdditionalSignatoryOffice((int) ($_POST['office_id'] ?? 0));
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/signatories'));
    exit;
}

if ($path === '/admin/assign-signatory' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->assignSignatory(
        $semesterId,
        (int) ($_POST['office_id'] ?? 0),
        (int) ($_POST['signatory_user_id'] ?? 0)
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/signatories'));
    exit;
}

if ($path === '/admin/signatory/update' && $method === 'POST' && $user['role'] === 'admin') {
    $newPw = trim((string) ($_POST['new_password'] ?? ''));
    $result = $service->updateSignatoryUser(
        (int) ($_POST['user_id'] ?? 0),
        postCapitalized('first_name'),
        postCapitalized('last_name'),
        (string) ($_POST['email'] ?? ''),
        $newPw !== '' ? $newPw : null
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/signatories'));
    exit;
}

if ($path === '/admin/signatory/deactivate' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->setSignatoryActive((int) ($_POST['user_id'] ?? 0), false);
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/signatories'));
    exit;
}

if ($path === '/admin/signatory/reactivate' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->setSignatoryActive((int) ($_POST['user_id'] ?? 0), true);
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/signatories'));
    exit;
}

if ($path === '/admin/signatory/remove-assignment' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->removeOfficeSignatoryAssignment(
        (int) ($_POST['assignment_id'] ?? 0),
        $semesterId
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/signatories'));
    exit;
}

if ($path === '/admin/assign-dean-college' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->assignDeanToCollege(
        $semesterId,
        (int) ($_POST['college_id'] ?? 0),
        (int) ($_POST['signatory_user_id'] ?? 0)
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/signatories'));
    exit;
}

if ($path === '/admin/colleges-programs' && $method === 'GET' && $user['role'] === 'admin') {
    $colleges = $service->listCollegesForAdmin();
    $programs = $service->listProgramsForAdmin();
    $editProgramId = isset($_GET['edit_program_id']) ? (int) $_GET['edit_program_id'] : 0;
    $editProgram = null;
    if ($editProgramId > 0) {
        $editProgram = $service->getProgramByIdForAdmin($editProgramId);
        if (!$editProgram) {
            $_SESSION['flash'] = 'Program not found.';
            header('Location: ' . app_path('/admin/colleges-programs'));
            exit;
        }
    }
    renderPage(
        'Admin - Colleges & Programs',
        renderAdminCollegesProgramsPage($semester, $colleges, $programs, $editProgram)
    );
    exit;
}

if ($path === '/admin/college' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->addCollege(
        (string) ($_POST['code'] ?? ''),
        postCapitalized('name')
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/colleges-programs'));
    exit;
}

if ($path === '/admin/program' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->addProgram(
        (int) ($_POST['college_id'] ?? 0),
        (string) ($_POST['code'] ?? ''),
        postCapitalized('name')
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/colleges-programs'));
    exit;
}

if ($path === '/admin/program/update' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->updateProgramByAdmin(
        (int) ($_POST['program_id'] ?? 0),
        (int) ($_POST['college_id'] ?? 0),
        (string) ($_POST['code'] ?? ''),
        postCapitalized('name')
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/colleges-programs'));
    exit;
}

if ($path === '/admin/program/delete' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->setProgramActive((int) ($_POST['program_id'] ?? 0), false);
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/colleges-programs'));
    exit;
}

if ($path === '/admin/import-students-csv' && $method === 'POST' && $user['role'] === 'admin') {
    $file = $_FILES['csv'] ?? null;
    if (!$file || (int) ($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        $_SESSION['flash'] = 'Pumili ng CSV file (max ~5MB).';
        header('Location: ' . app_path('/admin/register-students'));
        exit;
    }
    $tmp = (string) ($file['tmp_name'] ?? '');
    if ($tmp === '' || !is_readable($tmp)) {
        $_SESSION['flash'] = 'Unable to read the uploaded file.';
        header('Location: ' . app_path('/admin/register-students'));
        exit;
    }
    $importer = new StudentCsvImporter($service);
    $r = $importer->importFromPath($tmp);
    $parts = [];
    if ($r['errors'] !== [] && $r['saved'] === 0 && $r['failed'] === 0) {
        $parts[] = implode(' ', array_slice($r['errors'], 0, 3));
    } elseif ($r['no_data']) {
        $parts[] = 'No rows were imported (no data below the header, or all rows were duplicate/invalid).';
    } else {
        $parts[] = 'Na-import: ' . $r['saved'] . ', failed: ' . $r['failed'] . '.';
    }
    if ($r['errors'] !== [] && ($r['saved'] > 0 || $r['failed'] > 0)) {
        $parts[] = implode(' | ', array_slice($r['errors'], 0, 4));
        if (count($r['errors']) > 4) {
            $parts[] = '(+' . (count($r['errors']) - 4) . ' pa)';
        }
    }
    $_SESSION['flash'] = implode(' ', $parts);
    header('Location: ' . app_path('/admin/register-students'));
    exit;
}

if ($path === '/admin/download-students-csv-template' && $method === 'GET' && $user['role'] === 'admin') {
    $csvPath = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'import' . DIRECTORY_SEPARATOR . 'students_template.csv';
    if (!is_readable($csvPath)) {
        http_response_code(404);
        echo 'Template not found on this server.';
        exit;
    }
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="students_template.csv"');
    header('Content-Length: ' . (string) filesize($csvPath));
    readfile($csvPath);
    exit;
}

if ($path === '/admin/student/update' && $method === 'POST' && $user['role'] === 'admin') {
    $newPw = trim((string) ($_POST['new_password'] ?? ''));
    $result = $service->updateStudentByAdmin(
        (int) ($_POST['user_id'] ?? 0),
        (string) ($_POST['student_no'] ?? ''),
        postCapitalized('first_name'),
        postCapitalized('last_name'),
        (string) ($_POST['email'] ?? ''),
        (int) ($_POST['college_id'] ?? 0),
        (int) ($_POST['program_id'] ?? 0),
        (string) ($_POST['year_level'] ?? ''),
        (string) ($_POST['student_account_type'] ?? ''),
        (string) ($_POST['student_org_position'] ?? ''),
        (string) ($_POST['student_staying'] ?? ''),
        (string) ($_POST['campus'] ?? ''),
        $newPw !== '' ? $newPw : null
    );
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/register-students'));
    exit;
}

if ($path === '/admin/student/deactivate' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->setStudentActive((int) ($_POST['user_id'] ?? 0), false);
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/register-students'));
    exit;
}

if ($path === '/admin/student/reactivate' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->setStudentActive((int) ($_POST['user_id'] ?? 0), true);
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/register-students'));
    exit;
}

if ($path === '/admin/students/delete-selected' && $method === 'POST' && $user['role'] === 'admin') {
    $ids = isset($_POST['student_ids']) && is_array($_POST['student_ids']) ? $_POST['student_ids'] : [];
    $result = $service->deleteStudentsByAdmin($ids);
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/register-students'));
    exit;
}

if ($path === '/admin/students/delete-all' && $method === 'POST' && $user['role'] === 'admin') {
    $result = $service->deleteAllStudentsByAdmin();
    $_SESSION['flash'] = $result['message'];
    header('Location: ' . app_path('/admin/register-students'));
    exit;
}

if ($path === '/admin/register-students' && $method === 'GET' && $user['role'] === 'admin') {
    $colleges = $service->listActiveColleges();
    $programsByCollege = $service->programsGroupedByCollegeId();
    $studentsAll = $service->listAllStudentsForAdmin($semesterId);
    $editStudentId = isset($_GET['edit_student_id']) ? (int) $_GET['edit_student_id'] : 0;
    $editStudent = null;
    if ($editStudentId > 0) {
        $editStudent = $service->getStudentByIdForAdmin($editStudentId);
        if (!$editStudent) {
            $_SESSION['flash'] = 'Student not found.';
            header('Location: ' . app_path('/admin/register-students'));
            exit;
        }
    }
    renderPage(
        'Admin - Register Students',
        renderAdminRegisterStudentsPage($semester, $colleges, $programsByCollege, [], $studentsAll, $editStudent)
    );
    exit;
}

if ($path === '/admin/register-students' && $method === 'POST' && $user['role'] === 'admin') {
    $posted = [
        'student_no' => trim((string) ($_POST['student_no'] ?? '')),
        'first_name' => postCapitalized('first_name'),
        'last_name' => postCapitalized('last_name'),
        'email' => trim((string) ($_POST['email'] ?? '')),
        'college_id' => (int) ($_POST['college_id'] ?? 0),
        'program_id' => (int) ($_POST['program_id'] ?? 0),
        'year_level' => trim((string) ($_POST['year_level'] ?? '')),
        'student_account_type' => trim((string) ($_POST['student_account_type'] ?? '')),
        'student_org_position' => trim((string) ($_POST['student_org_position'] ?? '')),
        'student_staying' => trim((string) ($_POST['student_staying'] ?? '')),
        'campus' => trim((string) ($_POST['campus'] ?? '')),
    ];
    $result = $service->registerStudentWithCollegeProgram(
        $posted['student_no'],
        $posted['first_name'],
        $posted['last_name'],
        $posted['email'],
        (string) ($_POST['password'] ?? ''),
        $posted['college_id'],
        $posted['program_id'],
        $posted['year_level'],
        $posted['student_account_type'],
        $posted['student_org_position'],
        $posted['student_staying'],
        $posted['campus']
    );
    if ($result['ok']) {
        $_SESSION['flash'] = $result['message'];
        header('Location: ' . app_path('/admin/register-students'));
        exit;
    }
    $_SESSION['flash'] = $result['message'];
    $colleges = $service->listActiveColleges();
    $programsByCollege = $service->programsGroupedByCollegeId();
    $studentsAll = $service->listAllStudentsForAdmin($semesterId);
    renderPage(
        'Admin - Register Students',
        renderAdminRegisterStudentsPage($semester, $colleges, $programsByCollege, $posted, $studentsAll, null)
    );
    exit;
}

if ($path === '/admin/pending-departments' && $method === 'GET' && $user['role'] === 'admin') {
    $officeId = isset($_GET['office_id']) ? (int) $_GET['office_id'] : 0;
    $campusFilter = isset($_GET['campus']) ? trim((string) $_GET['campus']) : '';
    $collegeId = isset($_GET['college_id']) ? (int) $_GET['college_id'] : 0;
    $programId = isset($_GET['program_id']) ? (int) $_GET['program_id'] : 0;
    $yearLevel = trim((string) ($_GET['year_level'] ?? ''));
    $searchName = trim((string) ($_GET['search_name'] ?? ''));
    $officeStatus = strtolower(trim((string) ($_GET['office_status'] ?? '')));
    $export = isset($_GET['export']) ? (string) $_GET['export'] : '';
    $filters = [
        'office_id' => $officeId,
        'campus' => $campusFilter,
        'college_id' => $collegeId,
        'program_id' => $programId,
        'year_level' => $yearLevel,
        'search_name' => $searchName,
        'office_status' => $officeStatus,
    ];
    $monitor = $service->getAdminPendingDepartmentMonitor(
        $semesterId,
        $officeId > 0 ? $officeId : null,
        $campusFilter !== '' ? $campusFilter : null,
        $collegeId > 0 ? $collegeId : null,
        $programId > 0 ? $programId : null,
        $yearLevel !== '' ? $yearLevel : null,
        $searchName !== '' ? $searchName : null,
        $officeStatus !== '' ? $officeStatus : null
    );
    if ($export === 'csv') {
        downloadAdminPendingDepartmentsCsv($monitor['students'], $semester);
        exit;
    }
    renderPage(
        'Pending Departments',
        renderAdminPendingDepartments(
            $semester,
            $monitor,
            $filters,
            $service->listActiveColleges(),
            $service->programsGroupedByCollegeId()
        )
    );
    exit;
}

if ($path === '/admin/reports' && $method === 'GET' && $user['role'] === 'admin') {
    $overallStatus = isset($_GET['overall_status']) ? (string) $_GET['overall_status'] : '';
    $campusFilter = isset($_GET['campus']) ? trim((string) $_GET['campus']) : '';
    $export = isset($_GET['export']) ? (string) $_GET['export'] : '';
    $reportRows = $service->getAdminClearanceReport(
        $semesterId,
        $overallStatus !== '' ? $overallStatus : null,
        $campusFilter !== '' ? $campusFilter : null
    );
    if ($export === 'csv') {
        downloadAdminReportCsv($reportRows, $semester);
        exit;
    }
    renderPage(
        'Admin Clearance Reports',
        renderAdminReports($semester, $reportRows, [
            'overall_status' => $overallStatus,
            'campus' => $campusFilter,
        ])
    );
    exit;
}

if ($method === 'GET' && preg_match('#^/students/(\d+)/clearance$#', $path, $matches) === 1) {
    $studentId = (int) $matches[1];
    $targetSemesterId = isset($_GET['semester_id']) ? (int) $_GET['semester_id'] : $semesterId;
    if (!$service->actorCanViewStudentClearance((int) $user['id'], (string) $user['role'], $studentId, $targetSemesterId)) {
        http_response_code(403);
        json(['ok' => false, 'error' => 'Forbidden.']);
        exit;
    }
    json(['data' => $service->getStudentClearanceOverview($studentId, $targetSemesterId)]);
    exit;
}

if ($method === 'POST' && preg_match('#^/offices/(\d+)/students/(\d+)/decision$#', $path, $matches) === 1) {
    $officeId = (int) $matches[1];
    $studentId = (int) $matches[2];
    if ((string) ($user['role'] ?? '') !== 'signatory') {
        http_response_code(403);
        json(['ok' => false, 'error' => 'Forbidden.']);
        exit;
    }
    $rawBody = file_get_contents('php://input');
    $payload = json_decode($rawBody ?: '{}', true);
    if (!is_array($payload)) {
        $payload = [];
    }
    json($service->decideOfficeClearance(
        $officeId,
        $studentId,
        (int) ($payload['semester_id'] ?? $semesterId),
        (string) ($payload['status'] ?? 'pending'),
        (int) $user['id'],
        isset($payload['reason']) ? (string) $payload['reason'] : null
    ));
    exit;
}

http_response_code(404);
echo 'Route not found.';

function json(array $payload): void
{
    header('Content-Type: application/json');
    echo json_encode($payload);
}

function isJsonApiPath(string $path): bool
{
    return preg_match('#^/students/\d+/clearance$#', $path) === 1
        || preg_match('#^/offices/\d+/students/\d+/decision$#', $path) === 1;
}

function requestWantsJson(): bool
{
    $accept = (string) ($_SERVER['HTTP_ACCEPT'] ?? '');
    $contentType = (string) ($_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '');

    return str_contains($accept, 'application/json') || str_contains($contentType, 'application/json');
}

function createClearanceDompdf(): \Dompdf\Dompdf
{
    $root = dirname(__DIR__);
    $dompdfClass = '\Dompdf\Dompdf';

    return new $dompdfClass([
        'isRemoteEnabled' => false,
        'chroot' => [$root],
    ]);
}

function buildAppUrl(string $path): string
{
    $base = trim((string) (getenv('APP_BASE_URL') ?: ''));
    if ($base !== '') {
        return rtrim($base, '/') . '/' . ltrim($path, '/');
    }
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $qPos = strpos($path, '?');
    $pathOnly = $qPos === false ? $path : substr($path, 0, $qPos);
    $queryPart = $qPos === false ? '' : substr($path, $qPos);
    $pathOnly = $pathOnly === '' ? '/' : (str_starts_with($pathOnly, '/') ? $pathOnly : '/' . $pathOnly);

    return $scheme . '://' . $host . app_path($pathOnly) . $queryPart;
}

function sendPasswordResetEmail(string $toEmail, string $resetUrl): bool
{
    return PasswordResetEmail::send($toEmail, $resetUrl);
}

function formatYearLevelCell(mixed $yearLevel): string
{
    $t = trim((string) ($yearLevel ?? ''));

    return $t !== '' ? htmlspecialchars($t) : '—';
}

/** @return array<string,string> */
function studentCampusOptions(): array
{
    return ClearanceService::campusOptions();
}

function formatStudentCampusCell(mixed $campus): string
{
    $label = ClearanceService::campusDisplayLabel(trim((string) ($campus ?? '')));

    return $label !== '' ? htmlspecialchars($label) : '—';
}

function renderStudentCampusSelect(string $name, string $selectedRaw, bool $required, bool $includeAllOption = false): string
{
    $sel = trim($selectedRaw);
    $reqAttr = $required ? ' required' : '';
    $html = '<select class="form-select" name="' . htmlspecialchars($name) . '"' . $reqAttr . '>';
    if ($includeAllOption) {
        $html .= '<option value=""' . ($sel === '' ? ' selected' : '') . '>All campuses</option>';
    } else {
        $html .= '<option value=""' . ($sel === '' ? ' selected' : '') . '>Select campus</option>';
    }
    foreach (studentCampusOptions() as $val => $label) {
        $isSel = $sel === $val ? ' selected' : '';
        $html .= '<option value="' . htmlspecialchars($val) . '"' . $isSel . '>' . htmlspecialchars($label) . '</option>';
    }
    $html .= '</select>';

    return $html;
}

/** @return array<string,string> */
function signatoryQueueStatusFilterOptions(): array
{
    return [
        '' => 'All statuses',
        'for_review' => 'For Review',
        'cleared' => 'Approved',
        'rejected' => 'Disapproved',
    ];
}

function signatoryQueueStatusFilterValue(string $raw): string
{
    $v = strtolower(trim($raw));
    if ($v === 'approved') {
        return 'cleared';
    }
    if ($v === 'disapproved') {
        return 'rejected';
    }

    return in_array($v, ['for_review', 'cleared', 'rejected'], true) ? $v : '';
}

function renderSignatoryQueueStatusFilterOptionsHtml(string $selected): string
{
    $html = '';
    foreach (signatoryQueueStatusFilterOptions() as $val => $label) {
        $sel = $selected === (string) $val ? ' selected' : '';
        $html .= '<option value="' . htmlspecialchars((string) $val, ENT_QUOTES, 'UTF-8') . '"' . $sel . '>'
            . htmlspecialchars($label) . '</option>';
    }

    return $html;
}

/** @return array<string,string> */
function signatoryQueueFilterQuery(
    int $collegeId = 0,
    int $programId = 0,
    string $yearLevel = '',
    string $searchName = '',
    string $searchStatus = ''
): array {
    $q = [];
    if ($collegeId > 0) {
        $q['college_id'] = (string) $collegeId;
    }
    if ($programId > 0) {
        $q['program_id'] = (string) $programId;
    }
    $yl = trim($yearLevel);
    if ($yl !== '') {
        $q['year_level'] = $yl;
    }
    $name = trim($searchName);
    if ($name !== '') {
        $q['search_name'] = $name;
    }
    $status = signatoryQueueStatusFilterValue($searchStatus);
    if ($status !== '') {
        $q['search_status'] = $status;
    }

    return $q;
}

function signatoryQueueFilterQueryString(
    int $collegeId = 0,
    int $programId = 0,
    string $yearLevel = '',
    string $searchName = '',
    string $searchStatus = ''
): string {
    $q = signatoryQueueFilterQuery($collegeId, $programId, $yearLevel, $searchName, $searchStatus);

    return $q === [] ? '' : '?' . http_build_query($q);
}

/** @return array<string,string> */
function signatoryQueueFilterQueryFromPost(array $post, bool $useCollegeFieldNames = false): array
{
    $collegeKey = $useCollegeFieldNames ? 'return_college' : 'return_college_id';
    $programKey = $useCollegeFieldNames ? 'return_program' : 'return_program_id';

    return signatoryQueueFilterQuery(
        (int) ($post[$collegeKey] ?? 0),
        (int) ($post[$programKey] ?? 0),
        trim((string) ($post['return_year_level'] ?? '')),
        trim((string) ($post['return_search_name'] ?? '')),
        trim((string) ($post['return_search_status'] ?? ''))
    );
}

function signatoryQueueReturnFilterHiddenFields(
    int $returnCollege,
    int $returnProgram,
    string $returnYearLevel,
    string $returnSearchName = '',
    string $returnSearchStatus = ''
): string {
    $html = '<input type="hidden" name="return_college_id" value="' . $returnCollege . '">';
    $html .= '<input type="hidden" name="return_program_id" value="' . $returnProgram . '">';
    $html .= '<input type="hidden" name="return_year_level" value="' . htmlspecialchars($returnYearLevel, ENT_QUOTES, 'UTF-8') . '">';
    $html .= '<input type="hidden" name="return_search_name" value="' . htmlspecialchars($returnSearchName, ENT_QUOTES, 'UTF-8') . '">';
    $html .= '<input type="hidden" name="return_search_status" value="' . htmlspecialchars(signatoryQueueStatusFilterValue($returnSearchStatus), ENT_QUOTES, 'UTF-8') . '">';

    return $html;
}

/**
 * @param list<array<string,mixed>> $colleges
 * @param array<int, list<array<string,mixed>>> $programsByCollege
 */
function renderSignatoryQueueSearchFiltersForm(
    array $colleges,
    array $programsByCollege,
    int $returnCollege,
    int $returnProgram,
    string $returnYearLevel,
    bool $lockCollege = false,
    string $returnSearchName = '',
    string $returnSearchStatus = ''
): string {
    $programsJson = json_encode($programsByCollege, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE);
    if ($programsJson === false) {
        $programsJson = '{}';
    }
    $resetHref = hpath('/dashboard');

    $html = '<div class="card mb-3"><div class="card-header"><i class="fas fa-search me-1"></i> Search students</div><div class="card-body">';
    $html .= '<form method="GET" action="' . hpath('/dashboard') . '" class="row g-2 align-items-end">';
    $html .= '<div class="col-md-3"><label class="form-label small text-muted mb-1">Name or ID</label>';
    $html .= '<input type="text" name="search_name" class="form-control form-control-sm" value="' . htmlspecialchars($returnSearchName, ENT_QUOTES, 'UTF-8') . '" placeholder="Student name or ID">';
    $html .= '</div>';
    $html .= '<div class="col-md-2"><label class="form-label small text-muted mb-1">College</label>';
    $html .= '<select name="college_id" id="signatory_filter_college_id" class="form-select form-select-sm"' . ($lockCollege ? ' disabled' : '') . '>';
    if (!$lockCollege) {
        $html .= '<option value="0"' . ($returnCollege === 0 ? ' selected' : '') . '>All colleges</option>';
    }
    foreach ($colleges as $college) {
        $cid = (int) $college['id'];
        $sel = $returnCollege === $cid ? ' selected' : '';
        $html .= '<option value="' . $cid . '"' . $sel . '>' . htmlspecialchars((string) $college['name']) . '</option>';
    }
    if ($lockCollege && $returnCollege > 0) {
        $html .= '<input type="hidden" name="college_id" value="' . $returnCollege . '">';
    }
    $html .= '</select></div>';
    $html .= '<div class="col-md-2"><label class="form-label small text-muted mb-1">Program</label>';
    $html .= '<select name="program_id" id="signatory_filter_program_id" class="form-select form-select-sm">';
    $html .= '<option value="0"' . ($returnProgram === 0 ? ' selected' : '') . '>All programs</option>';
    if ($returnCollege > 0 && isset($programsByCollege[$returnCollege])) {
        foreach ($programsByCollege[$returnCollege] as $prog) {
            $pid = (int) $prog['id'];
            $sel = $returnProgram === $pid ? ' selected' : '';
            $label = htmlspecialchars($prog['name'] . ' (' . $prog['code'] . ')');
            $html .= '<option value="' . $pid . '"' . $sel . '>' . $label . '</option>';
        }
    }
    $html .= '</select></div>';
    $html .= '<div class="col-md-2"><label class="form-label small text-muted mb-1">Year level</label>';
    $html .= '<select name="year_level" id="signatory_filter_year_level" class="form-select form-select-sm">';
    $yearOptions = ['' => 'All years', '1' => '1', '2' => '2', '3' => '3', '4' => '4', '5+' => '5+'];
    foreach ($yearOptions as $val => $label) {
        $sel = $returnYearLevel === (string) $val ? ' selected' : '';
        $html .= '<option value="' . htmlspecialchars((string) $val) . '"' . $sel . '>' . htmlspecialchars((string) $label) . '</option>';
    }
    $html .= '</select></div>';
    $html .= '<div class="col-md-2"><label class="form-label small text-muted mb-1">Status</label>';
    $html .= '<select name="search_status" class="form-select form-select-sm">';
    $html .= renderSignatoryQueueStatusFilterOptionsHtml($returnSearchStatus);
    $html .= '</select></div>';
    $html .= '<div class="col-md-3 d-flex gap-2">';
    $html .= '<button class="btn btn-sm btn-primary" type="submit"><i class="fas fa-search me-1"></i>Apply</button>';
    $html .= '<a class="btn btn-sm btn-outline-secondary" href="' . $resetHref . '"><i class="fas fa-eraser me-1"></i>Reset</a>';
    $html .= '</div></form></div></div>';
    $html .= '<script>(function(){var byCollege=' . $programsJson . ';var c=document.getElementById("signatory_filter_college_id");var p=document.getElementById("signatory_filter_program_id");if(!c||!p)return;function refill(preserveSel){var id=parseInt(c.value,10)||0;var prev=preserveSel!==undefined?preserveSel:0;p.innerHTML="<option value=\\"0\\">All programs</option>";if(!byCollege[id])return;(byCollege[id]||[]).forEach(function(pr){var o=document.createElement("option");o.value=String(pr.id);o.textContent=pr.name+" ("+pr.code+")";if(prev&&parseInt(o.value,10)===prev)o.selected=true;p.appendChild(o);});}c.addEventListener("change",function(){refill(0);});})();</script>';

    return $html;
}

function renderYearLevelSelect(string $name, string $selectedRaw, bool $required): string
{
    $sel = trim($selectedRaw);
    $pairs = [
        '' => 'Select year level',
        '1' => '1',
        '2' => '2',
        '3' => '3',
        '4' => '4',
        '5+' => '5+',
    ];
    $reqAttr = $required ? ' required' : '';
    $html = '<select class="form-select" name="' . htmlspecialchars($name) . '"' . $reqAttr . '>';
    foreach ($pairs as $val => $label) {
        if ($val === '') {
            $isSel = $sel === '' ? ' selected' : '';

            $html .= '<option value=""' . $isSel . '>' . htmlspecialchars((string) $label) . '</option>';
            continue;
        }
        // PHP casts '1'..'4' keys to int; normalize for htmlspecialchars() and strict compare.
        $valStr = (string) $val;
        $isSel = $sel === $valStr ? ' selected' : '';
        $html .= '<option value="' . htmlspecialchars($valStr) . '"' . $isSel . '>' . htmlspecialchars((string) $label) . '</option>';
    }
    $html .= '</select>';

    return $html;
}

function formatStudentAccountTypeCell(mixed $accountType): string
{
    $t = trim((string) ($accountType ?? ''));
    if ($t === 'paying_tuition') {
        return 'Paying Tuition';
    }
    if ($t === 'not_paying_tuition') {
        return 'Not Paying Tuition';
    }

    return $t !== '' ? htmlspecialchars($t) : '—';
}

function renderStudentAccountTypeSelect(string $name, string $selectedRaw, bool $required): string
{
    $sel = trim($selectedRaw);
    $pairs = [
        '' => 'Select student account',
        'paying_tuition' => 'Paying Tuition',
        'not_paying_tuition' => 'Not Paying Tuition',
    ];
    $reqAttr = $required ? ' required' : '';
    $html = '<select class="form-select" name="' . htmlspecialchars($name) . '"' . $reqAttr . '>';
    foreach ($pairs as $val => $label) {
        $isSel = $sel === $val ? ' selected' : '';
        $html .= '<option value="' . htmlspecialchars($val) . '"' . $isSel . '>' . htmlspecialchars($label) . '</option>';
    }
    $html .= '</select>';

    return $html;
}

function formatStudentOrgPositionCell(mixed $position): string
{
    $labels = [
        'president' => 'President',
        'vice_president' => 'Vice-President',
        'treasurer' => 'Treasurer',
        'secretary' => 'Secretary',
        'auditor' => 'Auditor',
        'na' => 'N/A',
    ];
    $t = trim((string) ($position ?? ''));
    if (isset($labels[$t])) {
        return $labels[$t];
    }

    return $t !== '' ? htmlspecialchars($t) : '—';
}

function renderStudentOrgPositionSelect(string $name, string $selectedRaw, bool $required): string
{
    $sel = trim($selectedRaw);
    $pairs = [
        '' => 'Select org. position',
        'president' => 'President',
        'vice_president' => 'Vice-President',
        'treasurer' => 'Treasurer',
        'secretary' => 'Secretary',
        'auditor' => 'Auditor',
        'na' => 'N/A',
    ];
    $reqAttr = $required ? ' required' : '';
    $html = '<select class="form-select" name="' . htmlspecialchars($name) . '"' . $reqAttr . '>';
    foreach ($pairs as $val => $label) {
        $isSel = $sel === $val ? ' selected' : '';
        $html .= '<option value="' . htmlspecialchars($val) . '"' . $isSel . '>' . htmlspecialchars($label) . '</option>';
    }
    $html .= '</select>';

    return $html;
}

function formatStudentStayingCell(mixed $staying): string
{
    $labels = [
        'wpu_dormitory' => 'WPU Dormitory',
        'outside_dormitory' => 'Outside Dormitory',
        'commuter' => 'Commuter',
    ];
    $t = trim((string) ($staying ?? ''));
    if (isset($labels[$t])) {
        return $labels[$t];
    }

    return $t !== '' ? htmlspecialchars($t) : '—';
}

function renderStudentStayingSelect(string $name, string $selectedRaw, bool $required): string
{
    $sel = trim($selectedRaw);
    $pairs = [
        '' => 'Select students staying',
        'wpu_dormitory' => 'WPU Dormitory',
        'outside_dormitory' => 'Outside Dormitory',
        'commuter' => 'Commuter',
    ];
    $reqAttr = $required ? ' required' : '';
    $html = '<select class="form-select" name="' . htmlspecialchars($name) . '"' . $reqAttr . '>';
    foreach ($pairs as $val => $label) {
        $isSel = $sel === $val ? ' selected' : '';
        $html .= '<option value="' . htmlspecialchars($val) . '"' . $isSel . '>' . htmlspecialchars($label) . '</option>';
    }
    $html .= '</select>';

    return $html;
}

function renderStudentPwaHead(): string
{
    $html = '<link rel="manifest" href="' . hpath('/manifest.webmanifest') . '">';
    $html .= '<meta name="theme-color" content="#0f3b4f">';
    $html .= '<meta name="mobile-web-app-capable" content="yes">';
    $html .= '<meta name="apple-mobile-web-app-capable" content="yes">';
    $html .= '<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">';
    $html .= '<meta name="apple-mobile-web-app-title" content="SAFE Student">';
    $html .= '<link rel="apple-touch-icon" href="' . hpath('/app/icon/192') . '">';
    $html .= '<link rel="icon" type="image/png" sizes="192x192" href="' . hpath('/app/icon/192') . '">';
    $html .= '<link rel="stylesheet" href="' . hasset('student-app.css') . '">';

    return $html;
}

function renderStudentPwaScripts(): string
{
    global $appBasePath;
    $config = json_encode([
        'swUrl' => app_path('/sw.js'),
        'scope' => StudentPwa::scope((string) $appBasePath),
    ], JSON_UNESCAPED_SLASHES);

    return '<script>window.STUDENT_PWA = ' . $config . ';</script>'
        . '<script src="' . hasset('student-app.js') . '" defer></script>';
}

function studentAppNavKey(string $requestPath): string
{
    if (str_starts_with($requestPath, '/student/messages')) {
        return 'messages';
    }
    if (str_starts_with($requestPath, '/student/account')) {
        return 'account';
    }

    return 'home';
}

function renderStudentAppNav(string $requestPath, int $unread, string $placement): string
{
    $active = studentAppNavKey($requestPath);
    $items = [
        ['key' => 'home', 'href' => '/dashboard', 'icon' => 'fa-home', 'label' => 'Home'],
        ['key' => 'messages', 'href' => '/student/messages', 'icon' => 'fa-comments', 'label' => 'Messages'],
        ['key' => 'account', 'href' => '/student/account', 'icon' => 'fa-user', 'label' => 'Account'],
    ];
    $class = $placement === 'side' ? 'sapp-sidenav' : 'sapp-tabbar';
    $html = '<nav class="' . $class . '" aria-label="Student app">';
    foreach ($items as $item) {
        $isActive = $active === $item['key'];
        $html .= '<a class="sapp-tab' . ($isActive ? ' is-active' : '') . '" href="' . hpath($item['href']) . '">';
        $html .= '<i class="fas ' . $item['icon'] . '" aria-hidden="true"></i>';
        $html .= '<span>' . htmlspecialchars($item['label']) . '</span>';
        if ($item['key'] === 'messages' && $unread > 0) {
            $html .= '<span class="sapp-badge">' . (int) $unread . '</span>';
        }
        $html .= '</a>';
    }
    if ($placement === 'side') {
        $html .= '<form method="POST" action="' . hpath('/logout') . '" class="mt-auto mb-0 px-1">';
        $html .= '<button class="btn btn-outline-secondary w-100" type="submit">Logout</button></form>';
    }
    $html .= '</nav>';

    return $html;
}

function renderStudentAppTopbar(array $user): string
{
    $name = trim((string) ($user['display_account_name'] ?? ''));
    if ($name === '') {
        $name = trim((string) ($user['first_name'] ?? '') . ' ' . (string) ($user['last_name'] ?? ''));
    }
    if ($name === '') {
        $name = 'Student';
    }

    $html = '<header class="sapp-topbar">';
    $html .= '<div class="sapp-brand"><span class="sapp-brand-mark"><img src="' . hasset('wpu-logo.png') . '" alt="Western Philippines University"></span>';
    $html .= '<div class="sapp-brand-text"><strong>SAFE Student</strong><span>' . htmlspecialchars($name) . '</span></div></div>';
    $html .= '<button type="button" class="sapp-install-btn" data-sapp-install><i class="fas fa-download" aria-hidden="true"></i> Install app</button>';
    $html .= '</header>';

    return $html;
}

function renderStudentAppInstallBanner(): string
{
    return '<div class="sapp-install-banner" data-sapp-install-banner>'
        . '<div><strong>Install SAFE Student</strong>'
        . '<p>Use it like an app on this computer or add it to your phone home screen.</p>'
        . '<div class="sapp-ios-help" data-sapp-ios-help hidden>'
        . '<ol><li>Tap the Share button in Safari.</li><li>Choose <strong>Add to Home Screen</strong>.</li><li>Open the new SAFE Student icon.</li></ol>'
        . '</div></div>'
        . '<button type="button" class="btn btn-sm btn-success" data-sapp-install>Install</button>'
        . '</div>';
}

function renderStudentAppLogin(?string $error): string
{
    $safeError = htmlspecialchars((string) ($error ?? ''), ENT_QUOTES, 'UTF-8');
    $errorClass = $error ? ' show' : '';

    return '<div class="sapp-login">
    <div class="sapp-login-hero">
        <div class="sapp-login-brand">
            <span class="sapp-brand-mark"><img src="' . hasset('wpu-logo.png') . '" alt="Western Philippines University"></span>
            <h1>SAFE Student</h1>
        </div>
        <p>Track your clearance, upload requirements, and message offices.</p>
    </div>
    <div class="sapp-only-note"><i class="fas fa-user-graduate" aria-hidden="true"></i><span>Student accounts only. This app can be used in a browser or installed on your phone.</span></div>
    <div id="errorBox" class="error-message' . $errorClass . '">
        <i class="fas fa-exclamation-triangle"></i>
        <span id="errorText">' . ($safeError !== '' ? $safeError : 'Invalid credentials or inactive account.') . '</span>
    </div>
    <form method="POST" action="' . hpath('/app') . '">
        ' . csrf_field() . '
        <div class="input-group">
            <label class="input-label"><i class="fas fa-envelope"></i><span>Student email</span></label>
            <input type="email" name="email" class="input-field" placeholder="student@wpu.edu.ph" required>
        </div>
        <div class="input-group">
            <label class="input-label"><i class="fas fa-lock"></i><span>Password</span></label>
            <input type="password" name="password" class="input-field" placeholder="••••••••" required>
        </div>
        <div class="forgot-link"><a href="' . hpath('/forgot-password') . '?from=app">Forgot password?</a></div>
        <button type="submit" class="signin-btn"><i class="fas fa-arrow-right-to-bracket"></i> Sign in</button>
    </form>
    ' . renderStudentAppInstallBanner() . '
    <a class="sapp-staff-link" href="' . hpath('/login') . '">Signatory or admin? Open the staff portal</a>
</div>';
}

function renderStudentAppStaffBlocked(array $user): string
{
    $role = htmlspecialchars((string) ($user['role'] ?? 'staff'));

    return '<div class="sapp-login">'
        . '<div class="sapp-login-hero"><div class="sapp-login-brand"><span class="sapp-brand-mark"><img src="' . hasset('wpu-logo.png') . '" alt="Western Philippines University"></span>'
        . '<h1>Student app only</h1></div><p>This installable app is limited to student accounts.</p></div>'
        . '<div class="sapp-only-note"><i class="fas fa-ban" aria-hidden="true"></i><span>You are signed in as <strong>' . $role . '</strong>. Use the staff web portal instead.</span></div>'
        . '<a class="signin-btn" href="' . hpath('/dashboard') . '" style="text-decoration:none;">Open staff portal</a>'
        . '<form method="POST" action="' . hpath('/logout') . '" class="mt-3 mb-0">'
        . '<button class="btn btn-outline-secondary w-100" type="submit">Logout</button></form>'
        . '</div>';
}

function renderStudentAccountPage(array $user, array $semester): string
{
    $email = htmlspecialchars((string) ($user['email'] ?? ''));
    $dept = htmlspecialchars((string) ($user['display_department'] ?? '—'));
    $semesterLabel = htmlspecialchars((string) (($semester['academic_year'] ?? '') . ' ' . ($semester['term'] ?? '')));
    $html = '<h4 class="section-title">My Account</h4>';
    $html .= '<p class="muted-caption">Install this student app on your computer or phone. Staff accounts cannot sign in here.</p>';
    $html .= renderStudentAccountSummaryCard($user);
    $html .= '<div class="card mb-3"><div class="card-body">';
    $html .= '<div class="row g-3">';
    $html .= '<div class="col-12 col-md-4"><div class="account-field-label text-muted small text-uppercase fw-semibold">Email</div><div>' . $email . '</div></div>';
    $html .= '<div class="col-12 col-md-5"><div class="account-field-label text-muted small text-uppercase fw-semibold">Program / college</div><div>' . $dept . '</div></div>';
    $html .= '<div class="col-12 col-md-3"><div class="account-field-label text-muted small text-uppercase fw-semibold">Semester</div><div>' . $semesterLabel . '</div></div>';
    $html .= '</div></div></div>';
    $html .= '<div class="card mb-3"><div class="card-body">';
    $html .= '<strong>Install on this device</strong>';
    $html .= '<p class="small text-muted mb-2">Desktop: use the Install button in Chrome or Edge. Phone: install from the banner, or on iPhone use Share → Add to Home Screen.</p>';
    $html .= '<button type="button" class="btn btn-success" data-sapp-install><i class="fas fa-download me-1" aria-hidden="true"></i>Install app</button>';
    $html .= '</div></div>';
    $html .= '<form method="POST" action="' . hpath('/logout') . '"><button class="btn btn-outline-danger" type="submit">Logout</button></form>';

    return $html;
}

function renderPage(string $title, string $content): void
{
    $flash = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    $requestPath = $GLOBALS['_app_request_path'] ?? '/';
    $isStudentAppAuth = $requestPath === '/app' && !isset($_SESSION['user']);
    $isStudentAppGate = $requestPath === '/app';
    $isAuthPage = in_array($requestPath, ['/login', '/forgot-password', '/reset-password'], true) && !isset($_SESSION['user']);
    $isStudentPopup = $requestPath === '/student/deadline-countdown';
    $isStudentView = isset($_SESSION['user']) && (string) ($_SESSION['user']['role'] ?? '') === 'student'
        && !$isStudentPopup;
    $isAdminView = isset($_SESSION['user']) && (string) ($_SESSION['user']['role'] ?? '') === 'admin'
        && ($requestPath === '/dashboard' || str_starts_with($requestPath, '/admin/'));
    $enableStudentPwa = $isStudentView || $isStudentAppAuth || $isStudentAppGate;
    echo '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">';
    echo '<title>' . htmlspecialchars($title) . '</title>';
    echo AuthLayer::csrfMeta();
    echo '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">';
    if ($isAdminView) {
        echo '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">';
        echo '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" integrity="sha384-5e2ESR8Ycmos6g3gAKr1Jvwye8sW4U1u/cAKulfVJnkakCcMqhOudbtPnvJ+nbv7" crossorigin="anonymous">';
        echo '<style>
        body{margin:0;background:#f1f5f9;font-family:"Inter",sans-serif;color:#0f172a;}
        body.admin-layout{overflow:hidden;height:100vh;}
        body.admin-layout main{padding:0;margin:0;max-width:none;}
        .admin-app{display:flex;height:100vh;overflow:hidden;}
        .admin-sidebar{width:280px;background:linear-gradient(180deg,#0f2b3d 0%,#0a1c2a 100%);color:#e2e8f0;flex-shrink:0;box-shadow:2px 0 12px rgba(0,0,0,.08);height:100vh;overflow-y:auto;overscroll-behavior:contain;}
        .admin-sidebar-header{padding:28px 24px;border-bottom:1px solid #2d4a6e;}
        .admin-sidebar-brand{display:flex;align-items:center;gap:.75rem;}
        .admin-sidebar-brand img{width:44px;height:44px;object-fit:contain;border-radius:50%;background:#fff;flex-shrink:0;box-shadow:0 2px 8px rgba(0,0,0,.22);}
        .admin-sidebar-header h2{font-size:1.5rem;font-weight:700;letter-spacing:-.3px;background:linear-gradient(135deg,#fff 0%,#a5f3fc 100%);-webkit-background-clip:text;background-clip:text;color:transparent;margin:0;}
        .admin-sidebar-header p{font-size:.75rem;color:#94a3b8;margin:6px 0 0;}
        .admin-nav{padding:24px 16px;display:flex;flex-direction:column;gap:8px;}
        .admin-nav a{display:flex;align-items:center;gap:14px;padding:12px 16px;border-radius:12px;font-weight:500;color:#cbd5e1;text-decoration:none;transition:background .15s ease,color .15s ease;}
        .admin-nav a i{width:22px;font-size:1.1rem;}
        .admin-nav a.active,.admin-nav a:hover{background:#1e4a6e;color:#fff;}
        .admin-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh;overflow:hidden;}
        .admin-top{background:#fff;padding:16px 32px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #e2e8f0;box-shadow:0 1px 2px rgba(0,0,0,.03);flex-wrap:wrap;gap:12px;flex-shrink:0;}
        .admin-top-actions{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-left:auto;}
        .admin-user-block{max-width:min(360px,100%);}
        .admin-user-link{display:flex;align-items:center;gap:12px;text-decoration:none;color:inherit;}
        .admin-user-link:hover .admin-user-name{color:#1e4a6e;}
        .admin-avatar{width:42px;height:42px;border-radius:50%;object-fit:cover;border:2px solid #e2e8f0;background:#f1f5f9;display:flex;align-items:center;justify-content:center;color:#64748b;font-size:1rem;flex-shrink:0;}
        .admin-settings-preview{width:120px;height:120px;border-radius:50%;object-fit:cover;border:3px solid #e2edff;background:#f8fafc;}
        .admin-settings-preview-placeholder{width:120px;height:120px;border-radius:50%;border:3px dashed #cbd5e1;background:#f8fafc;display:flex;align-items:center;justify-content:center;color:#94a3b8;font-size:2rem;}
        .admin-user-name{font-weight:600;font-size:.9rem;color:#0f172a;line-height:1.25;}
        .admin-user-dept{font-size:.78rem;color:#64748b;line-height:1.3;margin-top:2px;}
        .semester-badge{background:#eef2ff;padding:8px 16px;border-radius:40px;font-size:.85rem;font-weight:500;color:#1e40af;}
        .logout-btn{display:flex;align-items:center;gap:8px;background:none;border:none;font-weight:500;color:#475569;cursor:pointer;padding:8px 14px;border-radius:40px;transition:background .15s ease,color .15s ease;}
        .logout-btn:hover{background:#fee2e2;color:#b91c1c;}
        .admin-content{flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:32px;max-width:1300px;}
        .cards-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:24px;margin-bottom:30px;}
        .stat-card{background:#fff;padding:20px;border-radius:20px;box-shadow:0 1px 3px rgba(0,0,0,.05);border:1px solid #eef2ff;}
        a.stat-card{color:inherit;}
        a.stat-card:hover{border-color:#93c5fd;}
        .stat-title{font-size:.85rem;text-transform:uppercase;letter-spacing:.5px;font-weight:600;color:#5b6e8c;margin-bottom:12px;}
        .stat-value{font-size:2rem;font-weight:800;color:#0f2b3d;}
        .student-selector{background:#f8fafc;padding:24px 28px;border-radius:20px;display:flex;flex-wrap:wrap;align-items:flex-end;gap:20px;margin-bottom:28px;border:1px solid #e2edff;}
        .form-group{flex:2;min-width:200px;}
        .form-group label{display:block;font-size:.75rem;font-weight:600;text-transform:uppercase;color:#4b6b8f;margin-bottom:6px;letter-spacing:.3px;}
        .admin-select,.generate-btn{width:100%;padding:12px 16px;border-radius:14px;font-family:inherit;font-weight:500;border:1px solid #cbd5e1;background:#fff;transition:border-color .15s ease,box-shadow .15s ease;}
        .admin-select:focus,.generate-btn:focus{outline:none;border-color:#2c6e9e;box-shadow:0 0 0 3px rgba(44,110,158,.2);}
        .generate-btn{background:#0f2b3d;color:#fff;border:none;font-weight:600;}
        .generate-btn:hover{background:#1e4a6e;}
        .panel{background:#fff;border-radius:20px;border:1px solid #e2edff;overflow:hidden;margin-bottom:28px;box-shadow:0 1px 2px rgba(0,0,0,.03);}
        .panel-header{padding:18px 22px;background:#fafcff;border-bottom:1px solid #eef2ff;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;}
        .panel-header h3{font-weight:700;font-size:1.1rem;display:flex;align-items:center;gap:10px;margin:0;}
        .badge-requirements{background:#e6f7ec;color:#15803d;padding:4px 10px;border-radius:40px;font-size:.72rem;font-weight:600;}
        .requirement-item{display:flex;align-items:center;justify-content:space-between;padding:14px 22px;border-bottom:1px solid #f0f4f9;}
        .requirement-item:last-child{border-bottom:0;}
        .req-name{display:flex;align-items:center;gap:10px;font-weight:500;}
        .req-status{font-size:.75rem;padding:4px 12px;border-radius:50px;background:#f1f5f9;color:#334155;}
        .report-table{width:100%;border-collapse:collapse;}
        .report-table th{padding:14px 16px;background:#f8fafc;font-weight:600;font-size:.78rem;color:#2c3e5c;border-bottom:1px solid #e2edff;}
        .report-table td{padding:12px 16px;border-bottom:1px solid #f0f4fa;font-size:.9rem;}
        .status-pill{padding:4px 12px;border-radius:40px;font-weight:600;font-size:.74rem;display:inline-block;}
        .status-cleared{background:#e0f2e9;color:#0b5e42;}
        .status-pending{background:#fff1e6;color:#b45309;}
        .status-for-review{background:#fef9c3;color:#a16207;}
        .status-rejected{background:#fee2e2;color:#b91c1c;}
        .dept-chip{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:40px;font-size:.72rem;font-weight:600;margin:2px 4px 2px 0;white-space:nowrap;}
        .dept-chip-pending{background:#fff1e6;color:#b45309;}
        .dept-chip-for_review{background:#fef9c3;color:#a16207;}
        .dept-chip-rejected{background:#fee2e2;color:#b91c1c;}
        .monitor-office-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:14px;margin-bottom:24px;}
        .monitor-office-card{display:block;background:#fff;padding:16px 18px;border-radius:16px;border:1px solid #e2edff;text-decoration:none;color:inherit;transition:border-color .15s,box-shadow .15s;}
        .monitor-office-card:hover{border-color:#93c5fd;box-shadow:0 2px 8px rgba(30,74,110,.08);color:inherit;}
        .monitor-office-card.active{border-color:#1e4a6e;box-shadow:0 0 0 2px rgba(30,74,110,.2);}
        .monitor-office-name{font-size:.82rem;font-weight:600;color:#334155;margin-bottom:8px;line-height:1.35;}
        .monitor-office-count{font-size:1.6rem;font-weight:800;color:#0f2b3d;line-height:1;}
        .monitor-office-meta{font-size:.72rem;color:#64748b;margin-top:6px;}
        .admin-toolbar{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:16px;}
        </style>';
    } else {
        $loginBackgroundUrl = hasset('login-background.png');
        echo '<link href="https://fonts.googleapis.com/css2?family=Inter:opsz,wght@14..32,300;14..32,400;14..32,500;14..32,600;14..32,700&display=swap" rel="stylesheet">';
        echo '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" integrity="sha384-5e2ESR8Ycmos6g3gAKr1Jvwye8sW4U1u/cAKulfVJnkakCcMqhOudbtPnvJ+nbv7" crossorigin="anonymous">';
        echo '<style>
        :root{--brand:#198754;--brand-dark:#146c43;--bg:#f3f6f8;--text:#1f2a37;--muted:#6b7280;--border:#e5e7eb;}
        body{background:var(--bg);color:var(--text);font-family:"Inter",sans-serif;}
        body.login-page{background:
            linear-gradient(120deg,rgba(7,24,35,.44) 0%,rgba(10,43,62,.4) 45%,rgba(25,75,104,.38) 100%),
            url("' . $loginBackgroundUrl . '");
            background-size:cover;
            background-position:center center;
            background-repeat:no-repeat;
            min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem;position:relative;overflow:hidden;}
        body.login-page::before{content:"";position:fixed;inset:0;pointer-events:none;background:
            radial-gradient(circle at 16% 78%,rgba(255,255,255,.18) 0%,rgba(255,255,255,0) 30%),
            radial-gradient(circle at 74% 32%,rgba(255,255,255,.15) 0%,rgba(255,255,255,0) 38%),
            repeating-linear-gradient(130deg,rgba(255,255,255,.04) 0 1px,transparent 1px 24px);
            mix-blend-mode:soft-light;opacity:.78;}
        body.login-page::after{content:"";position:fixed;inset:0;pointer-events:none;background:linear-gradient(to bottom,rgba(6,15,24,.04),rgba(6,15,24,.2));}
        .navbar{box-shadow:0 4px 14px rgba(0,0,0,.08);}
        .page-wrap{max-width:1240px;}
        .card{border:1px solid var(--border);border-radius:12px;box-shadow:0 1px 2px rgba(16,24,40,.04);}
        .card-header{background:#fff;font-weight:600;border-bottom:1px solid var(--border);}
        .btn-success{background:var(--brand);border-color:var(--brand);}
        .btn-success:hover{background:var(--brand-dark);border-color:var(--brand-dark);}
        .table{--bs-table-bg:transparent;}
        .table thead th{font-size:.82rem;text-transform:uppercase;letter-spacing:.02em;color:var(--muted);}
        .badge{font-weight:600;}
        .muted-caption{font-size:.85rem;color:var(--muted);}
        .section-title{font-weight:700;margin-bottom:.25rem;}
        .app-notifications-top{background:#fff;border:1px solid var(--border);border-radius:12px;margin-bottom:1rem;box-shadow:0 1px 2px rgba(16,24,40,.04);overflow:hidden;}
        .app-notifications-top .notif-head{display:flex;align-items:center;justify-content:space-between;gap:.75rem;padding:.7rem 1rem;background:#f8fafc;border-bottom:1px solid var(--border);font-weight:600;font-size:.9rem;}
        .app-notifications-top .notif-body{max-height:220px;overflow-y:auto;}
        .app-notifications-top .notif-item{padding:.75rem 1rem;border-bottom:1px solid #f3f4f6;}
        .app-notifications-top .notif-item:last-child{border-bottom:0;}
        .app-notifications-top .notif-title{font-weight:600;font-size:.88rem;margin-bottom:.2rem;}
        .app-notifications-top .notif-text{font-size:.82rem;color:var(--muted);margin:0;line-height:1.45;}
        .app-notifications-top .notif-empty{padding:.85rem 1rem;color:var(--muted);font-size:.85rem;margin:0;}
        .login-shell{min-height:calc(100vh - 130px);display:flex;align-items:center;justify-content:center;padding:1.2rem 0;}
        body.login-page .login-shell{min-height:unset;padding:0;width:100%;}
        .login-card{width:100%;max-width:1240px;background:rgba(255,255,255,.95);border-radius:2.3rem;display:flex;flex-wrap:wrap;overflow:hidden;box-shadow:0 32px 60px -22px rgba(0,0,0,.42),0 8px 18px rgba(8,18,35,.18);border:1px solid rgba(255,255,255,.35);backdrop-filter:blur(9px);position:relative;z-index:1;animation:fadeSlideUp .6s ease-out;}
        .login-brand{flex:1.15;background:
            linear-gradient(140deg,rgba(5,24,37,.9) 0%,rgba(15,58,84,.84) 45%,rgba(38,108,132,.8) 100%),
            radial-gradient(circle at 20% 20%,rgba(255,214,143,.35) 0%,rgba(255,214,143,0) 42%);
            padding:2.4rem 2.1rem;display:flex;flex-direction:column;justify-content:space-between;color:#fff;position:relative;overflow:hidden;}
        .login-brand::before{content:"";position:absolute;top:-28%;right:-18%;width:300px;height:300px;background:rgba(255,255,255,.08);border-radius:50%;filter:blur(2px);}
        .login-brand::after{content:"";position:absolute;bottom:-14%;left:-9%;width:230px;height:230px;background:rgba(255,215,150,.16);border-radius:50%;filter:blur(1px);}
        .brand-top,.stat-grid{position:relative;z-index:1;}
        .safe-logo{display:flex;align-items:center;gap:.8rem;margin-bottom:1.7rem;}
        .safe-logo img{width:52px;height:52px;object-fit:contain;border-radius:50%;background:#fff;flex-shrink:0;box-shadow:0 4px 12px rgba(0,0,0,.22);}
        .safe-logo h2{font-size:1.68rem;font-weight:700;letter-spacing:-.3px;margin:0;background:linear-gradient(to right,#fff,#ffe6b0);-webkit-background-clip:text;background-clip:text;color:transparent;}
        .hero-message h1{font-size:2.2rem;font-weight:800;line-height:1.25;margin:0 0 .95rem;letter-spacing:-.4px;}
        .hero-message .highlight{color:#ffd966;border-bottom:3px solid #ffb347;display:inline-block;}
        .hero-message p{margin:0;max-width:85%;font-size:.98rem;line-height:1.5;opacity:.86;}
        .clearance-badge{background:rgba(255,255,255,.15);backdrop-filter:blur(4px);padding:.86rem 1.1rem;border-radius:1.4rem;display:inline-flex;align-items:center;gap:10px;width:fit-content;margin-top:1.55rem;font-weight:500;font-size:.86rem;border:1px solid rgba(255,255,255,.2);}
        .stat-grid{display:flex;gap:1.65rem;margin-top:1.7rem;}
        .stat-item{display:flex;flex-direction:column;}
        .stat-number{font-size:1.7rem;font-weight:800;letter-spacing:-.4px;line-height:1;}
        .stat-label{font-size:.74rem;text-transform:uppercase;opacity:.72;letter-spacing:.5px;margin-top:.28rem;}
        .login-form-panel{flex:1;background:#fff;padding:2.4rem 2.1rem;display:flex;flex-direction:column;justify-content:center;transition:transform .2s ease;}
        .welcome-text{margin-bottom:1.7rem;}
        .login-title{font-size:1.85rem;font-weight:700;color:#0a2b3e;margin:0;letter-spacing:-.3px;}
        .login-subtitle{color:#5a6e7c;font-size:.9rem;margin:.55rem 0 0;border-left:3px solid #ffb347;padding-left:.8rem;}
        .input-group{margin-bottom:1.2rem;}
        .input-label{display:flex;align-items:center;gap:8px;font-weight:600;font-size:.84rem;color:#1f3b4c;margin-bottom:.45rem;}
        .input-label i{font-size:.86rem;color:#ff9f4a;}
        .input-field{width:100%;padding:.88rem 1rem;border-radius:1rem;border:1.5px solid #e2e8f0;background:#fefefe;font-family:"Inter",sans-serif;font-size:.95rem;transition:all .2s ease;outline:none;color:#0f2c3c;}
        .input-field:focus{border-color:#ff9f4a;box-shadow:0 0 0 4px rgba(255,159,74,.15);}
        .input-field::placeholder{color:#b9c7d4;font-weight:400;}
        .error-message{background:#fff2f0;border-left:4px solid #e53e3e;padding:.72rem 1rem;border-radius:.8rem;font-size:.83rem;color:#c53030;margin-bottom:1.1rem;display:none;align-items:center;gap:10px;}
        .error-message.show{display:flex;}
        .signin-btn{width:100%;background:linear-gradient(95deg,#0f3b4f 0%,#1f6390 100%);border:none;padding:.88rem;border-radius:2rem;font-weight:700;font-size:.98rem;color:#fff;display:flex;align-items:center;justify-content:center;gap:10px;cursor:pointer;transition:all .2s;margin-top:.25rem;box-shadow:0 8px 18px -6px rgba(31,99,144,.3);}
        .signin-btn:hover{background:linear-gradient(95deg,#0c3142 0%,#165d86 100%);transform:scale(1.01);box-shadow:0 12px 22px -8px rgba(31,99,144,.4);}
        .signin-btn:disabled{opacity:.8;cursor:not-allowed;transform:none;box-shadow:0 8px 18px -6px rgba(31,99,144,.2);}
        .forgot-link{text-align:right;margin-top:-.5rem;margin-bottom:1rem;font-size:.75rem;}
        .forgot-link a{color:#ff8c42;text-decoration:none;font-weight:500;}
        .forgot-link a:hover{text-decoration:underline;}
        .secure-footer{margin-top:1.8rem;text-align:center;font-size:.72rem;color:#8da1b0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:.55rem;border-top:1px solid #edf2f7;padding-top:1.2rem;}
        .secure-footer-note{display:flex;align-items:center;justify-content:center;gap:6px;}
        .developed-by{font-size:.7rem;color:#8da1b0;}
        .auth-helper-shell{width:100%;max-width:520px;margin:0 auto;}
        .auth-helper-card{background:#fff;border-radius:1.5rem;padding:1.5rem;border:1px solid #dbe7df;box-shadow:0 20px 35px -18px rgba(0,0,0,.25);}
        .auth-helper-title{font-size:1.35rem;font-weight:700;color:#0a2b3e;margin:0 0 .35rem;}
        .auth-helper-subtitle{font-size:.88rem;color:#5a6e7c;margin:0 0 1rem;}
        .auth-helper-card .form-label{font-size:.82rem;font-weight:600;color:#1f3b4c;}
        .auth-helper-card .form-control{border-radius:.9rem;padding:.78rem .92rem;border:1.5px solid #e2e8f0;}
        .auth-helper-card .form-control:focus{border-color:#ff9f4a;box-shadow:0 0 0 4px rgba(255,159,74,.15);}
        .auth-helper-actions{display:flex;gap:.6rem;flex-wrap:wrap;}
        .auth-helper-link{font-size:.82rem;color:#1f6390;text-decoration:none;font-weight:600;}
        .auth-helper-link:hover{text-decoration:underline;}
        .reset-debug{margin-top:.9rem;font-size:.78rem;background:#f8fafe;color:#2d4b63;padding:.65rem .8rem;border-radius:.8rem;word-break:break-all;}
        @keyframes fadeSlideUp{from{opacity:0;transform:translateY(12px);}to{opacity:1;transform:translateY(0);}}
        @media (max-width:991px){
            .login-card{flex-direction:column;border-radius:1.8rem;}
            .login-brand{padding:1.8rem;}
            .hero-message p{max-width:100%;}
            .login-form-panel{padding:2rem 1.5rem;}
            .login-title{font-size:1.55rem;}
            .login-shell{min-height:unset;padding:.6rem 0 1rem;}
            body.login-page{padding:.9rem;}
            body.login-page .login-shell{padding:0;}
        }
        @media (min-width:1200px){
            body.login-page{
                background-size:100% auto;
                background-position:center top;
            }
        }
        body.student-popup-page{background:#f8fafc;min-height:100vh;}
        .student-popup-wrap{max-width:420px;margin:0 auto;}
        .deadline-countdown-card{background:#fff;border:1px solid var(--border);border-radius:14px;padding:1rem 1rem 1.1rem;box-shadow:0 1px 2px rgba(16,24,40,.04);}
        .deadline-countdown-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.45rem;}
        .deadline-countdown-unit{background:#f8fafc;border:1px solid #e5e7eb;border-radius:10px;padding:.55rem .35rem;text-align:center;}
        .deadline-countdown-value{font-size:1.35rem;font-weight:700;line-height:1.1;color:#0f2a37;font-variant-numeric:tabular-nums;}
        .deadline-countdown-label{font-size:.62rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-top:.25rem;}
        .deadline-countdown-shell .section-title{font-size:1.05rem;}
        .deadline-countdown-pinned{position:fixed;right:18px;bottom:18px;z-index:1070;max-width:min(92vw,320px);display:none;}
        .deadline-countdown-pinned.is-collapsed .deadline-countdown-pinned-panel{display:none;}
        .deadline-countdown-pinned:not(.is-collapsed) .deadline-countdown-pinned-bar{display:none;}
        .deadline-countdown-pinned-bar{background:linear-gradient(135deg,#0f3b4f 0%,#1f6390 100%);color:#fff;border:0;border-radius:999px;padding:.45rem .85rem;box-shadow:0 10px 24px rgba(15,59,79,.28);cursor:pointer;font-size:.82rem;font-weight:600;display:inline-flex;align-items:center;gap:.45rem;}
        .deadline-countdown-pinned-bar:hover{transform:translateY(-1px);}
        .deadline-countdown-pinned-panel{background:#fff;border:1px solid var(--border);border-radius:14px;box-shadow:0 12px 32px rgba(15,42,55,.18);overflow:hidden;}
        .deadline-countdown-pinned-head{display:flex;align-items:center;justify-content:space-between;gap:.5rem;padding:.55rem .75rem;background:#f8fafc;border-bottom:1px solid var(--border);font-size:.82rem;font-weight:600;}
        .deadline-countdown-pinned-head-actions{display:flex;align-items:center;gap:.25rem;}
        .deadline-countdown-pinned-head-actions button{border:0;background:transparent;color:#64748b;width:28px;height:28px;border-radius:8px;cursor:pointer;}
        .deadline-countdown-pinned-head-actions button:hover{background:#e2e8f0;color:#0f172a;}
        .deadline-countdown-pinned-body{padding:.75rem;}
        .deadline-countdown-pinned .deadline-countdown-value{font-size:1.05rem;}
        .deadline-countdown-pinned .deadline-countdown-unit{padding:.4rem .25rem;}
        .deadline-countdown-pinned-note{font-size:.72rem;color:var(--muted);text-align:center;margin:.55rem 0 0;}
        @media (min-width:768px){
            .deadline-countdown-pinned{display:block;}
            .student-deadline-inline{display:none!important;}
        }
        body.student-layout .student-account-summary .account-field-label{font-size:.72rem;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);font-weight:600;margin-bottom:.15rem;}
        body.student-layout .student-account-summary .account-field-value{font-size:.9rem;font-weight:500;}
        @media (max-width:767px){
            body.student-layout .page-wrap{padding-top:1rem!important;padding-bottom:1.5rem!important;padding-left:.85rem;padding-right:.85rem;}
            body.student-layout .student-account-header{flex-direction:column;align-items:stretch!important;}
            body.student-layout .student-account-header .text-end{text-align:left!important;}
            body.student-layout .student-account-header form{align-self:flex-start;}
            body.student-layout .student-req-row{flex-direction:column;align-items:flex-start!important;}
            body.student-layout .student-action-bar .btn{flex:1 1 100%;text-align:center;}
            body.student-layout .app-toast-wrap{left:12px;right:12px;max-width:none;}
            body.student-layout .section-title{font-size:1.15rem;}
            body.student-layout .student-account-summary .account-field{flex:0 0 100%;max-width:100%;}
            body.student-layout .card-body.d-flex.flex-wrap.justify-content-between>.btn{width:100%;}
        }
        </style>';
    }
    echo '<style>
    .app-toast-wrap{position:fixed;top:18px;right:18px;z-index:1080;max-width:min(92vw,420px);}
    .app-toast{display:flex;align-items:flex-start;gap:10px;background:#0f172a;color:#fff;border-radius:12px;padding:12px 14px;box-shadow:0 10px 30px rgba(2,6,23,.28);border:1px solid rgba(255,255,255,.16);opacity:0;transform:translateY(-8px);pointer-events:none;transition:opacity .2s ease,transform .2s ease;}
    .app-toast.show{opacity:1;transform:translateY(0);pointer-events:auto;}
    .app-toast i{font-size:1rem;margin-top:2px;color:#93c5fd;}
    .app-toast-text{flex:1;font-size:.9rem;line-height:1.35;}
    .app-toast-close{border:0;background:transparent;color:#cbd5e1;font-size:1.1rem;line-height:1;cursor:pointer;padding:0 2px;}
    .app-toast-close:hover{color:#fff;}
    </style>';
    if ($enableStudentPwa) {
        echo renderStudentPwaHead();
    }
    $bodyClass = match (true) {
        $isStudentAppAuth || ($isStudentAppGate && !$isStudentView) => 'student-app-auth',
        $isAuthPage => 'login-page',
        $isAdminView => 'admin-layout',
        $isStudentPopup => 'student-popup-page',
        $isStudentView => 'student-layout student-app',
        default => '',
    };
    echo '</head><body' . ($bodyClass !== '' ? ' class="' . $bodyClass . '"' : '') . '>';
    $studentUnread = 0;
    if ($isStudentView) {
        global $service;
        $openSemester = $service->getOpenSemester();
        if ($openSemester !== null) {
            $studentUnread = $service->getUnreadClearanceMessageCountForStudent(
                (int) ($_SESSION['user']['id'] ?? 0),
                (int) $openSemester['id']
            );
        }
        echo renderStudentAppTopbar($_SESSION['user'] ?? []);
        echo '<div class="sapp-layout">';
        echo renderStudentAppNav($requestPath, $studentUnread, 'side');
    }
    $mainClass = $isAdminView
        ? ''
        : ($isAuthPage || $isStudentAppAuth || ($isStudentAppGate && !$isStudentView)
            ? ''
            : ($isStudentPopup
                ? 'student-popup-wrap py-3 px-3'
                : ($isStudentView ? 'container page-wrap py-4 sapp-main' : 'container page-wrap py-4')));
    echo '<main class="' . $mainClass . '">';
    if (!$isAdminView && !$isAuthPage && !$isStudentPopup && !$isStudentView && !$isStudentAppGate && isset($_SESSION['user'])) {
        $su = $_SESSION['user'];
        $accName = htmlspecialchars((string) ($su['display_account_name'] ?? ''));
        if ($accName === '') {
            $accName = htmlspecialchars(trim((string) ($su['first_name'] ?? '') . ' ' . (string) ($su['last_name'] ?? '')));
        }
        $dept = htmlspecialchars((string) ($su['display_department'] ?? ''));
        if ($dept === '') {
            $dept = '—';
        }
        echo '<div class="d-flex flex-wrap align-items-center justify-content-end gap-3 mb-3 pb-2 border-bottom">';
        echo '<div class="text-end small lh-sm">';
        echo '<div class="fw-semibold">' . $accName . '</div>';
        echo '<div class="text-muted" style="font-size:0.8rem;">' . $dept . '</div>';
        echo '</div>';
        echo '<form method="POST" action="' . hpath('/logout') . '" class="mb-0"><button class="btn btn-sm btn-outline-secondary" type="submit">Logout</button></form>';
        echo '</div>';
        $role = (string) ($su['role'] ?? '');
        if ($role === 'signatory') {
            global $service;
            $headerNotifications = $service->getNotifications((int) ($su['id'] ?? 0));
            echo renderTopNotificationsBar($headerNotifications);
        }
    }
    if ($isStudentView) {
        echo renderStudentAppInstallBanner();
        global $service;
        $headerNotifications = $service->getNotifications((int) ($_SESSION['user']['id'] ?? 0));
        echo renderTopNotificationsBar($headerNotifications);
    }
    if ($flash) {
        $flashText = (string) $flash;
        echo '<div class="app-toast-wrap" aria-live="polite" aria-atomic="true">';
        echo '<div class="app-toast" role="status" data-app-toast>';
        echo '<i class="fas fa-circle-info" aria-hidden="true"></i>';
        echo '<div class="app-toast-text">' . htmlspecialchars($flashText) . '</div>';
        echo '<button type="button" class="app-toast-close" data-app-toast-close aria-label="Close message">&times;</button>';
        echo '</div></div>';
    }
    echo $content;
    if ($flash) {
        echo '<script>
        (function(){
            var toast = document.querySelector("[data-app-toast]");
            if (!toast) { return; }
            var closeBtn = document.querySelector("[data-app-toast-close]");
            var hide = function(){
                toast.classList.remove("show");
                setTimeout(function(){
                    var wrap = toast.parentElement;
                    if (wrap) { wrap.remove(); }
                }, 220);
            };
            setTimeout(function(){ toast.classList.add("show"); }, 10);
            var autoTimer = setTimeout(hide, 4500);
            if (closeBtn) {
                closeBtn.addEventListener("click", function(){
                    clearTimeout(autoTimer);
                    hide();
                });
            }
        })();
        </script>';
    }
    echo renderCapitalizeInputScript();
    if (!$isAdminView && !$isAuthPage && !$isStudentAppAuth && isset($_SESSION['user'])) {
        echo renderStudentDeadlineCountdownLaunchScript();
    }
    echo '</main>';
    if ($isStudentView) {
        echo '</div>';
        echo renderStudentAppNav($requestPath, $studentUnread, 'tab');
    }
    if ($enableStudentPwa) {
        echo renderStudentPwaScripts();
    }
    echo AuthLayer::csrfScript();
    echo '</body></html>';
}

function renderCapitalizeInputScript(): string
{
    return '<script>
(function(){
    var skipTypes={"password":1,"email":1,"number":1,"tel":1,"url":1,"file":1,"hidden":1,"checkbox":1,"radio":1,"date":1,"time":1,"datetime-local":1,"range":1,"color":1,"month":1,"week":1,"search":1};
    var skipNames={"email":1,"password":1,"student_no":1,"code":1,"search_name":1,"token":1,"new_password":1,"confirm_password":1,"current_password":1,"academic_year":1};
    function shouldCapitalize(el){
        if(!el||el.disabled||el.readOnly)return false;
        var tag=el.tagName;
        if(tag!=="INPUT"&&tag!=="TEXTAREA")return false;
        var type=(el.type||"text").toLowerCase();
        if(skipTypes[type])return false;
        var name=(el.name||"").toLowerCase();
        if(skipNames[name])return false;
        if(name.indexOf("password")!==-1)return false;
        return true;
    }
    function capitalizeValue(value,multiline){
        if(!value)return value;
        var pattern=multiline?/(^|[\r\n]+)(\s*)([a-z])/g:/^(\s*)([a-z])/;
        return value.replace(pattern,function(_,lineStart,spaces,letter){
            return lineStart+spaces+letter.toUpperCase();
        });
    }
    function applyCapitalize(el){
        if(!shouldCapitalize(el))return;
        var multiline=el.tagName==="TEXTAREA";
        var val=el.value;
        var next=capitalizeValue(val,multiline);
        if(next===val)return;
        var start=el.selectionStart,end=el.selectionEnd;
        el.value=next;
        if(typeof start==="number"&&typeof end==="number"){
            try{el.setSelectionRange(start,end);}catch(e){}
        }
    }
    function wireField(el){
        if(!shouldCapitalize(el))return;
        el.setAttribute("autocapitalize","sentences");
        applyCapitalize(el);
    }
    function wireAll(root){
        (root||document).querySelectorAll("input,textarea").forEach(wireField);
    }
    document.addEventListener("input",function(e){applyCapitalize(e.target);},true);
    document.addEventListener("blur",function(e){applyCapitalize(e.target);},true);
    if(document.readyState==="loading"){
        document.addEventListener("DOMContentLoaded",function(){wireAll(document);});
    }else{
        wireAll(document);
    }
})();
</script>';
}

function renderClearanceDeadlineBanner(array $deadlineStatus): string
{
    if (!($deadlineStatus['has_deadline'] ?? false)) {
        return '';
    }

    $bannerClass = htmlspecialchars((string) ($deadlineStatus['banner_class'] ?? 'alert-info'));
    $statusLabel = htmlspecialchars((string) ($deadlineStatus['status_label'] ?? ''));
    $dueDateLabel = htmlspecialchars((string) ($deadlineStatus['due_date_label'] ?? ''));
    $bannerMessage = htmlspecialchars((string) ($deadlineStatus['banner_message'] ?? ''));

    $html = '<div class="alert ' . $bannerClass . ' d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">';
    $html .= '<div><strong><i class="fas fa-calendar-check me-2" aria-hidden="true"></i>Completion due date: ' . $dueDateLabel . '</strong>';
    $html .= '<div class="small mb-0">' . $bannerMessage . '</div></div>';
    $html .= '<span class="badge text-bg-light border">' . $statusLabel . '</span>';
    $html .= '</div>';

    return $html;
}

function renderDeadlineCountdownTicker(array $deadlineStatus): string
{
    if (!($deadlineStatus['has_deadline'] ?? false)) {
        return '';
    }

    $dueDate = htmlspecialchars((string) ($deadlineStatus['due_date'] ?? ''));
    $isExpired = ($deadlineStatus['is_expired'] ?? false) ? '1' : '0';
    $isWindowOpen = ($deadlineStatus['is_window_open'] ?? false) ? '1' : '0';

    $html = '<div data-deadline-countdown data-due-date="' . $dueDate . '"';
    $html .= ' data-is-expired="' . $isExpired . '" data-is-window-open="' . $isWindowOpen . '">';
    $html .= '<div class="deadline-countdown-grid" aria-live="polite">';
    foreach (['days', 'hours', 'minutes', 'seconds'] as $unit) {
        $label = ucfirst($unit);
        $html .= '<div class="deadline-countdown-unit"><div class="deadline-countdown-value" data-countdown-' . $unit . '>--</div>';
        $html .= '<div class="deadline-countdown-label">' . $label . '</div></div>';
    }
    $html .= '</div>';
    $html .= '<p class="small text-muted text-center mt-3 mb-0" data-countdown-note>Loading countdown...</p>';
    $html .= '</div>';

    return $html;
}

function renderStudentDeadlineCountdownDisplay(array $deadlineStatus): string
{
    if (!($deadlineStatus['has_deadline'] ?? false)) {
        return '';
    }

    $dueDateLabel = htmlspecialchars((string) ($deadlineStatus['due_date_label'] ?? ''));
    $statusLabel = htmlspecialchars((string) ($deadlineStatus['status_label'] ?? ''));

    $html = '<div class="card mb-3 student-deadline-inline"><div class="card-body">';
    $html .= '<div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">';
    $html .= '<strong><i class="fas fa-hourglass-half me-2 text-warning" aria-hidden="true"></i>Clearance deadline</strong>';
    $html .= '<span class="badge text-bg-light border">' . $statusLabel . '</span>';
    $html .= '</div>';
    $html .= '<p class="small text-muted mb-3">Due: <strong>' . $dueDateLabel . '</strong></p>';
    $html .= '<div class="deadline-countdown-card">' . renderDeadlineCountdownTicker($deadlineStatus) . '</div>';
    $html .= '</div></div>';

    return $html;
}

function renderStudentDeadlinePinnedWidget(array $deadlineStatus): string
{
    if (!($deadlineStatus['has_deadline'] ?? false)) {
        return '';
    }

    $dueDateLabel = htmlspecialchars((string) ($deadlineStatus['due_date_label'] ?? ''));
    $statusLabel = htmlspecialchars((string) ($deadlineStatus['status_label'] ?? ''));

    $html = '<div class="deadline-countdown-pinned" data-deadline-pinned>';
    $html .= '<button type="button" class="deadline-countdown-pinned-bar" data-deadline-pinned-expand aria-label="Expand deadline countdown">';
    $html .= '<i class="fas fa-hourglass-half" aria-hidden="true"></i>';
    $html .= '<span><span data-countdown-days-mini>--</span>d left</span>';
    $html .= '</button>';
    $html .= '<div class="deadline-countdown-pinned-panel" data-deadline-pinned-body>';
    $html .= '<div class="deadline-countdown-pinned-head">';
    $html .= '<span><i class="fas fa-hourglass-half me-1 text-warning" aria-hidden="true"></i>Clearance deadline</span>';
    $html .= '<div class="deadline-countdown-pinned-head-actions">';
    $html .= '<button type="button" data-deadline-pinned-collapse aria-label="Minimize countdown"><i class="fas fa-minus" aria-hidden="true"></i></button>';
    $html .= '</div></div>';
    $html .= '<div class="deadline-countdown-pinned-body">';
    $html .= '<div class="small text-muted mb-2">Due <strong>' . $dueDateLabel . '</strong> · ' . $statusLabel . '</div>';
    $pinnedTicker = renderDeadlineCountdownTicker($deadlineStatus);
    $pinnedTicker = str_replace(
        'class="small text-muted text-center mt-3 mb-0"',
        'class="deadline-countdown-pinned-note mb-0"',
        $pinnedTicker
    );
    $html .= $pinnedTicker;
    $html .= '</div></div></div>';

    return $html;
}

function renderStudentDeadlineCountdownLaunchScript(): string
{
    return '<script>
(function(){
    function pad(n){return String(n).padStart(2,"0");}
    function wireCountdown(root){
        if(root.dataset.deadlineTickerBound==="1"){return;}
        root.dataset.deadlineTickerBound="1";
        var dueDate=root.getAttribute("data-due-date")||"";
        var isExpired=root.getAttribute("data-is-expired")==="1";
        var isWindowOpen=root.getAttribute("data-is-window-open")==="1";
        var dayEl=root.querySelector("[data-countdown-days]");
        var hourEl=root.querySelector("[data-countdown-hours]");
        var minuteEl=root.querySelector("[data-countdown-minutes]");
        var secondEl=root.querySelector("[data-countdown-seconds]");
        var noteEl=root.querySelector("[data-countdown-note]");
        var miniDayEl=root.closest("[data-deadline-pinned]")?root.closest("[data-deadline-pinned]").querySelector("[data-countdown-days-mini]"):null;
        if(!dayEl||!hourEl||!minuteEl||!secondEl||!dueDate){return;}
        function setParts(days,hours,minutes,seconds){
            dayEl.textContent=pad(days);
            hourEl.textContent=pad(hours);
            minuteEl.textContent=pad(minutes);
            secondEl.textContent=pad(seconds);
            if(miniDayEl){miniDayEl.textContent=String(days);}
        }
        function update(){
            var dueEnd=new Date(dueDate+"T23:59:59");
            if(isNaN(dueEnd.getTime())){
                if(noteEl){noteEl.textContent="Unable to load countdown.";}
                return;
            }
            var diffMs=dueEnd.getTime()-Date.now();
            if(diffMs<=0){
                setParts(0,0,0,0);
                if(noteEl){
                    if(isExpired&&!isWindowOpen){
                        noteEl.textContent="The clearance window is closed.";
                    }else if(isExpired){
                        noteEl.textContent="Deadline passed. Finish pending items soon.";
                    }else{
                        noteEl.textContent="Deadline reached for today.";
                    }
                }
                return;
            }
            var totalSeconds=Math.floor(diffMs/1000);
            var days=Math.floor(totalSeconds/86400);
            totalSeconds%=86400;
            var hours=Math.floor(totalSeconds/3600);
            totalSeconds%=3600;
            var minutes=Math.floor(totalSeconds/60);
            var seconds=totalSeconds%60;
            setParts(days,hours,minutes,seconds);
            if(noteEl){
                if(days===0){
                    noteEl.textContent="Less than 24 hours remaining.";
                }else{
                    noteEl.textContent=days+" day(s) remaining.";
                }
            }
        }
        update();
        setInterval(update,1000);
    }
    function wirePinned(){
        document.querySelectorAll("[data-deadline-pinned]").forEach(function(pin){
            if(pin.dataset.deadlinePinnedBound==="1"){return;}
            pin.dataset.deadlinePinnedBound="1";
            var collapseBtn=pin.querySelector("[data-deadline-pinned-collapse]");
            var expandBtn=pin.querySelector("[data-deadline-pinned-expand]");
            var storageKey="clearanceDeadlinePinnedCollapsed";
            if(sessionStorage.getItem(storageKey)==="1"){
                pin.classList.add("is-collapsed");
            }
            if(collapseBtn){
                collapseBtn.addEventListener("click",function(){
                    pin.classList.add("is-collapsed");
                    sessionStorage.setItem(storageKey,"1");
                });
            }
            if(expandBtn){
                expandBtn.addEventListener("click",function(){
                    pin.classList.remove("is-collapsed");
                    sessionStorage.setItem(storageKey,"0");
                });
            }
        });
    }
    document.querySelectorAll("[data-deadline-countdown]").forEach(wireCountdown);
    wirePinned();
})();
</script>';
}

function renderStudentDeadlineCountdownPage(array $semester, array $deadlineStatus): string
{
    if (!($deadlineStatus['has_deadline'] ?? false)) {
        return '<div class="alert alert-secondary mb-0">No completion deadline is set for this semester.</div>';
    }

    $dueDateLabel = htmlspecialchars((string) ($deadlineStatus['due_date_label'] ?? ''));
    $statusLabel = htmlspecialchars((string) ($deadlineStatus['status_label'] ?? ''));
    $bannerClass = htmlspecialchars((string) ($deadlineStatus['banner_class'] ?? 'alert-info'));
    $bannerMessage = htmlspecialchars((string) ($deadlineStatus['banner_message'] ?? ''));
    $semesterLabel = htmlspecialchars($semester['academic_year'] . ' ' . $semester['term']);

    $html = '<div class="deadline-countdown-shell">';
    $html .= '<div class="d-flex justify-content-between align-items-start gap-2 mb-3">';
    $html .= '<div><h5 class="section-title mb-0">Deadline Countdown</h5>';
    $html .= '<p class="muted-caption mb-0">' . $semesterLabel . '</p></div>';
    $html .= '<span class="badge text-bg-light border">' . $statusLabel . '</span>';
    $html .= '</div>';
    $html .= '<div class="deadline-countdown-card mb-3">';
    $html .= '<p class="small text-muted mb-2 mb-md-3">Due: <strong>' . $dueDateLabel . '</strong></p>';
    $html .= renderDeadlineCountdownTicker($deadlineStatus);
    $html .= '</div>';
    $html .= '<div class="alert ' . $bannerClass . ' small mb-0">' . $bannerMessage . '</div>';
    $html .= '</div>';

    return $html;
}

function renderTopNotificationsBar(array $notifications): string
{
    $count = count($notifications);
    $html = '<div class="app-notifications-top" aria-label="Notifications">';
    $html .= '<div class="notif-head"><span><i class="fas fa-bell me-2 text-primary" aria-hidden="true"></i>Notifications</span>';
    if ($count > 0) {
        $html .= '<span class="badge bg-primary rounded-pill">' . $count . '</span>';
    }
    $html .= '</div><div class="notif-body">';
    if ($count === 0) {
        $html .= '<p class="notif-empty mb-0">No notifications yet.</p>';
    } else {
        foreach ($notifications as $notif) {
            $html .= '<div class="notif-item">';
            $html .= '<div class="notif-title">' . htmlspecialchars((string) ($notif['title'] ?? '')) . '</div>';
            $html .= '<p class="notif-text">' . htmlspecialchars((string) ($notif['body'] ?? '')) . '</p>';
            $html .= '</div>';
        }
    }
    $html .= '</div></div>';

    return $html;
}

function renderAdminShell(string $activePath, array $semester, string $innerHtml): string
{
    $su = $_SESSION['user'] ?? [];
    $accName = htmlspecialchars((string) ($su['display_account_name'] ?? ''));
    if ($accName === '') {
        $accName = htmlspecialchars(trim((string) ($su['first_name'] ?? '') . ' ' . (string) ($su['last_name'] ?? '')));
    }
    $dept = htmlspecialchars((string) ($su['display_department'] ?? ''));
    if ($dept === '') {
        $dept = '—';
    }
    $photoPath = trim((string) ($su['profile_photo_path'] ?? ''));
    $avatarHtml = '<div class="admin-avatar"><i class="fas fa-user-shield" aria-hidden="true"></i></div>';
    if ($photoPath !== '') {
        $avatarHtml = '<img class="admin-avatar" src="' . hpath('/' . ltrim($photoPath, '/')) . '" alt="Admin profile photo">';
    }
    $userBlock = '<a class="admin-user-link" href="' . hpath('/admin/settings') . '" title="Account settings">'
        . $avatarHtml
        . '<div class="admin-user-block"><div class="admin-user-name">' . $accName . '</div><div class="admin-user-dept">' . $dept . '</div></div>'
        . '</a>';

    return '<div class="admin-app">'
        . renderAdminControlPanel($activePath)
        . '<div class="admin-main"><div class="admin-top">'
        . '<div class="semester-badge"><i class="fas fa-calendar-alt me-2"></i>Open semester: '
        . htmlspecialchars($semester['academic_year'] . ' ' . $semester['term'])
        . '</div>'
        . '<div class="admin-top-actions">' . $userBlock
        . '<form method="POST" action="' . hpath('/logout') . '" class="mb-0"><button class="logout-btn" type="submit"><i class="fas fa-sign-out-alt"></i>Logout</button></form>'
        . '</div></div><div class="admin-content">' . $innerHtml . '</div></div></div>';
}

function formatLoginStatCount(int $value): string
{
    return number_format(max(0, $value));
}

function buildLoginStats(ClearanceService $service): array
{
    $openSemester = $service->getOpenSemester();
    $semesterId = $openSemester ? (int) ($openSemester['id'] ?? 0) : 0;

    $studentRows = $semesterId > 0 ? $service->listStudentsWithOverallStatus($semesterId) : [];
    $activeStudents = count($studentRows);
    $clearedStudents = 0;
    foreach ($studentRows as $row) {
        if ((string) ($row['overall_status'] ?? '') === 'cleared') {
            $clearedStudents++;
        }
    }

    $activeSignatories = count($service->listSignatoryUsers());
    $digitalProcessPercent = $activeStudents > 0
        ? (int) round(($clearedStudents / $activeStudents) * 100)
        : 0;

    return [
        'active_students' => formatLoginStatCount($activeStudents),
        'signatories' => formatLoginStatCount($activeSignatories),
        'digital_process_percent' => $digitalProcessPercent . '%',
    ];
}

function renderLoginForm(?string $error, ?array $stats = null): string
{
    $safeError = htmlspecialchars((string) ($error ?? ''), ENT_QUOTES, 'UTF-8');
    $errorClass = $error ? ' show' : '';
    $stats = $stats ?? [
        'active_students' => '0',
        'signatories' => '0',
        'digital_process_percent' => '0%',
    ];
    $activeStudentsStat = htmlspecialchars((string) ($stats['active_students'] ?? '0'), ENT_QUOTES, 'UTF-8');
    $signatoriesStat = htmlspecialchars((string) ($stats['signatories'] ?? '0'), ENT_QUOTES, 'UTF-8');
    $digitalProcessStat = htmlspecialchars((string) ($stats['digital_process_percent'] ?? '0%'), ENT_QUOTES, 'UTF-8');
    $wpuLogoSrc = hasset('wpu-logo.png');

    return '<div class="login-shell">
<div class="login-card">
    <div class="login-brand">
        <div class="brand-top">
            <div class="safe-logo">
                <img src="' . $wpuLogoSrc . '" alt="Western Philippines University">
                <h2>SAFE</h2>
            </div>
            <div class="hero-message">
                <h1>Final Semestral <span class="highlight">Clearance</span> Management</h1>
                <p>Streamlined digital workflow for students, signatories, and administrators.</p>
                <div class="clearance-badge">
                    <i class="fas fa-check-circle"></i>
                    <span>Real-time tracking · Multi-signature · Paperless</span>
                </div>
            </div>
        </div>
        <div class="stat-grid">
            <div class="stat-item"><span class="stat-number">' . $activeStudentsStat . '</span><span class="stat-label">Active Students</span></div>
            <div class="stat-item"><span class="stat-number">' . $signatoriesStat . '</span><span class="stat-label">Signatories</span></div>
            <div class="stat-item"><span class="stat-number">' . $digitalProcessStat . '</span><span class="stat-label">Digital Process</span></div>
        </div>
    </div>

    <div class="login-form-panel">
        <div class="welcome-text">
            <h4 class="login-title">Welcome back 👋</h4>
            <p class="login-subtitle">Sign in to continue your clearance journey - students, signatories & admins.</p>
        </div>

        <div id="errorBox" class="error-message' . $errorClass . '">
            <i class="fas fa-exclamation-triangle"></i>
            <span id="errorText">' . ($safeError !== '' ? $safeError : 'Invalid credentials or inactive account.') . '</span>
        </div>

        <form id="loginForm" method="POST" action="' . hpath('/login') . '">
            ' . csrf_field() . '
            <div class="input-group">
                <label class="input-label"><i class="fas fa-envelope"></i><span>Email address</span></label>
                <input type="email" id="email" name="email" class="input-field" placeholder="student@wpu.edu.ph" required>
            </div>
            <div class="input-group">
                <label class="input-label"><i class="fas fa-lock"></i><span>Password</span></label>
                <input type="password" id="password" name="password" class="input-field" placeholder="••••••••" required>
            </div>
            <div class="forgot-link"><a href="' . hpath('/forgot-password') . '">Forgot password?</a></div>
            <button type="submit" class="signin-btn">
                <i class="fas fa-arrow-right-to-bracket"></i> Sign in
            </button>
        </form>

        <div class="secure-footer">
            <div class="secure-footer-note">
                <i class="fas fa-shield-alt"></i>
                <span>Secure access for authorized users only</span>
            </div>
            <a class="sapp-staff-link" href="' . hpath('/app') . '" style="margin-top:0;">Students: open the Student App (desktop + phone install)</a>
            <span class="developed-by">Developed by: College of Computing Arts and Sciences</span>
        </div>
    </div>
</div>
</div>
<script>
(() => {
    const form = document.getElementById("loginForm");
    const errorBox = document.getElementById("errorBox");
    const errorTextSpan = document.getElementById("errorText");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");
    const formPanel = document.querySelector(".login-form-panel");
    const btn = form ? form.querySelector(".signin-btn") : null;
    if (!form || !errorBox || !errorTextSpan || !emailInput || !passwordInput || !formPanel || !btn) return;

    function showError(message) {
        errorTextSpan.innerText = message;
        errorBox.classList.add("show");
        setTimeout(() => {
            if (errorBox.classList.contains("show")) errorBox.classList.remove("show");
        }, 4500);
    }

    function hideError() {
        errorBox.classList.remove("show");
    }

    function validateCredentials(email, password) {
        const emailPattern = /^[^\\s@]+@([^\\s@]+\\.)+[^\\s@]+$/;
        if (!emailPattern.test(email)) {
            return { valid: false, message: "Please enter a valid email address (e.g., name@domain.com)." };
        }
        if (!password || password.trim() === "") {
            return { valid: false, message: "Password cannot be empty. Please enter your credentials." };
        }
        return { valid: true, message: "" };
    }

    form.addEventListener("submit", (e) => {
        e.preventDefault();
        hideError();
        const email = emailInput.value.trim();
        const password = passwordInput.value;
        const validation = validateCredentials(email, password);
        if (!validation.valid) {
            showError(validation.message);
            formPanel.style.transform = "translateX(4px)";
            setTimeout(() => { formPanel.style.transform = ""; }, 80);
            setTimeout(() => { formPanel.style.transform = "translateX(-2px)"; }, 150);
            setTimeout(() => { formPanel.style.transform = ""; }, 220);
            return;
        }

        const originalText = btn.innerHTML;
        btn.innerHTML = "<i class=\\"fas fa-spinner fa-pulse\\"></i> Authenticating...";
        btn.disabled = true;
        setTimeout(() => {
            btn.innerHTML = originalText;
            btn.disabled = false;
            form.submit();
        }, 800);
    });

    emailInput.addEventListener("input", () => {
        if (errorBox.classList.contains("show")) hideError();
    });
    passwordInput.addEventListener("input", () => {
        if (errorBox.classList.contains("show")) hideError();
    });
})();
</script>';
}

function renderForgotPasswordForm(
    ?string $error,
    ?string $email = null,
    ?string $success = null,
    ?string $debugResetUrl = null,
    ?string $emailNotice = null
): string
{
    $fromApp = ((string) ($_GET['from'] ?? $_POST['from'] ?? '')) === 'app';
    $backPath = $fromApp ? '/app' : '/login';
    $formAction = hpath('/forgot-password') . ($fromApp ? '?from=app' : '');
    $safeEmail = htmlspecialchars((string) ($email ?? ''), ENT_QUOTES, 'UTF-8');
    $html = '<div class="auth-helper-shell"><div class="auth-helper-card">';
    $html .= '<h2 class="auth-helper-title">Forgot Password</h2>';
    $html .= '<p class="auth-helper-subtitle">Enter your account email to request a password reset link.</p>';
    if ($error) {
        $html .= '<div class="error-message show"><i class="fas fa-exclamation-triangle"></i><span>' . htmlspecialchars($error) . '</span></div>';
    }
    if ($success) {
        $html .= '<div class="alert alert-success py-2 px-3 small">' . htmlspecialchars($success) . '</div>';
    }
    if ($emailNotice) {
        $html .= '<div class="alert alert-warning py-2 px-3 small">' . htmlspecialchars($emailNotice) . '</div>';
    }
    $html .= '<form method="POST" action="' . $formAction . '">';
    $html .= csrf_field();
    if ($fromApp) {
        $html .= '<input type="hidden" name="from" value="app">';
    }
    $html .= '<div class="mb-3"><label class="form-label">Email address</label><input type="email" name="email" class="form-control" value="' . $safeEmail . '" placeholder="name@wpu.edu.ph" required></div>';
    $html .= '<div class="auth-helper-actions"><button type="submit" class="signin-btn" style="margin-top:0;">Send reset link</button></div>';
    $html .= '</form>';
    if ($debugResetUrl) {
        $html .= '<div class="reset-debug"><strong>Reset link (for local testing):</strong><br><a class="auth-helper-link" href="' . htmlspecialchars($debugResetUrl) . '">' . htmlspecialchars($debugResetUrl) . '</a></div>';
    }
    $html .= '<div class="mt-3"><a class="auth-helper-link" href="' . hpath($backPath) . '"><i class="fas fa-arrow-left me-1"></i>Back to sign in</a></div>';
    $html .= '</div></div>';
    return $html;
}

function renderResetPasswordForm(string $token, ?string $error = null, ?string $success = null): string
{
    $safeToken = htmlspecialchars($token, ENT_QUOTES, 'UTF-8');
    $html = '<div class="auth-helper-shell"><div class="auth-helper-card">';
    $html .= '<h2 class="auth-helper-title">Reset Password</h2>';
    $html .= '<p class="auth-helper-subtitle">Create a new password for your account.</p>';
    if ($error) {
        $html .= '<div class="error-message show"><i class="fas fa-exclamation-triangle"></i><span>' . htmlspecialchars($error) . '</span></div>';
    }
    if ($success) {
        $html .= '<div class="alert alert-success py-2 px-3 small">' . htmlspecialchars($success) . '</div>';
    }
    if ($token !== '' && $success === null) {
        $html .= '<form method="POST" action="' . hpath('/reset-password') . '">';
        $html .= csrf_field();
        $html .= '<input type="hidden" name="token" value="' . $safeToken . '">';
        $html .= '<div class="mb-3"><label class="form-label">New password</label><input type="password" name="new_password" class="form-control" minlength="8" required></div>';
        $html .= '<div class="mb-3"><label class="form-label">Confirm password</label><input type="password" name="confirm_password" class="form-control" minlength="8" required></div>';
        $html .= '<button type="submit" class="signin-btn" style="margin-top:0;">Reset password</button>';
        $html .= '</form>';
    } elseif ($success === null) {
        $html .= '<div class="error-message show"><i class="fas fa-exclamation-triangle"></i><span>Invalid or missing reset token.</span></div>';
    }
    $html .= '<div class="mt-3"><a class="auth-helper-link" href="' . hpath('/login') . '"><i class="fas fa-arrow-left me-1"></i>Back to sign in</a></div>';
    $html .= '</div></div>';
    return $html;
}

function clearanceMessagingBubbleCss(): string
{
    return <<<'CSS'
.clearance-imsg{font-size:.88rem;}
.clearance-imsg .imsg-log{max-height:360px;overflow-y:auto;border:1px solid #e5e7eb;border-radius:12px;padding:.75rem .85rem;background:#f3f4f6;}
.clearance-imsg .imsg-row{display:flex;margin-bottom:.65rem;}
.clearance-imsg .imsg-row.imsg-self{justify-content:flex-end;}
.clearance-imsg .imsg-bubble{max-width:min(92%,420px);border-radius:16px;padding:.55rem .8rem;line-height:1.45;word-break:break-word;}
.clearance-imsg .imsg-in .imsg-bubble{background:#fff;border:1px solid #e5e7eb;}
.clearance-imsg .imsg-self .imsg-bubble{background:#1877f2;color:#fff;border:none;}
.clearance-imsg .imsg-meta{font-size:.7rem;color:#6b7280;margin-top:.25rem;}
.clearance-imsg .imsg-self .imsg-meta{color:rgba(255,255,255,.88);}
.clearance-imsg .imsg-name{font-weight:600;font-size:.76rem;margin-bottom:.12rem;color:#374151;}
.clearance-imsg .imsg-self .imsg-name{color:rgba(255,255,255,.95);}
CSS;
}

/**
 * @param list<array<string,mixed>> $messages
 * @param list<array{id:int, first_name:string, last_name:string, offices_label:string}> $signatoryChoices
 */
function buildStudentClearanceMessagesPanel(
    array $user,
    array $semester,
    array $messages,
    int $unreadCount,
    array $signatoryChoices,
    int $selectedSignatoryId,
    string $panelBasePath = '/dashboard'
): string {
    $semLabel = htmlspecialchars($semester['academic_year'] . ' ' . $semester['term']);
    $html = '<div class="card mb-4" id="clearance-messages"><div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">';
    $html .= '<strong><i class="fas fa-comments me-2 text-primary" aria-hidden="true"></i>Messages to signatories</strong>';
    if ($unreadCount > 0) {
        $html .= '<span class="badge bg-primary rounded-pill">' . (int) $unreadCount . ' new</span>';
    }
    $html .= '</div><div class="card-body">';
    $html .= '<p class="small text-muted mb-2">Choose a signatory to message.</p>';
    if ($signatoryChoices === []) {
        $html .= '<div class="alert alert-info small mb-0">Walang naka-assign na signatory ngayong semester. (No signatories are assigned yet for this semester.)</div></div></div>';

        return $html;
    }
    $html .= '<form method="get" action="' . hpath($panelBasePath) . '" class="mb-3"><label class="form-label small fw-semibold text-muted mb-1">Signatory</label>';
    $html .= '<select class="form-select" name="msg_signatory" onchange="this.form.submit()">';
    foreach ($signatoryChoices as $s) {
        $sid = (int) ($s['id'] ?? 0);
        $sel = $sid === $selectedSignatoryId ? ' selected' : '';
        $off = trim((string) ($s['offices_label'] ?? ''));
        $label = trim((string) ($s['last_name'] ?? '')) . ', ' . trim((string) ($s['first_name'] ?? ''));
        if ($off !== '') {
            $label .= ' — ' . $off;
        }
        $html .= '<option value="' . $sid . '"' . $sel . '>' . htmlspecialchars($label) . '</option>';
    }
    $html .= '</select></form>';
    $html .= '<style>' . clearanceMessagingBubbleCss() . '</style>';
    $html .= '<div class="clearance-imsg"><div class="imsg-log">';
    if ($messages === []) {
        $html .= '<p class="text-muted mb-0 small">No messages yet with this signatory. Say hello or ask a question below.</p>';
    } else {
        $uid = (int) $user['id'];
        foreach ($messages as $m) {
            $sid = (int) ($m['sender_user_id'] ?? 0);
            $self = $sid === $uid;
            $role = strtolower((string) ($m['sender_role'] ?? ''));
            $namePlain = trim((string) ($m['first_name'] ?? '') . ' ' . (string) ($m['last_name'] ?? ''));
            if ($self) {
                $whoLinePlain = 'You';
            } elseif ($role === 'signatory') {
                $whoLinePlain = 'Signatory' . ($namePlain !== '' ? ' · ' . $namePlain : '');
            } else {
                $whoLinePlain = 'Student' . ($namePlain !== '' ? ' · ' . $namePlain : '');
            }
            $ts = isset($m['created_at']) ? date('M j, g:i A', strtotime((string) $m['created_at'])) : '';
            $body = nl2br(htmlspecialchars((string) ($m['body'] ?? ''), ENT_QUOTES, 'UTF-8'));
            $rowClass = $self ? 'imsg-row imsg-self' : 'imsg-row imsg-in';
            $html .= '<div class="' . $rowClass . '"><div class="imsg-bubble">';
            $html .= '<div class="imsg-name">' . htmlspecialchars($whoLinePlain) . '</div>';
            $html .= '<div>' . $body . '</div>';
            $html .= '<div class="imsg-meta">' . htmlspecialchars($ts) . '</div></div></div>';
        }
    }
    $html .= '</div></div>';
    $html .= '<form method="POST" action="' . hpath('/student/clearance-message/send') . '" class="mt-3">';
    $html .= '<input type="hidden" name="signatory_user_id" value="' . (int) $selectedSignatoryId . '">';
    $html .= '<label class="form-label small text-muted mb-1">Write a message</label>';
    $html .= '<textarea name="body" class="form-control" rows="3" maxlength="4000" placeholder="Type your message…" required></textarea>';
    $html .= '<button type="submit" class="btn btn-primary mt-2"><i class="fas fa-paper-plane me-1" aria-hidden="true"></i>Send</button>';
    $html .= '</form></div></div>';

    return $html;
}

/**
 * @param list<array<string,mixed>> $threads
 * @param array{thread: array<string,mixed>, messages: list<array<string,mixed>>}|null $activeDetail
 */
function buildSignatoryClearanceMessagesPanel(
    array $semester,
    array $threads,
    ?array $activeDetail,
    int $requestedThreadId,
    int $returnCollege,
    int $returnProgram,
    string $returnYearLevel,
    string $returnSearchName,
    bool $premiumSkin,
    int $signatoryUserId,
    string $returnSearchStatus = ''
): string {
    $semLabel = htmlspecialchars($semester['academic_year'] . ' ' . $semester['term']);
    $baseQ = signatoryQueueFilterQuery($returnCollege, $returnProgram, $returnYearLevel, $returnSearchName, $returnSearchStatus);
    $dashBase = app_path('/dashboard');
    if ($baseQ !== []) {
        $dashBase .= '?' . http_build_query($baseQ);
    }

    $wrapClass = 'card mb-3';
    $wrapExtra = '';
    if ($premiumSkin) {
        $wrapClass = 'mb-3';
        $wrapExtra = ' style="background:#fff;border-radius:28px;padding:22px 26px;border:1px solid #eef2f8;box-shadow:0 2px 6px rgba(0,0,0,.02);"';
    }

    $html = '<div class="' . $wrapClass . '"' . $wrapExtra . '><div class="d-flex justify-content-between align-items-start flex-wrap gap-2 mb-2">';
    $msgPageHref = app_path('/signatory/messages');
    if ($baseQ !== []) {
        $msgPageHref .= '?' . http_build_query($baseQ);
    }
    $html .= '<div><strong><i class="fas fa-comments me-2 text-primary" aria-hidden="true"></i>Student messages</strong>';
    $html .= '<div class="small text-muted">Semester ' . $semLabel . ' · students message you directly</div></div>';
    $html .= '<div class="d-flex gap-2">';
    $html .= '<a class="btn btn-sm btn-outline-secondary" href="' . htmlspecialchars($dashBase, ENT_QUOTES, 'UTF-8') . '">Inbox</a>';
    $html .= '<a class="btn btn-sm btn-outline-primary" href="' . htmlspecialchars($msgPageHref, ENT_QUOTES, 'UTF-8') . '" target="_blank" rel="noopener">Open Messages</a>';
    $html .= '</div>';
    $html .= '</div>';
    $html .= '<style>' . clearanceMessagingBubbleCss() . '</style>';

    $html .= '<div class="row g-3"><div class="col-lg-4"><div class="border rounded p-2" style="max-height:320px;overflow-y:auto;background:#fafafa;">';
    if ($threads === []) {
        $html .= '<p class="text-muted small mb-0">No conversations yet. When a student sends a message, it appears here.</p>';
    } else {
        foreach ($threads as $tr) {
            $tid = (int) ($tr['thread_id'] ?? 0);
            $unread = (int) ($tr['unread_count'] ?? 0);
            $q = array_merge($baseQ, ['msg_thread' => (string) $tid]);
            $href = app_path('/signatory/messages') . '?' . http_build_query($q);
            $stu = htmlspecialchars(trim((string) ($tr['last_name'] ?? '') . ', ' . (string) ($tr['first_name'] ?? '')));
            $sn = htmlspecialchars((string) ($tr['student_no'] ?? ''));
            $snip = trim((string) ($tr['last_snippet'] ?? ''));
            if (strlen($snip) > 80) {
                $snip = substr($snip, 0, 77) . '…';
            }
            $snipEsc = htmlspecialchars($snip, ENT_QUOTES, 'UTF-8');
            $active = $requestedThreadId === $tid && $activeDetail !== null;
            $rowClass = 'd-block text-decoration-none text-dark rounded p-2 mb-1 small ' . ($active ? 'bg-light border border-primary' : '');
            $html .= '<a class="' . $rowClass . '" href="' . htmlspecialchars($href, ENT_QUOTES, 'UTF-8') . '" style="border:1px solid ' . ($active ? '#0d6efd' : 'transparent') . ';">';
            $html .= '<div class="fw-semibold">' . $stu . ' <span class="text-muted font-monospace" style="font-size:.72rem;">' . $sn . '</span></div>';
            if ($unread > 0) {
                $html .= '<span class="badge bg-danger me-1">' . $unread . '</span>';
            }
            $html .= '<div class="text-muted text-truncate">' . $snipEsc . '</div></a>';
        }
    }
    $html .= '</div></div><div class="col-lg-8">';

    if ($requestedThreadId > 0 && $activeDetail === null) {
        $html .= '<div class="alert alert-warning py-2 small mb-0">That conversation was not found or is not available.</div>';
    } elseif ($activeDetail !== null) {
        $th = $activeDetail['thread'];
        $msgs = $activeDetail['messages'];
        $sid = (int) ($th['student_id'] ?? 0);
        $hdr = htmlspecialchars(trim((string) ($th['last_name'] ?? '') . ', ' . (string) ($th['first_name'] ?? '')));
        $html .= '<div class="mb-2 fw-semibold">' . $hdr . ' <span class="text-muted small">#' . htmlspecialchars((string) ($th['student_no'] ?? '')) . '</span></div>';
        $html .= '<div class="clearance-imsg"><div class="imsg-log mb-2">';
        if ($msgs === []) {
            $html .= '<p class="text-muted small mb-0">No messages in this thread.</p>';
        } else {
            foreach ($msgs as $m) {
                $sender = (int) ($m['sender_user_id'] ?? 0);
                $self = $sender === $signatoryUserId;
                $namePlain = trim((string) ($m['first_name'] ?? '') . ' ' . (string) ($m['last_name'] ?? ''));
                if ($self) {
                    $whoLinePlain = 'You';
                } elseif ($sender === $sid) {
                    $whoLinePlain = 'Student' . ($namePlain !== '' ? ' · ' . $namePlain : '');
                } else {
                    $whoLinePlain = 'Signatory' . ($namePlain !== '' ? ' · ' . $namePlain : '');
                }
                $ts = isset($m['created_at']) ? date('M j, g:i A', strtotime((string) $m['created_at'])) : '';
                $body = nl2br(htmlspecialchars((string) ($m['body'] ?? ''), ENT_QUOTES, 'UTF-8'));
                $rowClass = $self ? 'imsg-row imsg-self' : 'imsg-row imsg-in';
                $html .= '<div class="' . $rowClass . '"><div class="imsg-bubble">';
                $html .= '<div class="imsg-name">' . htmlspecialchars($whoLinePlain) . '</div>';
                $html .= '<div>' . $body . '</div>';
                $html .= '<div class="imsg-meta">' . htmlspecialchars($ts) . '</div></div></div>';
            }
        }
        $html .= '</div></div>';
        $html .= '<form method="POST" action="' . hpath('/signatory/clearance-message/send') . '" class="mt-2">';
        $html .= '<input type="hidden" name="thread_id" value="' . (int) ($th['thread_id'] ?? 0) . '">';
        $html .= '<input type="hidden" name="return_college" value="' . (int) $returnCollege . '">';
        $html .= '<input type="hidden" name="return_program" value="' . (int) $returnProgram . '">';
        $html .= '<input type="hidden" name="return_year_level" value="' . htmlspecialchars($returnYearLevel, ENT_QUOTES, 'UTF-8') . '">';
        $html .= '<input type="hidden" name="return_search_name" value="' . htmlspecialchars($returnSearchName, ENT_QUOTES, 'UTF-8') . '">';
        $html .= '<input type="hidden" name="return_search_status" value="' . htmlspecialchars(signatoryQueueStatusFilterValue($returnSearchStatus), ENT_QUOTES, 'UTF-8') . '">';
        $html .= '<textarea name="body" class="form-control" rows="2" maxlength="4000" placeholder="Reply…" required></textarea>';
        $html .= '<button type="submit" class="btn btn-primary btn-sm mt-2"><i class="fas fa-paper-plane me-1" aria-hidden="true"></i>Send reply</button>';
        $html .= '</form>';
    } else {
        $html .= '<p class="text-muted small mb-0">Select a student on the left to read messages and reply.</p>';
    }

    $html .= '</div></div></div>';

    return $html;
}

/** @return list<string> */
function sasChildOfficeCodes(): array
{
    return ['SSC', 'DORM', 'ACCT', 'SOA'];
}

/** @return list<string> */
function deanChildOfficeCodes(): array
{
    return ['LIB'];
}

/** @return list<string> */
function studentDashboardSasChildOfficeCodes(): array
{
    return sasChildOfficeCodes();
}

/** @return list<string> */
function studentDashboardDeanChildOfficeCodes(): array
{
    return deanChildOfficeCodes();
}

function studentDashboardGroupParentCodeForItem(array $item): string
{
    $code = officeRowCode($item, 'office_code');
    if (in_array($code, adminGroupParentCodes(), true)) {
        return $code;
    }

    $parentCode = officeParentCode($item, 'office_code');
    if ($parentCode !== '' && in_array($parentCode, adminGroupParentCodes(), true)) {
        return $parentCode;
    }

    foreach (adminOfficeGroupDefinitions() as $definition) {
        if (in_array($code, $definition['child_codes'], true)) {
            return $definition['parent_code'];
        }
    }

    return '';
}

/**
 * @param list<array<string,mixed>> $items
 * @return array<string, array{parent:?array<string,mixed>, children:list<array<string,mixed>>, subtitle:string}>
 */
function buildStudentDashboardGroupBuckets(array $items): array
{
    $buckets = [];
    foreach (adminGroupParentCodes() as $parentCode) {
        $buckets[$parentCode] = ['parent' => null, 'children' => [], 'subtitle' => ''];
    }
    foreach (adminOfficeGroupDefinitions() as $definition) {
        $buckets[$definition['parent_code']]['subtitle'] = $definition['subtitle'];
    }

    foreach ($items as $item) {
        $code = officeRowCode($item, 'office_code');
        if (in_array($code, adminGroupParentCodes(), true)) {
            $buckets[$code]['parent'] = $item;
            continue;
        }

        $groupCode = studentDashboardGroupParentCodeForItem($item);
        if ($groupCode !== '') {
            $buckets[$groupCode]['children'][] = $item;
        }
    }

    foreach ($buckets as &$bucket) {
        usort(
            $bucket['children'],
            static fn(array $a, array $b): int => ((int) ($a['sequence_no'] ?? 0)) <=> ((int) ($b['sequence_no'] ?? 0))
                ?: strcmp((string) ($a['office_name'] ?? ''), (string) ($b['office_name'] ?? ''))
        );
    }
    unset($bucket);

    return $buckets;
}

function studentDashboardGroupBorderClass(string $parentCode): string
{
    return match ($parentCode) {
        'SAS' => 'border-primary',
        'DEAN' => 'border-dark',
        default => 'border-secondary',
    };
}

/**
 * @return list<string>
 */
function adminGroupParentCodes(): array
{
    return ['SAS', 'DEAN'];
}

/** @return list<string> */
function finalClearanceSignatureOfficeCodes(): array
{
    return ['SAS', 'DEAN'];
}

/**
 * @return list<array{parent_code:string, child_codes:list<string>, subtitle:string}>
 */
function adminOfficeGroupDefinitions(): array
{
    return [
        [
            'parent_code' => 'SAS',
            'child_codes' => sasChildOfficeCodes(),
            'subtitle' => 'Supreme Student Council, Dormitory Coordinator, Accounting, Students Organization Association',
        ],
        [
            'parent_code' => 'DEAN',
            'child_codes' => deanChildOfficeCodes(),
            'subtitle' => 'University/Campus Library',
        ],
    ];
}

function officeParentCode(array $office, string $codeField = 'code'): string
{
    return strtoupper(trim((string) ($office['parent_code'] ?? $office['parent_office_code'] ?? '')));
}

/**
 * @param list<array<string,mixed>> $children
 */
function buildAdminOfficeGroupSubtitle(array $children): string
{
    if ($children === []) {
        return '';
    }

    return implode(', ', array_map(
        static fn(array $office): string => (string) ($office['name'] ?? ''),
        $children
    ));
}

/**
 * @param list<array<string,mixed>> $offices
 * @return array<int, string>
 */
function officeIdToGroupParentCodeMap(array $offices, string $codeField = 'code'): array
{
    $parentsById = [];
    foreach ($offices as $office) {
        $code = officeRowCode($office, $codeField);
        if (in_array($code, adminGroupParentCodes(), true)) {
            $parentsById[(int) ($office['id'] ?? 0)] = $code;
        }
    }

    $map = [];
    foreach ($offices as $office) {
        $officeId = (int) ($office['id'] ?? 0);
        if ($officeId <= 0) {
            continue;
        }
        $code = officeRowCode($office, $codeField);
        if (in_array($code, adminGroupParentCodes(), true)) {
            $map[$officeId] = $code;
            continue;
        }

        $parentId = (int) ($office['parent_office_id'] ?? 0);
        if ($parentId > 0 && isset($parentsById[$parentId])) {
            $map[$officeId] = $parentsById[$parentId];
            continue;
        }

        foreach (adminOfficeGroupDefinitions() as $definition) {
            if (in_array($code, $definition['child_codes'], true)) {
                $map[$officeId] = $definition['parent_code'];
                break;
            }
        }
    }

    return $map;
}

function officeRowCode(array $office, string $codeField = 'code'): string
{
    if ($codeField === 'office_code') {
        return strtoupper(trim((string) ($office['office_code'] ?? $office['code'] ?? '')));
    }

    return strtoupper(trim((string) ($office['code'] ?? $office['office_code'] ?? '')));
}

/**
 * @param list<array<string,mixed>> $offices
 * @return array{other:list<array<string,mixed>>, groups:list<array{parent:?array<string,mixed>, children:list<array<string,mixed>>, subtitle:string}>}
 */
function partitionOfficesForAdminGroups(array $offices, string $codeField = 'code'): array
{
    $parents = [];
    $childrenByParentCode = [];
    foreach (adminGroupParentCodes() as $parentCode) {
        $childrenByParentCode[$parentCode] = [];
    }

    foreach ($offices as $office) {
        $code = officeRowCode($office, $codeField);
        if (in_array($code, adminGroupParentCodes(), true)) {
            $parents[$code] = $office;
        }
    }

    $otherOffices = [];
    foreach ($offices as $office) {
        $code = officeRowCode($office, $codeField);
        if (in_array($code, adminGroupParentCodes(), true)) {
            continue;
        }

        $parentCode = officeParentCode($office, $codeField);
        if ($parentCode === '' && isset($office['parent_office_id'])) {
            $parentId = (int) $office['parent_office_id'];
            foreach ($parents as $groupCode => $parentOffice) {
                if ((int) ($parentOffice['id'] ?? 0) === $parentId) {
                    $parentCode = $groupCode;
                    break;
                }
            }
        }
        if ($parentCode === '') {
            foreach (adminOfficeGroupDefinitions() as $definition) {
                if (in_array($code, $definition['child_codes'], true)) {
                    $parentCode = $definition['parent_code'];
                    break;
                }
            }
        }

        if ($parentCode !== '' && isset($childrenByParentCode[$parentCode])) {
            $childrenByParentCode[$parentCode][] = $office;
            continue;
        }

        $otherOffices[] = $office;
    }

    $groups = [];
    foreach (adminGroupParentCodes() as $parentCode) {
        $parent = $parents[$parentCode] ?? null;
        $children = $childrenByParentCode[$parentCode] ?? [];
        usort(
            $children,
            static fn(array $a, array $b): int => ((int) ($a['sequence_no'] ?? 0)) <=> ((int) ($b['sequence_no'] ?? 0))
                ?: strcmp((string) ($a['name'] ?? ''), (string) ($b['name'] ?? ''))
        );
        if ($parent !== null || $children !== []) {
            $groups[] = [
                'parent' => $parent,
                'children' => $children,
                'subtitle' => buildAdminOfficeGroupSubtitle($children),
            ];
        }
    }

    return [
        'other' => $otherOffices,
        'groups' => $groups,
    ];
}

/**
 * @param list<array<string,mixed>> $items
 * @return list<array<string,mixed>>
 */
function buildStudentDashboardDisplayItems(array $items): array
{
    $buckets = buildStudentDashboardGroupBuckets($items);
    $displayItems = [];
    $renderedGroups = [];

    foreach ($items as $item) {
        $groupCode = studentDashboardGroupParentCodeForItem($item);
        if ($groupCode !== '') {
            if (!isset($renderedGroups[$groupCode])) {
                $bucket = $buckets[$groupCode] ?? ['parent' => null, 'children' => [], 'subtitle' => ''];
                if (($bucket['parent'] ?? null) !== null || ($bucket['children'] ?? []) !== []) {
                    $displayItems[] = [
                        'type' => 'office_group',
                        'parent_code' => $groupCode,
                        'parent' => $bucket['parent'] ?? null,
                        'children' => $bucket['children'] ?? [],
                        'subtitle' => (string) ($bucket['subtitle'] ?? ''),
                    ];
                }
                $renderedGroups[$groupCode] = true;
            }
            continue;
        }

        $displayItems[] = ['type' => 'office', 'office' => $item];
    }

    return $displayItems;
}

/**
 * @param list<array<string,mixed>> $offices
 */
function renderAdminOfficeSelectOptions(array $offices, string $codeField = 'code'): string
{
    $partition = partitionOfficesForAdminGroups($offices, $codeField);
    $html = '';

    foreach ($partition['other'] as $office) {
        $html .= '<option value="' . (int) $office['id'] . '">' . htmlspecialchars((string) $office['name']) . '</option>';
    }

    foreach ($partition['groups'] as $group) {
        $groupLabel = $group['parent'] !== null
            ? (string) $group['parent']['name']
            : 'Office group';
        $html .= '<optgroup label="' . htmlspecialchars($groupLabel) . '">';
        if ($group['parent'] !== null) {
            $html .= '<option value="' . (int) $group['parent']['id'] . '">' . htmlspecialchars((string) $group['parent']['name']) . '</option>';
        }
        foreach ($group['children'] as $child) {
            $html .= '<option value="' . (int) $child['id'] . '">' . htmlspecialchars((string) $child['name']) . '</option>';
        }
        $html .= '</optgroup>';
    }

    return $html;
}

/**
 * @param list<array<string,mixed>> $assignments
 * @param list<array<string,mixed>> $offices
 * @return array{other:list<array<string,mixed>>, groups:list<array{parent:?array<string,mixed>, children:list<array<string,mixed>>, subtitle:string}>}
 */
function partitionAssignmentsForAdminGroups(array $assignments, array $offices): array
{
    $groupMap = officeIdToGroupParentCodeMap($offices);
    $officePartition = partitionOfficesForAdminGroups($offices);
    $parentLabels = [];
    $parentOfficeIdByCode = [];
    foreach ($officePartition['groups'] as $group) {
        $parent = $group['parent'] ?? null;
        if ($parent === null) {
            continue;
        }
        $parentCode = officeRowCode($parent);
        $parentLabels[$parentCode] = (string) ($parent['name'] ?? '');
        $parentOfficeIdByCode[$parentCode] = (int) ($parent['id'] ?? 0);
    }

    $otherAssignments = [];
    $parentAssignmentsByCode = [];
    $childAssignmentsByCode = [];
    foreach (adminGroupParentCodes() as $parentCode) {
        $parentAssignmentsByCode[$parentCode] = [];
        $childAssignmentsByCode[$parentCode] = [];
    }

    foreach ($assignments as $assignment) {
        $officeId = (int) ($assignment['office_id'] ?? 0);
        $groupCode = $groupMap[$officeId] ?? '';
        if ($groupCode === '' || !isset($childAssignmentsByCode[$groupCode])) {
            $otherAssignments[] = $assignment;
            continue;
        }

        if (($parentOfficeIdByCode[$groupCode] ?? 0) === $officeId) {
            $parentAssignmentsByCode[$groupCode][] = $assignment;
        } else {
            $childAssignmentsByCode[$groupCode][] = $assignment;
        }
    }

    $groups = [];
    foreach (adminGroupParentCodes() as $parentCode) {
        $parentAssignments = $parentAssignmentsByCode[$parentCode] ?? [];
        $childAssignments = $childAssignmentsByCode[$parentCode] ?? [];
        if ($parentAssignments === [] && $childAssignments === []) {
            continue;
        }

        $subtitle = '';
        foreach ($officePartition['groups'] as $group) {
            $groupParent = $group['parent'] ?? null;
            if ($groupParent !== null && officeRowCode($groupParent) === $parentCode) {
                $subtitle = (string) ($group['subtitle'] ?? '');
                break;
            }
        }

        $groups[] = [
            'parent_assignments' => $parentAssignments,
            'child_assignments' => $childAssignments,
            'subtitle' => $subtitle,
            'label' => $parentAssignments !== []
                ? (string) ($parentAssignments[0]['office_name'] ?? '')
                : ($parentLabels[$parentCode] ?? $parentCode),
        ];
    }

    return [
        'other' => $otherAssignments,
        'groups' => $groups,
    ];
}

function renderAdminAssignmentGroupSection(array $group): string
{
    $html = '<tr class="table-light"><td colspan="3"><strong>' . htmlspecialchars((string) $group['label']) . '</strong>';
    if (!empty($group['subtitle'])) {
        $html .= '<div class="small text-muted fw-normal">' . htmlspecialchars((string) $group['subtitle']) . '</div>';
    }
    $html .= '</td></tr>';
    foreach ($group['parent_assignments'] as $assignment) {
        $html .= renderAdminSignatoryAssignmentRow($assignment);
    }
    foreach ($group['child_assignments'] as $assignment) {
        $html .= renderAdminSignatoryAssignmentRow($assignment, true);
    }

    return $html;
}

function renderAdminSignatoryAssignmentRow(array $assignment, bool $indentChild = false): string
{
    $name = htmlspecialchars((string) ($assignment['last_name'] . ', ' . $assignment['first_name']));
    $officeLabel = htmlspecialchars((string) $assignment['office_name']);
    if ($indentChild) {
        $officeLabel = '<span class="text-muted me-1">↳</span>' . $officeLabel;
    }

    $html = '<tr><td>' . $officeLabel . '</td>';
    $html .= '<td>' . $name . '<br><span class="text-muted small">' . htmlspecialchars((string) $assignment['email']) . '</span></td>';
    $html .= '<td><form method="POST" action="' . hpath('/admin/signatory/remove-assignment') . '" class="d-inline" onsubmit="return confirm(\'Remove this office assignment?\');">';
    $html .= '<input type="hidden" name="assignment_id" value="' . (int) $assignment['id'] . '">';
    $html .= '<button class="btn btn-sm btn-outline-danger" type="submit">Remove</button></form></td></tr>';

    return $html;
}

/**
 * @param list<array<string,mixed>> $requirements
 * @param list<array<string,mixed>> $overview
 * @return list<array<string,mixed>>
 */
function mergeStudentDashboardRequirementsWithOverview(array $requirements, array $overview): array
{
    $requirementsByOfficeId = [];
    foreach ($requirements as $group) {
        $requirementsByOfficeId[(int) ($group['office_id'] ?? 0)] = $group;
    }

    $merged = [];
    foreach ($overview as $office) {
        $officeId = (int) ($office['office_id'] ?? 0);
        $parentFields = [
            'parent_office_id' => $office['parent_office_id'] ?? null,
            'parent_office_code' => $office['parent_office_code'] ?? '',
        ];
        if (isset($requirementsByOfficeId[$officeId])) {
            $merged[] = array_merge($requirementsByOfficeId[$officeId], $parentFields);
            continue;
        }
        $merged[] = array_merge([
            'office_id' => $officeId,
            'office_code' => $office['office_code'] ?? '',
            'office_name' => $office['office_name'] ?? '',
            'sequence_no' => (int) ($office['sequence_no'] ?? 0),
            'requirements' => [],
        ], $parentFields);
    }

    return $merged;
}

function studentDashboardStatusColorClass(array $office): string
{
    return match ($office['color'] ?? '') {
        'green' => 'success',
        'yellow' => 'warning',
        default => 'danger',
    };
}

function renderStudentOfficeOverviewCard(array $office, bool $compact = false): string
{
    $colorClass = studentDashboardStatusColorClass($office);
    $colClass = $compact ? 'col-12 col-sm-6' : 'col-12 col-sm-6 col-md-3';
    $html = '<div class="' . $colClass . '"><div class="card border-' . $colorClass . ' h-100"><div class="card-body py-3">';
    $html .= '<h6 class="' . ($compact ? 'small mb-1' : '') . '">' . htmlspecialchars((string) $office['office_name']) . '</h6>';
    $html .= '<span class="badge bg-' . $colorClass . '">' . htmlspecialchars(strtoupper((string) ($office['status'] ?? 'pending'))) . '</span>';
    $decisionReason = trim((string) ($office['rejection_reason'] ?? ''));
    if ($decisionReason !== '') {
        $html .= '<p class="small text-muted mt-2 mb-0"><strong>Reason:</strong> ' . htmlspecialchars($decisionReason) . '</p>';
    }
    $html .= '</div></div></div>';
    return $html;
}

function renderStudentOfficeGroupOverviewCard(
    string $parentCode,
    ?array $parentOffice,
    array $children,
    string $subtitle = ''
): string {
    $parentName = (string) ($parentOffice['office_name'] ?? $parentCode);
    $borderClass = studentDashboardGroupBorderClass($parentCode);
    $html = '<div class="col-12 col-lg-6"><div class="card ' . $borderClass . ' h-100"><div class="card-body py-3">';
    $html .= '<h6 class="mb-2">' . htmlspecialchars($parentName) . '</h6>';
    if ($parentOffice !== null) {
        $colorClass = studentDashboardStatusColorClass($parentOffice);
        $html .= '<div class="d-flex justify-content-between align-items-center mb-2 pb-2 border-bottom">';
        $html .= '<span class="small text-muted">' . htmlspecialchars($parentName) . ' clearance</span>';
        $html .= '<span class="badge bg-' . $colorClass . '">' . htmlspecialchars(strtoupper((string) ($parentOffice['status'] ?? 'pending'))) . '</span>';
        $html .= '</div>';
        $decisionReason = trim((string) ($parentOffice['rejection_reason'] ?? ''));
        if ($decisionReason !== '') {
            $html .= '<p class="small text-muted mb-2"><strong>Reason:</strong> ' . htmlspecialchars($decisionReason) . '</p>';
        }
    }
    if ($children !== []) {
        if ($subtitle !== '') {
            $html .= '<div class="small text-muted mb-2">' . htmlspecialchars($subtitle) . '</div>';
        }
        $html .= '<div class="row g-2">';
        foreach ($children as $child) {
            $html .= renderStudentOfficeOverviewCard($child, true);
        }
        $html .= '</div>';
    }
    $html .= '</div></div></div>';
    return $html;
}

function renderStudentRequirementRow(array $req, int $officeId, array $overviewStatusByOfficeId): string
{
    if (!empty($req['is_individual'])) {
        return renderStudentIndividualRequirementRow($req, $officeId, $overviewStatusByOfficeId);
    }

    $officeStatus = $overviewStatusByOfficeId[$officeId] ?? 'pending';
    $requirementStatus = strtolower((string) ($req['review_status'] ?? 'pending'));
    if ($officeStatus === 'cleared') {
        $requirementStatus = 'cleared';
    } elseif ($officeStatus === 'rejected') {
        $requirementStatus = 'rejected';
    } elseif ($officeStatus === 'for_review' && $requirementStatus === 'pending') {
        $requirementStatus = 'for_review';
    }
    $html = '<div class="border rounded p-3 mb-2"><div class="d-flex justify-content-between align-items-start flex-wrap gap-2 student-req-row">';
    $html .= '<strong>' . htmlspecialchars((string) $req['title']) . '</strong>';
    $badgeClass = 'bg-info text-dark';
    if ($requirementStatus === 'cleared') {
        $badgeClass = 'bg-success';
    } elseif ($requirementStatus === 'rejected') {
        $badgeClass = 'bg-danger';
    } elseif ($requirementStatus === 'for_review') {
        $badgeClass = 'bg-warning text-dark';
    }
    $html .= '<span class="badge ' . $badgeClass . '">' . htmlspecialchars(strtoupper($requirementStatus)) . '</span></div>';
    $html .= '<p class="mb-2 text-muted">' . htmlspecialchars((string) $req['description']) . '</p>';
    if (!empty($req['requirement_attachment_path'])) {
        $downloadName = htmlspecialchars((string) ($req['requirement_attachment_name'] ?? 'Download requirement attachment'));
        $html .= '<p class="mb-2"><a href="' . hpath('/' . ltrim((string) $req['requirement_attachment_path'], '/')) . '" target="_blank" rel="noopener">' . $downloadName . '</a></p>';
    }
    $html .= '<form method="POST" action="' . hpath('/student/upload') . '" enctype="multipart/form-data" class="row g-2">';
    $html .= '<input type="hidden" name="requirement_id" value="' . (int) $req['requirement_id'] . '">';
    $html .= '<div class="col-12 col-md-8"><input class="form-control form-control-sm" type="file" name="proof" required></div>';
    $html .= '<div class="col-12 col-md-4"><button class="btn btn-sm btn-outline-success w-100">Upload</button></div>';
    $html .= '</form>';
    if (!empty($req['original_filename'])) {
        $html .= '<small class="text-muted">Latest file: ' . htmlspecialchars((string) $req['original_filename']) . '</small>';
    }
    $html .= '</div>';
    return $html;
}

function renderStudentIndividualRequirementRow(array $req, int $officeId, array $overviewStatusByOfficeId): string
{
    $officeStatus = $overviewStatusByOfficeId[$officeId] ?? 'pending';
    $requirementStatus = strtolower((string) ($req['review_status'] ?? 'pending'));
    if ($officeStatus === 'cleared') {
        $requirementStatus = 'cleared';
    } elseif ($officeStatus === 'rejected') {
        $requirementStatus = 'rejected';
    } elseif ($requirementStatus === 'approved') {
        $requirementStatus = 'cleared';
    }
    $html = '<div class="border rounded p-3 mb-2 border-info-subtle bg-light">';
    $html .= '<div class="d-flex justify-content-between align-items-start gap-2">';
    $html .= '<div><strong>' . htmlspecialchars((string) $req['title']) . '</strong>';
    $html .= '<div class="small text-muted mt-1">Assigned specifically to you by this office.</div></div>';
    $badgeClass = $requirementStatus === 'cleared' ? 'bg-success' : 'bg-secondary';
    $badgeLabel = $requirementStatus === 'cleared' ? 'COMPLETE' : 'PENDING';
    $html .= '<span class="badge ' . $badgeClass . '">' . htmlspecialchars($badgeLabel) . '</span></div>';
    if (!empty($req['requirement_attachment_path'])) {
        $downloadName = htmlspecialchars((string) ($req['requirement_attachment_name'] ?? 'Download attachment'));
        $html .= '<p class="mb-2 mt-2"><a href="' . hpath('/' . ltrim((string) $req['requirement_attachment_path'], '/')) . '" target="_blank" rel="noopener"><i class="fas fa-paperclip me-1"></i>' . $downloadName . '</a></p>';
    }
    if ($requirementStatus === 'cleared' && !empty($req['uploaded_at'])) {
        $html .= '<small class="text-muted d-block mt-2">Completed: ' . htmlspecialchars((string) $req['uploaded_at']) . '</small>';
    }
    $html .= '</div>';
    return $html;
}

function renderStudentOfficeRequirementsBody(array $officeGroup, array $overviewStatusByOfficeId): string
{
    $officeId = (int) ($officeGroup['office_id'] ?? 0);
    $requirements = $officeGroup['requirements'] ?? [];
    if ($requirements === []) {
        return '<p class="text-muted small mb-0">No requirements listed for this office.</p>';
    }

    $html = '';
    foreach ($requirements as $req) {
        $html .= renderStudentRequirementRow($req, $officeId, $overviewStatusByOfficeId);
    }
    return $html;
}

function renderStudentOfficeRequirementsCard(array $officeGroup, array $overviewStatusByOfficeId): string
{
    $html = '<div class="card mb-3"><div class="card-header">';
    $html .= '<strong>' . htmlspecialchars((string) $officeGroup['office_name']) . '</strong>';
    $html .= '</div><div class="card-body">';
    $html .= renderStudentOfficeRequirementsBody($officeGroup, $overviewStatusByOfficeId);
    $html .= '</div></div>';
    return $html;
}

function renderStudentOfficeGroupRequirementsCard(
    string $parentCode,
    ?array $parentGroup,
    array $childGroups,
    string $subtitle,
    array $overviewStatusByOfficeId
): string {
    $parentName = (string) ($parentGroup['office_name'] ?? $parentCode);
    $borderClass = studentDashboardGroupBorderClass($parentCode);
    $html = '<div class="card mb-3 ' . $borderClass . '"><div class="card-header bg-white">';
    $html .= '<strong>' . htmlspecialchars($parentName) . '</strong>';
    if ($subtitle !== '') {
        $html .= '<div class="small text-muted">' . htmlspecialchars($subtitle) . '</div>';
    } elseif ($childGroups !== []) {
        $childNames = array_map(
            static fn(array $officeGroup): string => (string) ($officeGroup['office_name'] ?? ''),
            $childGroups
        );
        $html .= '<div class="small text-muted">' . htmlspecialchars(implode(', ', array_filter($childNames))) . '</div>';
    }
    $html .= '</div><div class="card-body">';
    foreach ($childGroups as $officeGroup) {
        $html .= '<div class="border rounded p-3 mb-3 bg-light">';
        $html .= '<div class="fw-semibold mb-2">' . htmlspecialchars((string) $officeGroup['office_name']) . '</div>';
        $html .= renderStudentOfficeRequirementsBody($officeGroup, $overviewStatusByOfficeId);
        $html .= '</div>';
    }
    if ($parentGroup !== null) {
        $html .= '<div class="border rounded p-3 mb-0">';
        $html .= '<div class="fw-semibold mb-2">' . htmlspecialchars((string) $parentGroup['office_name']) . ' clearance</div>';
        $html .= renderStudentOfficeRequirementsBody($parentGroup, $overviewStatusByOfficeId);
        $html .= '</div>';
    }
    $html .= '</div></div>';
    return $html;
}

function renderStudentAccountSummaryCard(array $user): string
{
    $studentNo = trim((string) ($user['student_no'] ?? ''));
    $fields = [
        ['label' => 'Student No.', 'value' => $studentNo !== '' ? htmlspecialchars($studentNo) : '—'],
        ['label' => 'Campus', 'value' => formatStudentCampusCell($user['campus'] ?? null)],
        ['label' => 'Student account', 'value' => htmlspecialchars(formatStudentAccountTypeCell($user['student_account_type'] ?? null))],
        ['label' => 'Org. position', 'value' => htmlspecialchars(formatStudentOrgPositionCell($user['student_org_position'] ?? null))],
        ['label' => 'Students staying', 'value' => htmlspecialchars(formatStudentStayingCell($user['student_staying'] ?? null))],
    ];
    $html = '<div class="card mb-3 student-account-summary"><div class="card-header py-2">';
    $html .= '<strong><i class="fas fa-id-card me-2 text-secondary" aria-hidden="true"></i>My Account</strong>';
    $html .= '</div><div class="card-body py-3"><div class="row g-3">';
    foreach ($fields as $field) {
        $html .= '<div class="col-6 col-md-3 account-field">';
        $html .= '<div class="account-field-label">' . htmlspecialchars($field['label']) . '</div>';
        $html .= '<div class="account-field-value">' . $field['value'] . '</div>';
        $html .= '</div>';
    }
    $html .= '</div></div></div>';

    return $html;
}

function renderStudentDashboard(
    array $user,
    array $semester,
    array $overview,
    array $requirements,
    int $clearanceUnreadCount = 0,
    array $deadlineStatus = []
): string
{
    $html = '<h4 class="section-title">Student Dashboard</h4><p class="muted-caption">Semester: ' . htmlspecialchars($semester['academic_year'] . ' ' . $semester['term']) . '</p>';
    $html .= renderStudentAccountSummaryCard($user);
    $html .= renderStudentDeadlineCountdownDisplay($deadlineStatus);
    $overviewStatusByOfficeId = [];
    $fullyCleared = true;
    foreach ($overview as $office) {
        $overviewStatusByOfficeId[(int) ($office['office_id'] ?? 0)] = strtolower((string) ($office['status'] ?? 'pending'));
        if (($office['status'] ?? 'pending') !== 'cleared') {
            $fullyCleared = false;
            break;
        }
    }
    $html .= '<div class="mb-3 d-flex flex-wrap gap-2 student-action-bar">';
    if ($fullyCleared) {
        $html .= '<a class="btn btn-success" href="' . hpath('/student/final-clearance') . '" target="_blank" rel="noopener">View Final Clearance PDF</a>';
        $html .= '<a class="btn btn-outline-success" href="' . hpath('/student/final-clearance') . '?download=1">Download PDF</a>';
    } else {
        $html .= '<button class="btn btn-secondary" type="button" disabled>View Final Clearance PDF (Locked)</button>';
    }
    $html .= '</div>';
    $html .= '<div class="row g-3 mb-4">';
    foreach (buildStudentDashboardDisplayItems($overview) as $displayItem) {
        if (($displayItem['type'] ?? '') === 'office_group') {
            $html .= renderStudentOfficeGroupOverviewCard(
                (string) ($displayItem['parent_code'] ?? ''),
                $displayItem['parent'] ?? null,
                $displayItem['children'] ?? [],
                (string) ($displayItem['subtitle'] ?? '')
            );
            continue;
        }
        $html .= renderStudentOfficeOverviewCard($displayItem['office'] ?? []);
    }
    $html .= '</div>';
    $html .= '<div class="card mb-4"><div class="card-body d-flex flex-wrap justify-content-between align-items-center gap-2">';
    $html .= '<div><strong><i class="fas fa-comments me-2 text-primary" aria-hidden="true"></i>Messages to signatories</strong>';
    $html .= '<div class="small text-muted">Open your private message window with assigned signatories.</div></div>';
    $html .= '<a class="btn btn-outline-primary" href="' . hpath('/student/messages') . '">Open Messages';
    if ($clearanceUnreadCount > 0) {
        $html .= ' <span class="badge bg-primary rounded-pill ms-1">' . (int) $clearanceUnreadCount . '</span>';
    }
    $html .= '</a></div></div>';
    $requirementGroups = mergeStudentDashboardRequirementsWithOverview($requirements, $overview);
    foreach (buildStudentDashboardDisplayItems($requirementGroups) as $displayItem) {
        if (($displayItem['type'] ?? '') === 'office_group') {
            $html .= renderStudentOfficeGroupRequirementsCard(
                (string) ($displayItem['parent_code'] ?? ''),
                $displayItem['parent'] ?? null,
                $displayItem['children'] ?? [],
                (string) ($displayItem['subtitle'] ?? ''),
                $overviewStatusByOfficeId
            );
            continue;
        }
        $html .= renderStudentOfficeRequirementsCard($displayItem['office'] ?? [], $overviewStatusByOfficeId);
    }
    $html .= renderStudentDeadlinePinnedWidget($deadlineStatus);

    return $html;
}

function renderStudentMessagesPage(
    array $user,
    array $semester,
    array $clearanceMessages,
    int $clearanceUnreadCount,
    array $signatoryMsgChoices,
    int $selectedMsgSignatoryId
): string {
    $html = '<div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">';
    $html .= '<div><h4 class="section-title mb-0">Messages to Signatories</h4>';
    $html .= '<p class="muted-caption mb-0">Semester: ' . htmlspecialchars($semester['academic_year'] . ' ' . $semester['term']) . '</p></div>';
    $html .= '<a class="btn btn-sm btn-outline-secondary" href="' . hpath('/dashboard') . '"><i class="fas fa-arrow-left me-1" aria-hidden="true"></i>Back to Dashboard</a>';
    $html .= '</div>';
    $html .= buildStudentClearanceMessagesPanel(
        $user,
        $semester,
        $clearanceMessages,
        $clearanceUnreadCount,
        $signatoryMsgChoices,
        $selectedMsgSignatoryId,
        '/student/messages'
    );

    return $html;
}

function renderSignatoryMessagesPage(
    array $semester,
    ?array $office,
    array $threads,
    ?array $activeDetail,
    int $requestedThreadId,
    int $returnCollege,
    int $returnProgram,
    string $returnYearLevel,
    string $returnSearchName,
    string $returnSearchStatus,
    bool $premiumSkin,
    int $signatoryUserId
): string {
    $html = '<div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">';
    $html .= '<div><h4 class="section-title mb-0">Student Messages</h4>';
    $html .= '<p class="muted-caption mb-0">Semester: ' . htmlspecialchars($semester['academic_year'] . ' ' . $semester['term']) . '</p></div>';
    $dashHref = app_path('/dashboard') . signatoryQueueFilterQueryString($returnCollege, $returnProgram, $returnYearLevel, $returnSearchName, $returnSearchStatus);
    $html .= '<a class="btn btn-sm btn-outline-secondary" href="' . htmlspecialchars($dashHref, ENT_QUOTES, 'UTF-8') . '"><i class="fas fa-arrow-left me-1" aria-hidden="true"></i>Back to Dashboard</a>';
    $html .= '</div>';
    if ($office === null) {
        $html .= '<div class="alert alert-warning">You are not assigned to any office for this semester.</div>';
        return $html;
    }

    $html .= buildSignatoryClearanceMessagesPanel(
        $semester,
        $threads,
        $activeDetail,
        $requestedThreadId,
        $returnCollege,
        $returnProgram,
        $returnYearLevel,
        $returnSearchName,
        $premiumSkin,
        $signatoryUserId,
        $returnSearchStatus
    );
    return $html;
}

function renderSignatoryMessagesLaunchCard(
    int $returnCollege = 0,
    int $returnProgram = 0,
    string $returnYearLevel = '',
    string $returnSearchName = '',
    int $unreadCount = 0,
    string $returnSearchStatus = ''
): string {
    $q = signatoryQueueFilterQuery($returnCollege, $returnProgram, $returnYearLevel, $returnSearchName, $returnSearchStatus);
    $href = app_path('/signatory/messages');
    if ($q !== []) {
        $href .= '?' . http_build_query($q);
    }

    $html = '<div class="card mb-3"><div class="card-body d-flex flex-wrap justify-content-between align-items-center gap-2">';
    $html .= '<div><strong><i class="fas fa-comments me-2 text-primary" aria-hidden="true"></i>Messages to students</strong>';
    $html .= '<div class="small text-muted">Open your private message window with assigned students.</div></div>';
    $html .= '<a class="btn btn-outline-primary" href="' . htmlspecialchars($href, ENT_QUOTES, 'UTF-8') . '" target="_blank" rel="noopener">Open Messages';
    if ($unreadCount > 0) {
        $html .= ' <span class="badge bg-danger rounded-pill ms-1">' . (int) $unreadCount . '</span>';
    }
    $html .= '</a>';
    $html .= '</div></div>';
    return $html;
}

/**
 * Per-student requirements controls for signatory queue rows.
 *
 * @param list<array{id:int, requirement_text:string, attachment_path:?string, attachment_name:?string, is_completed:bool, completed_at:?string}> $attachedRequirements
 */
function renderSignatoryStudentAttachedRequirements(
    int $studentId,
    int $officeId,
    array $attachedRequirements,
    int $returnCollege,
    int $returnProgram,
    string $returnYearLevel,
    bool $premium = false,
    string $returnSearchName = '',
    string $returnSearchStatus = ''
): string {
    $html = $premium
        ? '<div class="attached-req-block">'
        : '<div class="mt-2 pt-2 border-top">';
    $html .= $premium
        ? '<div class="attached-req-title"><i class="fas fa-user-tag"></i> Individual requirements</div>'
        : '<div class="small fw-semibold text-muted mb-1">Individual requirements</div>';

    if ($attachedRequirements !== []) {
        $html .= $premium ? '<ul class="attached-req-list">' : '<ul class="small mb-2 ps-3">';
        foreach ($attachedRequirements as $item) {
            $reqId = (int) ($item['id'] ?? 0);
            $text = htmlspecialchars((string) ($item['requirement_text'] ?? ''));
            $attachmentPath = trim((string) ($item['attachment_path'] ?? ''));
            $attachmentName = trim((string) ($item['attachment_name'] ?? ''));
            $isCompleted = (bool) ($item['is_completed'] ?? false);
            $html .= $premium ? '<li class="attached-req-item">' : '<li class="mb-1">';
            if ($isCompleted) {
                $html .= $premium
                    ? '<span class="attached-req-done"><i class="fas fa-check-circle"></i> ' . $text . '</span>'
                    : '<span class="text-success">' . $text . ' (done)</span>';
            } else {
                $html .= $premium
                    ? '<span class="attached-req-pending"><i class="fas fa-circle"></i> ' . $text . '</span>'
                    : '<span class="text-danger">' . $text . ' (pending)</span>';
            }
            if ($attachmentPath !== '') {
                $attachLabel = $attachmentName !== '' ? htmlspecialchars($attachmentName) : 'Download attachment';
                $attachHtml = '<a href="' . hpath('/' . ltrim($attachmentPath, '/')) . '" target="_blank" rel="noopener">' . $attachLabel . '</a>';
                $html .= $premium
                    ? '<div class="attached-req-attach"><i class="fas fa-paperclip"></i> ' . $attachHtml . '</div>'
                    : '<div class="small mt-1"><i class="fas fa-paperclip"></i> ' . $attachHtml . '</div>';
            }
            $html .= $premium ? '<div class="attached-req-actions">' : '<span class="ms-1">';
            $html .= '<form method="POST" action="' . hpath('/signatory/student-requirement/toggle') . '" class="d-inline">';
            $html .= '<input type="hidden" name="requirement_id" value="' . $reqId . '">';
            $html .= '<input type="hidden" name="completed" value="' . ($isCompleted ? '0' : '1') . '">';
            $html .= signatoryQueueReturnFilterHiddenFields($returnCollege, $returnProgram, $returnYearLevel, $returnSearchName, $returnSearchStatus);
            $html .= $premium
                ? '<button class="btn-outline" type="submit">' . ($isCompleted ? 'Undo' : 'Mark Done') . '</button>'
                : '<button class="btn btn-sm btn-outline-' . ($isCompleted ? 'secondary' : 'success') . '" type="submit">' . ($isCompleted ? 'Undo' : 'Done') . '</button>';
            $html .= '</form>';
            $html .= '<form method="POST" action="' . hpath('/signatory/student-requirement/delete') . '" class="d-inline" onsubmit="return confirm(\'Remove this requirement?\');">';
            $html .= '<input type="hidden" name="requirement_id" value="' . $reqId . '">';
            $html .= signatoryQueueReturnFilterHiddenFields($returnCollege, $returnProgram, $returnYearLevel, $returnSearchName, $returnSearchStatus);
            $html .= $premium
                ? '<button class="btn-outline" type="submit">Delete</button>'
                : '<button class="btn btn-sm btn-outline-danger" type="submit">Delete</button>';
            $html .= '</form>';
            $html .= $premium ? '</div>' : '</span>';
            $html .= '</li>';
        }
        $html .= '</ul>';
    } else {
        $html .= $premium
            ? '<div class="attached-req-empty">No individual requirements yet.</div>'
            : '<p class="small text-muted mb-2">No individual requirements yet.</p>';
    }

    $html .= $premium
        ? '<form method="POST" action="' . hpath('/signatory/student-requirement/add') . '" class="attached-req-add-form" enctype="multipart/form-data">'
        : '<form method="POST" action="' . hpath('/signatory/student-requirement/add') . '" class="mt-1" enctype="multipart/form-data">';
    $html .= '<input type="hidden" name="student_id" value="' . $studentId . '">';
    $html .= signatoryQueueReturnFilterHiddenFields($returnCollege, $returnProgram, $returnYearLevel, $returnSearchName, $returnSearchStatus);
    if ($premium) {
        $html .= '<textarea name="requirements_text" rows="2" placeholder="Add requirement(s), one per line"></textarea>';
        $html .= '<div class="attached-req-upload"><label><i class="fas fa-paperclip"></i> Attachment</label><input type="file" name="attachment"></div>';
        $html .= '<button class="btn-primary" type="submit"><i class="fas fa-plus"></i> Add</button>';
    } else {
        $html .= '<div class="d-flex gap-1 flex-wrap align-items-start">';
        $html .= '<textarea name="requirements_text" class="form-control form-control-sm" rows="2" placeholder="Add requirement(s), one per line" style="min-width:220px;flex:1;" required></textarea>';
        $html .= '<input type="file" name="attachment" class="form-control form-control-sm" style="min-width:180px;flex:1;">';
        $html .= '<button class="btn btn-sm btn-outline-primary" type="submit">Add</button>';
        $html .= '</div>';
    }
    $html .= '</form></div>';

    return $html;
}

function signatoryGroupSubordinateLabel(?array $office): ?string
{
    $code = strtoupper(trim((string) ($office['code'] ?? '')));

    return match ($code) {
        'SAS' => 'Units under SAS',
        'DEAN' => 'Units under Dean',
        default => null,
    };
}

function signatoryOfficeShowsGroupSubordinates(?array $office): bool
{
    return signatoryGroupSubordinateLabel($office) !== null;
}

function renderSignatoryGroupSubordinateStatusChips(array $subordinateStatuses, string $groupLabel, bool $premium = false): string
{
    if ($subordinateStatuses === []) {
        return '';
    }

    if (!$premium) {
        $html = '<div class="mt-2"><div class="small fw-semibold text-muted mb-1">' . htmlspecialchars($groupLabel) . '</div><div class="d-flex flex-wrap gap-1">';
        foreach ($subordinateStatuses as $unit) {
            $status = strtolower((string) ($unit['status'] ?? 'pending'));
            $label = htmlspecialchars((string) ($unit['office_name'] ?? ''));
            $badgeClass = 'bg-secondary';
            if ($status === 'cleared') {
                $badgeClass = 'bg-success';
            } elseif ($status === 'rejected') {
                $badgeClass = 'bg-danger';
            } elseif ($status === 'for_review') {
                $badgeClass = 'bg-warning text-dark';
            }
            $html .= '<span class="badge ' . $badgeClass . '">' . $label . '</span>';
        }
        $html .= '</div></div>';

        return $html;
    }

    $html = '<div class="group-unit-status">';
    $html .= '<div class="group-unit-status-title"><i class="fas fa-sitemap"></i> ' . htmlspecialchars($groupLabel) . '</div>';
    $html .= '<div class="group-unit-chips">';
    foreach ($subordinateStatuses as $unit) {
        $status = strtolower((string) ($unit['status'] ?? 'pending'));
        $label = htmlspecialchars((string) ($unit['office_name'] ?? ''));
        $chipClass = 'group-unit-chip-pending';
        $icon = 'fa-clock';
        if ($status === 'cleared') {
            $chipClass = 'group-unit-chip-cleared';
            $icon = 'fa-check';
        } elseif ($status === 'rejected') {
            $chipClass = 'group-unit-chip-rejected';
            $icon = 'fa-times';
        } elseif ($status === 'for_review') {
            $chipClass = 'group-unit-chip-review';
            $icon = 'fa-eye';
        }
        $html .= '<span class="group-unit-chip ' . $chipClass . '"><i class="fas ' . $icon . '"></i> ' . $label . '</span>';
    }
    $html .= '</div></div>';

    return $html;
}

function studentMeetsGroupSubordinateClearanceFromMap(array $subordinateStatuses): bool
{
    if ($subordinateStatuses === []) {
        return false;
    }

    foreach ($subordinateStatuses as $unit) {
        if (strtolower((string) ($unit['status'] ?? 'pending')) !== 'cleared') {
            return false;
        }
    }

    return true;
}

/**
 * @param array<string,mixed>|null $queueCollegeProgramFilter College/program/year search data for signatory queues.
 */
function renderSignatoryDashboard(
    array $user,
    array $semester,
    ?array $office,
    array $queue,
    array $officeRequirements = [],
    int $editRequirementId = 0,
    ?array $queueCollegeProgramFilter = null,
    array $studentRequirementMap = [],
    array $studentAttachedRequirementsMap = [],
    ?string $signatorySignaturePath = null,
    array $clearanceMessageThreads = [],
    ?array $clearanceMessageActiveDetail = null,
    int $clearanceRequestedThreadId = 0,
    bool $requiresSignatureUpload = false,
    array $groupSubordinateStatusMap = [],
    array $deadlineStatus = []
): string {
    $html = '<h4 class="section-title">Signatory Dashboard</h4>';
    $html .= renderClearanceDeadlineBanner($deadlineStatus);
    if (!$office) {
        return $html . '<div class="alert alert-warning">You are not assigned to any office for this semester.</div>';
    }
    $missingSignatorySignature = $requiresSignatureUpload
        && ($signatorySignaturePath === null || trim($signatorySignaturePath) === '');
    $groupSubordinateLabel = signatoryGroupSubordinateLabel($office);
    $showsGroupSubordinates = $groupSubordinateLabel !== null;

    $returnCollege = 0;
    $returnProgram = 0;
    $returnYearLevel = '';
    $returnSearchName = '';
    $returnSearchStatus = '';
    $showCollegeProgramCols = false;
    if ($queueCollegeProgramFilter !== null) {
        $showCollegeProgramCols = true;
        $returnCollege = (int) ($queueCollegeProgramFilter['college_id'] ?? 0);
        $returnProgram = (int) ($queueCollegeProgramFilter['program_id'] ?? 0);
        $returnYearLevel = trim((string) ($queueCollegeProgramFilter['year_level'] ?? ''));
        $returnSearchName = trim((string) ($queueCollegeProgramFilter['search_name'] ?? ''));
        $returnSearchStatus = signatoryQueueStatusFilterValue((string) ($queueCollegeProgramFilter['search_status'] ?? ''));
    }

    $signatoryUnreadCount = 0;
    foreach ($clearanceMessageThreads as $threadRow) {
        $signatoryUnreadCount += (int) ($threadRow['unread_count'] ?? 0);
    }
    $msgsLaunchHtml = renderSignatoryMessagesLaunchCard($returnCollege, $returnProgram, $returnYearLevel, $returnSearchName, $signatoryUnreadCount, $returnSearchStatus);

    if ($queueCollegeProgramFilter !== null) {
        return renderSignatoryDashboardPremiumLayout(
            $semester,
            $office,
            $queue,
            $officeRequirements,
            $editRequirementId,
            $queueCollegeProgramFilter,
            $returnCollege,
            $returnProgram,
            $returnYearLevel,
            $returnSearchName,
            $studentRequirementMap,
            $studentAttachedRequirementsMap,
            $signatorySignaturePath,
            $msgsLaunchHtml,
            $requiresSignatureUpload,
            $groupSubordinateStatusMap
        );
    }

    $html .= '<p class="text-muted mb-2">Office: ' . htmlspecialchars($office['name']) . '</p>';
    $html .= '<p class="small text-muted mb-3">Semester: ' . htmlspecialchars($semester['academic_year'] . ' ' . $semester['term']) . '</p>';
    if ($requiresSignatureUpload) {
        $html .= renderSignatorySignatureUploadCard($signatorySignaturePath);
    }
    $html .= $msgsLaunchHtml;
    if ($queueCollegeProgramFilter !== null) {
        $html .= renderSignatoryQueueSearchFiltersForm(
            $queueCollegeProgramFilter['colleges'] ?? [],
            $queueCollegeProgramFilter['programs_by_college'] ?? [],
            $returnCollege,
            $returnProgram,
            $returnYearLevel,
            !empty($queueCollegeProgramFilter['lock_college']),
            $returnSearchName,
            $returnSearchStatus
        );
    }
    $filterQs = signatoryQueueFilterQueryString($returnCollege, $returnProgram, $returnYearLevel, $returnSearchName, $returnSearchStatus);
    $html .= '<div class="card mb-3"><div class="card-header">Shared Requirements Module</div><div class="card-body">';
    $html .= '<p class="small text-muted mb-2">This is the shared requirements list for this office. All students can see it. You can also assign individual requirements per student in the queue below.</p>';
    $html .= '<form method="POST" action="' . hpath('/signatory/office-requirement/add') . '" enctype="multipart/form-data" class="row g-2 mb-3">';
    $html .= '<div class="col-md-4"><input name="title" class="form-control form-control-sm" placeholder="Requirement title (e.g. Return of Books)" required></div>';
    $html .= '<div class="col-md-4"><input name="description" class="form-control form-control-sm" placeholder="Description (optional)"></div>';
    $html .= '<div class="col-md-2"><input name="attachment" type="file" class="form-control form-control-sm"></div>';
    $html .= '<div class="col-md-2"><button class="btn btn-sm btn-outline-primary w-100">Add</button></div>';
    $html .= '</form>';
    if ($officeRequirements === []) {
        $html .= '<p class="text-muted mb-0">No shared requirements yet.</p>';
    } else {
        $html .= '<ul class="mb-0">';
        foreach ($officeRequirements as $req) {
            $html .= '<li><strong>' . htmlspecialchars((string) $req['title']) . '</strong>';
            $desc = trim((string) ($req['description'] ?? ''));
            if ($desc !== '') {
                $html .= ' - ' . htmlspecialchars($desc);
            }
            if (!empty($req['attachment_path'])) {
                $label = htmlspecialchars((string) ($req['attachment_name'] ?? 'Download attachment'));
                $html .= ' <a href="' . hpath('/' . ltrim((string) $req['attachment_path'], '/')) . '" target="_blank" rel="noopener">(' . $label . ')</a>';
            }
            if ($editRequirementId === (int) $req['id']) {
                $html .= '<form method="POST" action="' . hpath('/signatory/office-requirement/update') . '" enctype="multipart/form-data" class="row g-1 mt-1 mb-1">';
                $html .= '<input type="hidden" name="requirement_id" value="' . (int) $req['id'] . '">';
                $html .= '<div class="col-md-3"><input class="form-control form-control-sm" name="title" value="' . htmlspecialchars((string) $req['title']) . '" required></div>';
                $html .= '<div class="col-md-3"><input class="form-control form-control-sm" name="description" value="' . htmlspecialchars((string) ($req['description'] ?? '')) . '"></div>';
                $html .= '<div class="col-md-3"><input class="form-control form-control-sm" type="file" name="attachment"></div>';
                $checkedRemove = !empty($req['attachment_path']) ? '' : ' disabled';
                $html .= '<div class="col-md-3 form-check d-flex align-items-center"><input class="form-check-input me-1" type="checkbox" name="remove_attachment" value="1"' . $checkedRemove . '><label class="form-check-label small">Remove current attachment</label></div>';
                $html .= '<div class="col-md-12 d-flex gap-1"><button class="btn btn-sm btn-success">Save</button><a class="btn btn-sm btn-outline-secondary" href="' . hpath('/dashboard') . $filterQs . '">Cancel</a></div>';
                $html .= '</form>';
            } else {
                $editQs = signatoryQueueFilterQuery($returnCollege, $returnProgram, $returnYearLevel, $returnSearchName, $returnSearchStatus);
                $editQs['edit_requirement_id'] = (string) $req['id'];
                $html .= ' <a class="btn btn-sm btn-outline-success ms-1" href="' . hpath('/dashboard') . '?' . http_build_query($editQs) . '">Edit</a>';
            }
            $html .= '<form method="POST" action="' . hpath('/signatory/office-requirement/delete') . '" class="d-inline ms-1" onsubmit="return confirm(\'Delete this requirement?\');">';
            $html .= '<input type="hidden" name="requirement_id" value="' . (int) $req['id'] . '">';
            $html .= '<button class="btn btn-sm btn-outline-danger" type="submit">Delete</button>';
            $html .= '</form>';
            $html .= '</li>';
        }
        $html .= '</ul>';
    }
    $html .= '</div></div>';

    $html .= '<div class="card"><div class="card-header">Student clearance queue</div><div class="card-body">';
    if (!$queue) {
        $emptyMsg = $queueCollegeProgramFilter !== null
            ? 'No students match the filters.'
            : 'No students in queue.';
        return $html . '<p class="text-muted mb-0">' . $emptyMsg . '</p></div></div>';
    }
    if ($missingSignatorySignature) {
        $html .= '<div class="alert alert-warning py-2 mb-2">No e-signature uploaded. If you choose <strong>CLEARED</strong>, save will be blocked until you upload your signature.</div>';
    }
    $html .= '<div class="table-responsive"><table class="table table-sm align-middle"><thead><tr><th>Student</th>';
    if ($showCollegeProgramCols) {
        $html .= '<th>College</th><th>Program</th>';
    }
    $html .= '<th>Year</th><th>Campus</th><th>Status</th><th>Action</th></tr></thead><tbody>';
    foreach ($queue as $row) {
        $studentId = (int) ($row['student_id'] ?? 0);
        $attachedItems = $studentAttachedRequirementsMap[$studentId] ?? [];
        $progressItems = $studentRequirementMap[$studentId] ?? [];
        $html .= '<tr><td>';
        $html .= '<div>' . htmlspecialchars($row['student_no'] . ' - ' . $row['last_name'] . ', ' . $row['first_name']) . '</div>';
        if ($showsGroupSubordinates && $groupSubordinateLabel !== null) {
            $subordinateStatuses = $groupSubordinateStatusMap[$studentId] ?? [];
            $html .= renderSignatoryGroupSubordinateStatusChips($subordinateStatuses, $groupSubordinateLabel, false);
        }
        if ($progressItems !== []) {
            $html .= '<div class="small mt-1">';
            foreach ($progressItems as $item) {
                $title = htmlspecialchars((string) ($item['title'] ?? 'Requirement'));
                $isSubmitted = (bool) ($item['is_submitted'] ?? false);
                if ($isSubmitted) {
                    $html .= '<span class="badge bg-success-subtle text-success-emphasis me-1 mb-1">' . $title . ' uploaded</span>';
                } else {
                    $html .= '<span class="badge bg-danger-subtle text-danger-emphasis me-1 mb-1">Missing: ' . $title . '</span>';
                }
            }
            $html .= '</div>';
        }
        $html .= renderSignatoryStudentAttachedRequirements(
            $studentId,
            (int) $office['id'],
            $attachedItems,
            $returnCollege,
            $returnProgram,
            $returnYearLevel,
            false,
            $returnSearchName,
            $returnSearchStatus
        );
        $html .= '</td>';
        if ($showCollegeProgramCols) {
            $cn = trim((string) ($row['college_name'] ?? ''));
            $pn = trim((string) ($row['program_name'] ?? ''));
            $html .= '<td>' . ($cn !== '' ? htmlspecialchars($cn) : '—') . '</td>';
            $html .= '<td>' . ($pn !== '' ? htmlspecialchars($pn) : '—') . '</td>';
        }
        $html .= '<td>' . formatYearLevelCell($row['year_level'] ?? null) . '</td>';
        $html .= '<td>' . formatStudentCampusCell($row['campus'] ?? null) . '</td>';
        $html .= '<td><span class="badge bg-secondary">' . htmlspecialchars(strtoupper((string) $row['clearance_status'])) . '</span></td><td>';
        $subordinateStatuses = $showsGroupSubordinates ? ($groupSubordinateStatusMap[$studentId] ?? []) : [];
        $canApproveGroup = !$showsGroupSubordinates || studentMeetsGroupSubordinateClearanceFromMap($subordinateStatuses);
        $html .= '<form method="POST" action="' . hpath('/signatory/decision') . '" class="d-flex flex-wrap gap-1 align-items-center">';
        $html .= '<input type="hidden" name="office_id" value="' . (int) $office['id'] . '">';
        $html .= '<input type="hidden" name="student_id" value="' . (int) $row['student_id'] . '">';
        if ($queueCollegeProgramFilter !== null) {
            $html .= signatoryQueueReturnFilterHiddenFields($returnCollege, $returnProgram, $returnYearLevel, $returnSearchName, $returnSearchStatus);
        }
        $html .= '<select name="status" class="form-select form-select-sm"><option value="for_review">For Review</option>';
        $html .= '<option value="cleared"' . ($canApproveGroup ? '' : ' disabled') . '>Cleared</option>';
        $html .= '<option value="rejected">Rejected</option></select>';
        $html .= '<input name="reason" class="form-control form-control-sm" placeholder="Reason (optional)">';
        $html .= '<button class="btn btn-sm btn-success">Save</button></form>';
        if ($showsGroupSubordinates && !$canApproveGroup) {
            $html .= '<div><small class="text-warning">All units under your office group must clear this student before you can approve.</small></div>';
        }
        if ($missingSignatorySignature) {
            $html .= '<div><small class="text-warning">Upload e-signature first to allow <strong>CLEARED</strong>.</small></div>';
        }
        $html .= '</td></tr>';
    }
    $html .= '</tbody></table></div></div></div>';
    return $html;
}

function renderSignatorySignatureUploadCard(?string $signatorySignaturePath): string
{
    $html = '<div class="card mb-3"><div class="card-header"><strong>My E-Signature</strong></div><div class="card-body">';
    $html .= '<p class="small text-muted mb-2">Upload your signature image (PNG/JPG/WEBP, max 2MB). This will be attached when you mark a student as <strong>CLEARED</strong>.</p>';
    if ($signatorySignaturePath !== null && $signatorySignaturePath !== '') {
        $html .= '<div class="mb-2"><small class="text-success">Current signature is active.</small></div>';
        $html .= '<div class="mb-2"><img src="' . hpath('/' . ltrim((string) $signatorySignaturePath, '/')) . '" alt="Current signatory signature" style="max-width:220px;max-height:80px;border:1px solid #ced4da;padding:4px;border-radius:6px;background:#fff;"></div>';
    } else {
        $html .= '<div class="mb-2"><small class="text-danger">No signature uploaded yet.</small></div>';
    }
    $html .= '<form method="POST" action="' . hpath('/signatory/signature/upload') . '" enctype="multipart/form-data" class="row g-2">';
    $html .= '<div class="col-md-8"><input class="form-control form-control-sm" type="file" name="signature_file" accept=".png,.jpg,.jpeg,.webp,image/png,image/jpeg,image/webp" required></div>';
    $html .= '<div class="col-md-4"><button class="btn btn-sm btn-outline-primary w-100">Upload Signature</button></div>';
    $html .= '</form></div></div>';
    return $html;
}

/**
 * Signatory queue UI for SSC, Library, and SAS (college/program filters) — matches dedicated dashboard styling.
 *
 * @param array<string,mixed> $semester
 * @param array<string,mixed> $office
 * @param list<array<string,mixed>> $queue
 * @param array<string,mixed> $queueCollegeProgramFilter
 */
function renderSignatoryDashboardPremiumLayout(
    array $semester,
    array $office,
    array $queue,
    array $officeRequirements,
    int $editRequirementId,
    array $queueCollegeProgramFilter,
    int $returnCollege,
    int $returnProgram,
    string $returnYearLevel,
    string $returnSearchName,
    array $studentRequirementMap = [],
    array $studentAttachedRequirementsMap = [],
    ?string $signatorySignaturePath = null,
    string $clearanceMessagesHtml = '',
    bool $requiresSignatureUpload = false,
    array $groupSubordinateStatusMap = []
): string {
    $colleges = $queueCollegeProgramFilter['colleges'] ?? [];
    $programsByCollege = $queueCollegeProgramFilter['programs_by_college'] ?? [];
    $lockCollege = !empty($queueCollegeProgramFilter['lock_college']);
    $returnSearchStatus = signatoryQueueStatusFilterValue((string) ($queueCollegeProgramFilter['search_status'] ?? ''));
    $filterQs = signatoryQueueFilterQueryString($returnCollege, $returnProgram, $returnYearLevel, $returnSearchName, $returnSearchStatus);
    $programsJson = json_encode($programsByCollege, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE);
    if ($programsJson === false) {
        $programsJson = '{}';
    }

    $semesterLabel = htmlspecialchars($semester['academic_year'] . ' ' . $semester['term']);
    $officeName = htmlspecialchars((string) $office['name']);
    $officeCode = strtoupper(trim((string) ($office['code'] ?? '')));
    $isSasOffice = $officeCode === 'SAS';
    $isDeanOffice = $officeCode === 'DEAN';
    $groupSubordinateLabel = signatoryGroupSubordinateLabel($office);
    $showsGroupSubordinates = $groupSubordinateLabel !== null;
    $missingSignatorySignature = $requiresSignatureUpload
        && ($signatorySignaturePath === null || trim($signatorySignaturePath) === '');

    $pendingN = 0;
    $collegesSeen = [];
    $readyForGroupApprovalN = 0;
    foreach ($queue as $qrow) {
        $st = strtolower((string) ($qrow['clearance_status'] ?? 'pending'));
        if ($st === 'pending') {
            $pendingN++;
        }
        $cn = trim((string) ($qrow['college_name'] ?? ''));
        if ($cn !== '') {
            $collegesSeen[$cn] = true;
        }
        if ($showsGroupSubordinates) {
            $studentId = (int) ($qrow['student_id'] ?? 0);
            $subordinateStatuses = $groupSubordinateStatusMap[$studentId] ?? [];
            if (studentMeetsGroupSubordinateClearanceFromMap($subordinateStatuses)) {
                $readyForGroupApprovalN++;
            }
        }
    }
    $uniqueColleges = count($collegesSeen);
    if ($isSasOffice) {
        $awaitingLabel = 'Ready for SAS approval';
        $awaitingN = $readyForGroupApprovalN;
    } elseif ($isDeanOffice) {
        $awaitingLabel = 'Ready for Dean approval';
        $awaitingN = $readyForGroupApprovalN;
    } else {
        $awaitingLabel = 'Awaiting review';
        $awaitingN = count($queue);
    }

    $css = <<<'CSS'
.signatory-dash-premium { background:#f0f2f8; font-family:'Inter',sans-serif; color:#1a2c3e; margin:0 -12px; padding:2rem 0 2.5rem; }
@media (min-width:576px){ .signatory-dash-premium { margin:0 -24px; } }
.signatory-dash-premium * { box-sizing:border-box; }
.signatory-dash-premium .dashboard-container { max-width:1440px; margin:0 auto; padding:0 1.25rem; }
.signatory-dash-premium .top-bar { display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:1rem; margin-bottom:2rem; }
.signatory-dash-premium .brand-area h1 { font-size:1.85rem; font-weight:700; background:linear-gradient(135deg,#1e3c72,#2b4c8a); -webkit-background-clip:text; background-clip:text; color:transparent; letter-spacing:-0.3px; margin:0; }
.signatory-dash-premium .brand-lockup { display:flex; align-items:center; gap:.7rem; }
.signatory-dash-premium .brand-lockup img { width:44px; height:44px; object-fit:contain; border-radius:50%; background:#fff; flex-shrink:0; box-shadow:0 2px 8px rgba(0,0,0,.12); }
.signatory-dash-premium .badge-req { font-size:0.8rem; background:#fee2e2; color:#b91c1c; padding:4px 12px; border-radius:40px; display:inline-block; margin-top:8px; font-weight:500; }
.signatory-dash-premium .office-panel { background:#fff; padding:12px 24px; border-radius:60px; box-shadow:0 4px 12px rgba(0,0,0,0.02); display:flex; gap:1rem; align-items:baseline; flex-wrap:wrap; border:1px solid rgba(0,0,0,0.05); }
.signatory-dash-premium .office-item { display:flex; align-items:center; gap:10px; font-weight:500; }
.signatory-dash-premium .office-item i { font-size:1.05rem; color:#2c6e9e; }
.signatory-dash-premium .semester-chip { background:#eef2ff; padding:5px 14px; border-radius:40px; font-weight:600; font-size:0.85rem; }
.signatory-dash-premium .stats-row { display:flex; gap:20px; margin-bottom:1.8rem; flex-wrap:wrap; }
.signatory-dash-premium .stat-card { background:#fff; border-radius:28px; padding:18px 28px; flex:1; min-width:160px; box-shadow:0 8px 20px rgba(0,0,0,0.02),0 2px 4px rgba(0,0,0,0.02); border:1px solid #e9edf2; transition:all 0.2s; }
.signatory-dash-premium .stat-card:hover { transform:translateY(-2px); box-shadow:0 14px 26px rgba(0,0,0,0.05); }
.signatory-dash-premium .stat-label { font-size:0.85rem; text-transform:uppercase; letter-spacing:0.04em; font-weight:600; color:#5b6e8c; }
.signatory-dash-premium .stat-value { font-size:2.3rem; font-weight:800; color:#1e3a5f; line-height:1.1; margin-top:8px; }
.signatory-dash-premium .stat-card-semester { background:linear-gradient(135deg,#f8fbff 0%,#ecf4ff 100%); border-color:#cfe0f6; }
.signatory-dash-premium .stat-card-semester .stat-label { color:#375a7f; }
.signatory-dash-premium .stat-card-semester .stat-value { color:#1f4f82; }
.signatory-dash-premium .stat-card-colleges { background:linear-gradient(135deg,#fffdf7 0%,#fef8e6 100%); border-color:#f4e0ad; }
.signatory-dash-premium .stat-card-colleges .stat-label { color:#7a6230; }
.signatory-dash-premium .stat-card-colleges .stat-value { color:#946f2d; }
.signatory-dash-premium .stat-card-awaiting { background:linear-gradient(135deg,#fff8f9 0%,#ffeff2 100%); border-color:#f4c8d3; }
.signatory-dash-premium .stat-card-awaiting .stat-label { color:#7d4252; }
.signatory-dash-premium .stat-card-awaiting .stat-value { color:#9a3f59; }
.signatory-dash-premium .info-note { background:#fef9e6; border-left:4px solid #f5b042; padding:14px 24px; border-radius:20px; font-size:0.85rem; margin-bottom:1.8rem; display:flex; align-items:flex-start; gap:12px; color:#7a6700; }
.signatory-dash-premium .filter-section { background:#fff; border-radius:28px; padding:18px 28px; margin-bottom:1.8rem; display:flex; flex-wrap:wrap; gap:20px; align-items:flex-end; box-shadow:0 2px 6px rgba(0,0,0,0.02); border:1px solid #eef2f8; }
.signatory-dash-premium .filter-group { flex:1; min-width:180px; }
.signatory-dash-premium .filter-group label { font-size:0.75rem; font-weight:600; text-transform:uppercase; color:#4f6f8f; display:block; margin-bottom:6px; }
.signatory-dash-premium .filter-group select,
.signatory-dash-premium .filter-group input,
.signatory-dash-premium .filter-group textarea { width:100%; padding:12px 14px; border-radius:18px; border:1px solid #cfdfed; background:#fff; font-family:'Inter',sans-serif; font-weight:500; outline:none; transition:0.2s; }
.signatory-dash-premium .filter-group select:focus,
.signatory-dash-premium .filter-group input:focus,
.signatory-dash-premium .filter-group textarea:focus { border-color:#2c7da0; box-shadow:0 0 0 3px rgba(44,125,160,0.1); }
.signatory-dash-premium .button-group { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.signatory-dash-premium .btn-primary { background:#2266a8; border:none; padding:12px 20px; border-radius:36px; color:#fff; font-weight:600; cursor:pointer; transition:0.2s; display:inline-flex; align-items:center; gap:8px; text-decoration:none; }
.signatory-dash-premium .btn-primary:hover { background:#0e4b7c; transform:scale(0.98); color:#fff; }
.signatory-dash-premium .btn-outline { background:none; border:1px solid #dce5ef; padding:11px 16px; border-radius:30px; font-size:0.8rem; font-weight:500; cursor:pointer; transition:0.1s; color:#334155; text-decoration:none; }
.signatory-dash-premium .btn-outline:hover { background:#f7f9fd; color:#0f172a; }
.signatory-dash-premium .two-col-grid { display:grid; grid-template-columns:1fr 1.2fr; gap:28px; margin-bottom:1rem; }
.signatory-dash-premium .card-panel { background:#fff; border-radius:32px; box-shadow:0 8px 24px rgba(0,0,0,0.03); border:1px solid #eef2f8; overflow:hidden; }
.signatory-dash-premium .card-header { padding:20px 28px; background:#fafcff; border-bottom:1px solid #eef2f8; display:flex; justify-content:space-between; align-items:flex-start; gap:10px; flex-wrap:wrap; }
.signatory-dash-premium .card-header h2 { font-size:1.3rem; font-weight:600; display:flex; align-items:center; gap:12px; margin:0; }
.signatory-dash-premium .card-subtext { font-size:0.75rem; color:#5f7c9f; margin:0; }
.signatory-dash-premium .req-list { padding:8px 0; max-height:540px; overflow-y:auto; }
.signatory-dash-premium .req-item { padding:18px 28px; border-bottom:1px solid #eff3f9; transition:background 0.1s; }
.signatory-dash-premium .req-title { font-weight:700; font-size:1rem; color:#1e3a5f; }
.signatory-dash-premium .req-desc { font-size:0.8rem; color:#5e7c9c; margin-top:5px; }
.signatory-dash-premium .req-attach { margin-top:10px; display:flex; align-items:center; gap:12px; font-size:0.8rem; background:#f7f9fd; padding:8px 12px; border-radius:50px; width:fit-content; }
.signatory-dash-premium .req-actions { margin-top:8px; display:flex; align-items:center; gap:6px; flex-wrap:wrap; }
.signatory-dash-premium .add-req-form { padding:22px 28px; background:#f8fafd; border-top:1px solid #eef2f8; }
.signatory-dash-premium .student-list { max-height:700px; overflow-y:auto; }
.signatory-dash-premium .student-row { padding:20px 24px; border-bottom:1px solid #eff3f9; transition:all 0.15s; display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:16px; }
.signatory-dash-premium .student-info { flex:2; min-width:260px; }
.signatory-dash-premium .student-name { font-weight:700; font-size:1rem; display:flex; align-items:baseline; gap:12px; flex-wrap:wrap; color:#1e3a5f; }
.signatory-dash-premium .student-id { font-family:ui-monospace,monospace; background:#ecf3fa; padding:2px 10px; border-radius:30px; font-size:0.7rem; font-weight:500; }
.signatory-dash-premium .college-prog { font-size:0.75rem; color:#597a9e; margin-top:6px; display:flex; gap:12px; flex-wrap:wrap; }
.signatory-dash-premium .req-progress { margin-top:10px; display:flex; gap:6px; flex-wrap:wrap; }
.signatory-dash-premium .req-chip { display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:999px; font-size:0.68rem; font-weight:600; text-decoration:none; }
.signatory-dash-premium .req-chip-submitted { background:#dcfce7; color:#166534; border:1px solid #86efac; }
.signatory-dash-premium .req-chip-missing { background:#fee2e2; color:#991b1b; border:1px solid #fca5a5; }
.signatory-dash-premium .group-unit-status { margin-top:10px; }
.signatory-dash-premium .group-unit-status-title { font-size:0.68rem; font-weight:700; color:#475569; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.04em; }
.signatory-dash-premium .group-unit-chips { display:flex; gap:6px; flex-wrap:wrap; }
.signatory-dash-premium .group-unit-chip { display:inline-flex; align-items:center; gap:5px; padding:4px 10px; border-radius:999px; font-size:0.66rem; font-weight:600; border:1px solid transparent; }
.signatory-dash-premium .group-unit-chip-cleared { background:#dcfce7; color:#166534; border-color:#86efac; }
.signatory-dash-premium .group-unit-chip-pending { background:#f1f5f9; color:#475569; border-color:#cbd5e1; }
.signatory-dash-premium .group-unit-chip-review { background:#ffedd5; color:#b45309; border-color:#fdba74; }
.signatory-dash-premium .group-unit-chip-rejected { background:#fee2e2; color:#991b1b; border-color:#fca5a5; }
.signatory-dash-premium .attached-req-block { margin-top:12px; padding-top:12px; border-top:1px dashed #dbe4f0; }
.signatory-dash-premium .attached-req-title { font-size:0.72rem; font-weight:700; color:#475569; margin-bottom:8px; text-transform:uppercase; letter-spacing:0.04em; }
.signatory-dash-premium .attached-req-list { list-style:none; margin:0 0 10px; padding:0; display:flex; flex-direction:column; gap:8px; }
.signatory-dash-premium .attached-req-item { display:flex; flex-direction:column; gap:6px; padding:8px 10px; border-radius:10px; background:#f8fafc; border:1px solid #e2e8f0; }
.signatory-dash-premium .attached-req-done { color:#166534; font-size:0.78rem; font-weight:600; }
.signatory-dash-premium .attached-req-pending { color:#9a3412; font-size:0.78rem; font-weight:600; }
.signatory-dash-premium .attached-req-attach { font-size:0.72rem; color:#475569; }
.signatory-dash-premium .attached-req-attach a { color:#2266a8; text-decoration:none; font-weight:600; }
.signatory-dash-premium .attached-req-attach a:hover { text-decoration:underline; }
.signatory-dash-premium .attached-req-actions { display:flex; gap:6px; flex-wrap:wrap; }
.signatory-dash-premium .attached-req-empty { font-size:0.75rem; color:#94a3b8; margin-bottom:8px; }
.signatory-dash-premium .attached-req-add-form { display:flex; gap:8px; flex-wrap:wrap; align-items:flex-start; }
.signatory-dash-premium .attached-req-add-form textarea { flex:1; min-width:180px; min-height:56px; border:1px solid #dbe4f0; border-radius:10px; padding:8px 10px; font-size:0.78rem; }
.signatory-dash-premium .attached-req-upload { display:flex; flex-direction:column; gap:4px; min-width:180px; }
.signatory-dash-premium .attached-req-upload label { font-size:0.68rem; font-weight:600; text-transform:uppercase; color:#64748b; }
.signatory-dash-premium .attached-req-upload input[type=file] { font-size:0.72rem; }
.signatory-dash-premium .status-area { display:flex; align-items:center; gap:12px; flex-wrap:wrap; justify-content:flex-end; }
.signatory-dash-premium .status-badge { padding:6px 16px; border-radius:60px; font-weight:600; font-size:0.75rem; letter-spacing:0.3px; display:inline-flex; align-items:center; gap:5px; }
.signatory-dash-premium .status-for_review { background:#ffedd5; color:#b45309; }
.signatory-dash-premium .status-cleared { background:#dcfce7; color:#15803d; }
.signatory-dash-premium .status-rejected { background:#fee2e2; color:#b91c1c; }
.signatory-dash-premium .reason-input { padding:6px 10px; border-radius:30px; border:1px solid #cddae9; font-size:0.7rem; width:140px; }
.signatory-dash-premium .review-select { padding:6px 10px; border-radius:30px; border:1px solid #cddae9; font-size:0.75rem; background:#fff; min-width:132px; }
.signatory-dash-premium .save-btn { background:#1e3a5f; color:#fff; border:none; padding:6px 12px; border-radius:30px; font-size:0.74rem; font-weight:500; cursor:pointer; }
.signatory-dash-premium .empty-state { text-align:center; padding:48px 20px; color:#8aa0bc; }
.signatory-dash-premium .footer-note { margin-top:1rem; text-align:center; font-size:0.75rem; color:#6c86a3; }
.signatory-dash-premium .signatory-clearance-msg-wrap,
.signatory-dash-premium .signatory-signature-wrap { margin-bottom:1.8rem; }
.signatory-dash-premium .signatory-clearance-msg-wrap .card,
.signatory-dash-premium .signatory-signature-wrap .card { border-radius:28px; border:1px solid #eef2f8; box-shadow:0 2px 6px rgba(0,0,0,.02); overflow:hidden; }
.signatory-dash-premium .signatory-clearance-msg-wrap .card-header,
.signatory-dash-premium .signatory-signature-wrap .card-header { background:#fafcff; border-bottom:1px solid #eef2f8; font-weight:600; }
.signatory-dash-premium .signatory-clearance-msg-wrap .btn-outline-primary,
.signatory-dash-premium .signatory-signature-wrap .btn-outline-primary { background:#2266a8; border-color:#2266a8; color:#fff; border-radius:36px; font-weight:600; padding:8px 18px; }
.signatory-dash-premium .signatory-clearance-msg-wrap .btn-outline-primary:hover,
.signatory-dash-premium .signatory-signature-wrap .btn-outline-primary:hover { background:#0e4b7c; border-color:#0e4b7c; color:#fff; }
@media (max-width:900px){
  .signatory-dash-premium { padding-top:1.2rem; }
  .signatory-dash-premium .dashboard-container { padding:0 0.9rem; }
  .signatory-dash-premium .two-col-grid { grid-template-columns:1fr; }
}
CSS;

    $out = '<div class="signatory-dash-premium"><style>' . $css . '</style>';
    $out .= '<div class="dashboard-container">';
    $out .= '<div class="top-bar"><div class="brand-area">';
    $out .= '<div class="brand-lockup"><img src="' . hasset('wpu-logo.png') . '" alt="Western Philippines University"><h1>SAFE Clearance System</h1></div>';
    $out .= '</div>';
    $out .= '<div class="office-panel">';
    $out .= '<div class="office-item"><i class="fas fa-building"></i> Office: <strong>' . $officeName . '</strong></div>';
    $out .= '<div class="office-item"><i class="fas fa-calendar-alt"></i> Semester: <span class="semester-chip">' . $semesterLabel . '</span></div>';
    $out .= '<div class="office-item"><i class="fas fa-chalkboard-user"></i> Signatory Dashboard</div>';
    $out .= '</div></div>';
    if ($requiresSignatureUpload) {
        $out .= '<div class="signatory-signature-wrap">' . renderSignatorySignatureUploadCard($signatorySignaturePath) . '</div>';
    }
    if ($clearanceMessagesHtml !== '') {
        $out .= '<div class="signatory-clearance-msg-wrap">' . $clearanceMessagesHtml . '</div>';
    }

    $out .= '<div class="stats-row">';
    $out .= '<div class="stat-card stat-card-semester"><div class="stat-label">Semester</div><div class="stat-value">' . $semesterLabel . '</div></div>';
    $out .= '<div class="stat-card stat-card-colleges"><div class="stat-label">Colleges in queue</div><div class="stat-value">' . (int) $uniqueColleges . '</div></div>';
    $out .= '<div class="stat-card stat-card-awaiting"><div class="stat-label">' . $awaitingLabel . '</div><div class="stat-value">' . (int) $awaitingN . '</div></div>';
    $out .= '</div>';

    $out .= '<div class="info-note"><i class="fas fa-info-circle" style="font-size:1.1rem;"></i><span>';
    if ($isSasOffice) {
        $out .= 'Review each student\'s clearance from <strong>units under Student Affairs and Services only</strong> (SSC, Dormitory, Accounting, SOA, and any additional SAS units). The <strong>College Dean</strong> group is not shown here. You may approve only after every SAS unit shows <strong>Cleared</strong>. Upload your e-signature before marking a student as <strong>Approved</strong>.';
    } elseif ($isDeanOffice) {
        $out .= 'Review each student\'s clearance from <strong>units under College Dean / Campus Administrator only</strong> (University/Campus Library and any additional Dean units). The <strong>Student Affairs and Services</strong> group is not shown here. You may approve only after every Dean unit shows <strong>Cleared</strong>. Upload your e-signature before marking a student as <strong>Approved</strong>.';
    } else {
        $out .= 'All active students are available for review at any time. Use name, college, program, year level, or status filters to narrow the list.';
    }
    $out .= '</span></div>';

    $out .= '<div class="filter-section">';
    $out .= '<form method="GET" action="' . hpath('/dashboard') . '" class="filter-section" id="signatory-queue-filter-form" style="padding:0;margin:0;border:0;box-shadow:none;background:transparent;width:100%;">';
    $out .= '<div class="filter-group"><label><i class="fas fa-user"></i> Name or ID</label>';
    $out .= '<input type="text" name="search_name" value="' . htmlspecialchars($returnSearchName, ENT_QUOTES, 'UTF-8') . '" placeholder="Student name or ID">';
    $out .= '</div>';
    $out .= '<div class="filter-group"><label><i class="fas fa-university"></i> College</label>';
    $out .= '<select name="college_id" id="signatory_filter_college_id"' . ($lockCollege ? ' disabled' : '') . '>';
    if (!$lockCollege) {
        $out .= '<option value="0"' . ($returnCollege === 0 ? ' selected' : '') . '>All colleges</option>';
    }
    foreach ($colleges as $college) {
        $cid = (int) $college['id'];
        $sel = $returnCollege === $cid ? ' selected' : '';
        $out .= '<option value="' . $cid . '"' . $sel . '>' . htmlspecialchars((string) $college['name']) . '</option>';
    }
    if ($lockCollege && $returnCollege > 0) {
        $out .= '<input type="hidden" name="college_id" value="' . $returnCollege . '">';
    }
    $out .= '</select></div>';
    $out .= '<div class="filter-group"><label><i class="fas fa-graduation-cap"></i> Program</label>';
    $out .= '<select name="program_id" id="signatory_filter_program_id">';
    $out .= '<option value="0"' . ($returnProgram === 0 ? ' selected' : '') . '>All programs</option>';
    if ($returnCollege > 0 && isset($programsByCollege[$returnCollege])) {
        foreach ($programsByCollege[$returnCollege] as $prog) {
            $pid = (int) $prog['id'];
            $sel = $returnProgram === $pid ? ' selected' : '';
            $label = htmlspecialchars($prog['name'] . ' (' . $prog['code'] . ')');
            $out .= '<option value="' . $pid . '"' . $sel . '>' . $label . '</option>';
        }
    }
    $out .= '</select></div>';
    $out .= '<div class="filter-group"><label><i class="fas fa-layer-group"></i> Year level</label>';
    $out .= '<select name="year_level" id="signatory_filter_year_level">';
    $yearOptions = ['' => 'All years', '1' => '1', '2' => '2', '3' => '3', '4' => '4', '5+' => '5+'];
    foreach ($yearOptions as $val => $label) {
        $sel = $returnYearLevel === (string) $val ? ' selected' : '';
        $out .= '<option value="' . htmlspecialchars((string) $val) . '"' . $sel . '>' . htmlspecialchars((string) $label) . '</option>';
    }
    $out .= '</select></div>';
    $out .= '<div class="filter-group"><label><i class="fas fa-filter"></i> Status</label>';
    $out .= '<select name="search_status">';
    $out .= renderSignatoryQueueStatusFilterOptionsHtml($returnSearchStatus);
    $out .= '</select></div>';
    $out .= '<div class="button-group"><button class="btn-primary" type="submit"><i class="fas fa-search"></i> Apply</button>';
    $out .= '<a class="btn-outline" href="' . hpath('/dashboard') . '"><i class="fas fa-eraser"></i> Reset</a></div>';
    $out .= '</form>';
    $out .= '</div>';

    $out .= '<div class="two-col-grid">';
    $out .= '<div class="card-panel">';
    $out .= '<div class="card-header"><div><h2><i class="fas fa-folder-open"></i> Shared Requirements Module</h2>';
    $out .= '<p class="card-subtext">All students can see this list in the upload section. Individual requirements can be assigned per student in the queue.</p></div></div>';

    if ($officeRequirements === []) {
        $out .= '<div class="req-list"><div class="empty-state"><i class="fas fa-inbox"></i> No shared requirements yet.</div></div>';
    } else {
        $out .= '<div class="req-list">';
        foreach ($officeRequirements as $req) {
            $out .= '<div class="req-item"><div class="req-title"><i class="fas fa-file-alt"></i> ' . htmlspecialchars((string) $req['title']) . '</div>';
            $desc = trim((string) ($req['description'] ?? ''));
            $out .= '<div class="req-desc">' . ($desc !== '' ? htmlspecialchars($desc) : 'No description provided') . '</div>';
            if (!empty($req['attachment_path'])) {
                $label = htmlspecialchars((string) ($req['attachment_name'] ?? 'Download attachment'));
                $out .= '<div class="req-attach"><i class="fas fa-paperclip"></i> <a href="' . hpath('/' . ltrim((string) $req['attachment_path'], '/')) . '" target="_blank" rel="noopener">' . $label . '</a></div>';
            } else {
                $out .= '<div class="req-attach"><i class="fas fa-cloud-upload-alt"></i> No file attached</div>';
            }
            $out .= '<div class="req-actions">';
            if ($editRequirementId === (int) $req['id']) {
                $out .= '<form method="POST" action="' . hpath('/signatory/office-requirement/update') . '" enctype="multipart/form-data" style="display:flex;gap:6px;flex-wrap:wrap;width:100%;">';
                $out .= '<input type="hidden" name="requirement_id" value="' . (int) $req['id'] . '">';
                $out .= '<input name="title" value="' . htmlspecialchars((string) $req['title']) . '" style="flex:1;min-width:180px;" required>';
                $out .= '<input name="description" value="' . htmlspecialchars((string) ($req['description'] ?? '')) . '" style="flex:1;min-width:180px;">';
                $out .= '<input type="file" name="attachment" style="flex:1;min-width:180px;">';
                if (!empty($req['attachment_path'])) {
                    $out .= '<label style="display:flex;align-items:center;gap:4px;font-size:0.75rem;"><input type="checkbox" name="remove_attachment" value="1"> Remove attachment</label>';
                }
                $out .= '<button class="btn-primary" type="submit">Save</button>';
                $out .= '<a class="btn-outline" href="' . hpath('/dashboard') . $filterQs . '">Cancel</a>';
                $out .= '</form>';
            } else {
                $editQs = signatoryQueueFilterQuery($returnCollege, $returnProgram, $returnYearLevel, $returnSearchName, $returnSearchStatus);
                $editQs['edit_requirement_id'] = (string) $req['id'];
                $out .= '<a class="btn-outline" href="' . hpath('/dashboard') . '?' . http_build_query($editQs) . '">Edit</a>';
            }
            $out .= '<form method="POST" action="' . hpath('/signatory/office-requirement/delete') . '" style="display:inline;" onsubmit="return confirm(\'Delete this requirement?\');">';
            $out .= '<input type="hidden" name="requirement_id" value="' . (int) $req['id'] . '">';
            $out .= '<button class="btn-outline" type="submit">Delete</button></form></div></div>';
        }
        $out .= '</div>';
    }

    $out .= '<div class="add-req-form">';
    $out .= '<h4 style="margin-bottom:14px;font-weight:600;"><i class="fas fa-plus-circle"></i> Add new requirement</h4>';
    $out .= '<form method="POST" action="' . hpath('/signatory/office-requirement/add') . '" enctype="multipart/form-data">';
    $out .= '<div class="filter-group" style="margin-bottom:12px;"><input name="title" placeholder="REQUIREMENT TITLE e.g. Thesis Binding Receipt" required></div>';
    $out .= '<div class="filter-group" style="margin-bottom:12px;"><textarea name="description" rows="2" placeholder="DESCRIPTION (optional)"></textarea></div>';
    $out .= '<div class="filter-group" style="margin-bottom:12px;"><label><i class="fas fa-file-alt"></i> Attachment</label><input type="file" name="attachment"></div>';
    $out .= '<button class="btn-primary" type="submit"><i class="fas fa-plus"></i> Add Requirement</button>';
    $out .= '</form></div></div>';

    $out .= '<div class="card-panel">';
    $out .= '<div class="card-header"><h2><i class="fas fa-users"></i> Student clearance queue</h2>';
    if ($isSasOffice) {
        $out .= '<span style="font-size:0.7rem;background:#eef2ff;padding:4px 14px;border-radius:20px;">SAS units only — Dean group hidden</span>';
    } elseif ($isDeanOffice) {
        $out .= '<span style="font-size:0.7rem;background:#eef2ff;padding:4px 14px;border-radius:20px;">Dean units only — SAS group hidden</span>';
    } else {
        $out .= '<span style="font-size:0.7rem;background:#eef2ff;padding:4px 14px;border-radius:20px;">Active students only</span>';
    }
    $out .= '</div>';
    $out .= '<div class="student-list">';
    if ($missingSignatorySignature) {
        $out .= '<div style="margin:14px 20px;padding:10px 12px;border-left:4px solid #f59e0b;background:#fffbeb;color:#92400e;border-radius:10px;font-size:0.82rem;">No e-signature uploaded. If status is set to <strong>Approved</strong>, save will be blocked until you upload your signature above.</div>';
    }
    if ($queue === []) {
        $out .= '<div class="empty-state"><i class="fas fa-user-slash"></i> No students match the filters.</div>';
    } else {
        foreach ($queue as $row) {
            $stRaw = strtolower((string) ($row['clearance_status'] ?? 'pending'));
            $statusLabel = strtoupper($stRaw);
            $badgeClass = 'status-for_review';
            $icon = 'fa-eye';
            if ($stRaw === 'cleared') {
                $badgeClass = 'status-cleared';
                $icon = 'fa-check';
            } elseif ($stRaw === 'rejected') {
                $badgeClass = 'status-rejected';
                $icon = 'fa-times';
            }
            $cn = trim((string) ($row['college_name'] ?? ''));
            $pn = trim((string) ($row['program_name'] ?? ''));
            $studentLine = htmlspecialchars($row['last_name'] . ', ' . $row['first_name']);
            $selFor = ($stRaw === 'for_review' || $stRaw === 'pending') ? ' selected' : '';
            $selClear = $stRaw === 'cleared' ? ' selected' : '';
            $selRej = $stRaw === 'rejected' ? ' selected' : '';

            $out .= '<div class="student-row"><div class="student-info">';
            $out .= '<div class="student-name">' . $studentLine . ' <span class="student-id">ID: ' . htmlspecialchars((string) $row['student_no']) . '</span></div>';
            $out .= '<div class="college-prog"><span><i class="fas fa-building"></i> ' . ($cn !== '' ? htmlspecialchars($cn) : '—') . '</span>';
            $out .= '<span><i class="fas fa-book-open"></i> ' . ($pn !== '' ? htmlspecialchars($pn) : '—') . '</span>';
            $out .= '<span><i class="fas fa-layer-group"></i> ' . formatYearLevelCell($row['year_level'] ?? null) . '</span>';
            $out .= '<span><i class="fas fa-map-marker-alt"></i> ' . formatStudentCampusCell($row['campus'] ?? null) . '</span></div>';
            if ($showsGroupSubordinates && $groupSubordinateLabel !== null) {
                $subordinateStatuses = $groupSubordinateStatusMap[(int) ($row['student_id'] ?? 0)] ?? [];
                $out .= renderSignatoryGroupSubordinateStatusChips($subordinateStatuses, $groupSubordinateLabel, true);
            }
            $progressItems = $studentRequirementMap[(int) ($row['student_id'] ?? 0)] ?? [];
            if ($progressItems !== []) {
                $out .= '<div class="req-progress">';
                foreach ($progressItems as $item) {
                    $title = htmlspecialchars((string) ($item['title'] ?? 'Requirement'));
                    $isSubmitted = (bool) ($item['is_submitted'] ?? false);
                    if ($isSubmitted) {
                        $filePath = trim((string) ($item['file_path'] ?? ''));
                        $fileName = trim((string) ($item['original_filename'] ?? ''));
                        if ($filePath !== '') {
                            $label = $fileName !== '' ? $fileName : $title;
                            $out .= '<a class="req-chip req-chip-submitted" href="' . hpath('/' . ltrim($filePath, '/')) . '" target="_blank" rel="noopener"><i class="fas fa-paperclip"></i> ' . htmlspecialchars($label) . '</a>';
                        } else {
                            $out .= '<span class="req-chip req-chip-submitted"><i class="fas fa-check-circle"></i> ' . $title . ' submitted</span>';
                        }
                    } else {
                        $out .= '<span class="req-chip req-chip-missing"><i class="fas fa-exclamation-circle"></i> Missing: ' . $title . '</span>';
                    }
                }
                $out .= '</div>';
            }
            $attachedItems = $studentAttachedRequirementsMap[(int) ($row['student_id'] ?? 0)] ?? [];
            $out .= renderSignatoryStudentAttachedRequirements(
                (int) ($row['student_id'] ?? 0),
                (int) $office['id'],
                $attachedItems,
                $returnCollege,
                $returnProgram,
                $returnYearLevel,
                true,
                $returnSearchName,
                $returnSearchStatus
            );
            $out .= '</div>';
            $subordinateStatuses = $showsGroupSubordinates ? ($groupSubordinateStatusMap[(int) ($row['student_id'] ?? 0)] ?? []) : [];
            $canApproveGroup = !$showsGroupSubordinates || studentMeetsGroupSubordinateClearanceFromMap($subordinateStatuses);
            $out .= '<form method="POST" action="' . hpath('/signatory/decision') . '" class="status-area" style="margin:0;">';
            $out .= '<input type="hidden" name="office_id" value="' . (int) $office['id'] . '">';
            $out .= '<input type="hidden" name="student_id" value="' . (int) $row['student_id'] . '">';
            $out .= signatoryQueueReturnFilterHiddenFields($returnCollege, $returnProgram, $returnYearLevel, $returnSearchName, $returnSearchStatus);
            $out .= '<div class="status-badge ' . $badgeClass . '"><i class="fas ' . $icon . '"></i> ' . htmlspecialchars($statusLabel) . '</div>';
            $out .= '<select name="status" class="review-select"><option value="for_review"' . $selFor . '>For Review</option>';
            $out .= '<option value="cleared"' . $selClear . ($canApproveGroup ? '' : ' disabled') . '>Approved</option>';
            $out .= '<option value="rejected"' . $selRej . '>Disapproved</option></select>';
            $out .= '<input type="text" name="reason" class="reason-input" placeholder="Reason (optional)">';
            $out .= '<button class="save-btn" type="submit"><i class="fas fa-save"></i> Save</button>';
            if ($showsGroupSubordinates && !$canApproveGroup) {
                $groupShortLabel = $isSasOffice ? 'SAS' : 'Dean';
                $out .= '<div style="width:100%;font-size:0.72rem;color:#b45309;">All ' . $groupShortLabel . ' units must clear this student before <strong>Approved</strong> is available.</div>';
            }
            if ($missingSignatorySignature) {
                $out .= '<div style="width:100%;font-size:0.72rem;color:#b45309;">Upload e-signature first to allow <strong>Approved</strong>.</div>';
            }
            $out .= '</form></div>';
        }
    }
    $out .= '</div></div></div>';
    $out .= '<div class="footer-note"><i class="fas fa-shield-alt"></i> Authorized Signatory · Actions are recorded for audit</div>';
    $out .= '</div></div>';
    $out .= '<script>(function(){var byCollege=' . $programsJson . ';var c=document.getElementById("signatory_filter_college_id");var p=document.getElementById("signatory_filter_program_id");if(!c||!p)return;function refill(preserveSel){var id=parseInt(c.value,10)||0;var prev=preserveSel!==undefined?preserveSel:0;p.innerHTML="<option value=\\"0\\">All programs</option>";if(!byCollege[id])return;(byCollege[id]||[]).forEach(function(pr){var o=document.createElement("option");o.value=String(pr.id);o.textContent=pr.name+" ("+pr.code+")";if(prev&&parseInt(o.value,10)===prev)o.selected=true;p.appendChild(o);});}c.addEventListener("change",function(){refill(0);});})();</script>';

    return $out;
}

function renderAdminDashboard(array $semester, array $requirements, array $students, array $deadlineStatus = []): string
{
    $totalStudents = count($students);
    $totalRequirements = count($requirements);
    $clearedStudents = 0;
    $pendingStudents = 0;
    foreach ($students as $student) {
        $status = (string) ($student['overall_status'] ?? '');
        if ($status === 'cleared') {
            $clearedStudents++;
        } elseif ($status === 'pending') {
            $pendingStudents++;
        }
    }

    $inner = renderClearanceDeadlineBanner($deadlineStatus);
    if ($deadlineStatus['has_deadline'] ?? false) {
        $inner .= '<div class="panel mb-3"><div class="panel-header"><h3><i class="fas fa-calendar-check"></i>Completion Deadline</h3></div><div class="p-3">';
        $inner .= '<p class="mb-2"><strong>Due date:</strong> ' . htmlspecialchars((string) ($deadlineStatus['due_date_label'] ?? '')) . '</p>';
        $inner .= '<p class="mb-0 text-muted">Status: ' . htmlspecialchars((string) ($deadlineStatus['status_label'] ?? '')) . '. ';
        $inner .= '<a href="' . hpath('/admin/semester') . '">Manage deadline settings</a></p></div></div>';
    }

    $inner .= '<div class="cards-grid">';
    $inner .= '<div class="stat-card"><div class="stat-title"><i class="fas fa-users me-1"></i>Total Students</div><div class="stat-value">' . $totalStudents . '</div></div>';
    $inner .= '<div class="stat-card"><div class="stat-title"><i class="fas fa-check-circle me-1"></i>Fully Cleared</div><div class="stat-value">' . $clearedStudents . '</div></div>';
    $inner .= '<a class="stat-card text-decoration-none" href="' . hpath('/admin/pending-departments') . '"><div class="stat-title"><i class="fas fa-hourglass-half me-1"></i>Pending</div><div class="stat-value">' . $pendingStudents . '</div></a>';
    $inner .= '<div class="stat-card"><div class="stat-title"><i class="fas fa-university me-1"></i>Requirements Total</div><div class="stat-value">' . $totalRequirements . '</div></div>';
    $inner .= '</div>';

    $inner .= '<div class="student-selector" style="margin-bottom:24px;">';
    $inner .= '<span style="display:block;font-size:.75rem;font-weight:600;text-transform:uppercase;color:#4b6b8f;margin-bottom:8px;letter-spacing:.3px;">Admin shortcuts</span>';
    $inner .= '<a class="btn btn-outline-secondary me-2 mb-2" href="' . hpath('/admin/signatories') . '"><i class="fas fa-pen-signature me-1"></i>Add / Assign Signatory</a>';
    $inner .= '<a class="btn btn-outline-secondary me-2 mb-2" href="' . hpath('/admin/register-students') . '"><i class="fas fa-user-plus me-1"></i>Register Students</a>';
    $inner .= '<a class="btn btn-outline-secondary me-2 mb-2" href="' . hpath('/admin/pending-departments') . '"><i class="fas fa-hourglass-half me-1"></i>Pending Departments</a>';
    $inner .= '<a class="btn btn-outline-secondary mb-2" href="' . hpath('/admin/colleges-programs') . '"><i class="fas fa-school me-1"></i>Colleges &amp; Programs</a>';
    $inner .= '</div>';

    $inner .= '<div class="student-selector">';
    $inner .= '<form method="GET" action="' . hpath('/admin/final-clearance') . '" class="w-100 d-flex flex-wrap align-items-end gap-3">';
    $inner .= '<div class="form-group"><label><i class="fas fa-user-graduate me-1"></i>Select Student</label><select class="admin-select" name="student_id" required>';
    $inner .= '<option value="">- Choose a student -</option>';
    foreach ($students as $student) {
        $parts = array_filter([
            trim((string) ($student['college_name'] ?? '')),
            trim((string) ($student['program_name'] ?? '')),
        ]);
        $cp = implode(' / ', $parts);
        $yl = trim((string) ($student['year_level'] ?? ''));
        $ylPart = $yl !== '' ? ' · Yr ' . $yl : '';
        $campusPart = formatStudentCampusCell($student['campus'] ?? null);
        $campusPart = $campusPart !== '—' ? ' · ' . $campusPart : '';
        $label = sprintf(
            '%s, %s (%s)%s%s%s',
            (string) $student['last_name'],
            (string) $student['first_name'],
            (string) ($student['student_no'] ?: 'N/A'),
            $cp !== '' ? ' — ' . $cp : '',
            $ylPart,
            $campusPart
        );
        $inner .= '<option value="' . (int) $student['id'] . '">' . htmlspecialchars($label) . '</option>';
    }
    $inner .= '</select></div>';
    $inner .= '<div class="form-group" style="flex:0.7;min-width:180px;"><label>&nbsp;</label><button class="generate-btn" type="submit"><i class="fas fa-stamp"></i>Generate Final Clearance</button></div>';
    $inner .= '</form></div>';

    $inner .= '<div class="panel"><div class="panel-header"><h3><i class="fas fa-tasks" style="color:#2c6e9e;"></i>Current Requirements</h3><span class="badge-requirements">' . $totalRequirements . ' active items</span></div>';
    if ($requirements === []) {
        $inner .= '<div class="p-3 text-muted">No active requirements yet.</div>';
    } else {
        foreach ($requirements as $requirement) {
            $inner .= '<div class="requirement-item">';
            $inner .= '<div class="req-name"><i class="fas fa-clipboard-check"></i>' . htmlspecialchars((string) $requirement['office_name']) . ' - ' . htmlspecialchars((string) $requirement['title']) . '</div>';
            $inner .= '<span class="req-status">Active</span></div>';
        }
    }
    $inner .= '</div>';

    $inner .= '<div class="panel"><div class="panel-header"><h3><i class="fas fa-chart-line"></i>Clearance Reports</h3><a href="' . hpath('/admin/reports') . '" class="text-decoration-none text-secondary"><i class="fas fa-up-right-from-square"></i> Open full report</a></div>';
    $inner .= '<div style="overflow-x:auto;"><table class="report-table"><thead><tr><th>Student ID</th><th>Name</th><th>Campus</th><th>College</th><th>Program</th><th>Year</th><th>Email</th><th>Status</th></tr></thead><tbody>';
    if ($students === []) {
        $inner .= '<tr><td colspan="8" class="text-center text-muted">No student records found.</td></tr>';
    } else {
        foreach (array_slice($students, 0, 8) as $row) {
            $status = (string) ($row['overall_status'] ?? 'pending');
            $statusClass = $status === 'cleared' ? 'status-cleared' : 'status-pending';
            $inner .= '<tr>';
            $inner .= '<td>' . htmlspecialchars((string) ($row['student_no'] ?: 'N/A')) . '</td>';
            $inner .= '<td>' . htmlspecialchars((string) ($row['last_name'] . ', ' . $row['first_name'])) . '</td>';
            $inner .= '<td>' . formatStudentCampusCell($row['campus'] ?? null) . '</td>';
            $collegeCell = trim((string) ($row['college_name'] ?? ''));
            $programCell = trim((string) ($row['program_name'] ?? ''));
            $inner .= '<td>' . ($collegeCell !== '' ? htmlspecialchars($collegeCell) : '—') . '</td>';
            $inner .= '<td>' . ($programCell !== '' ? htmlspecialchars($programCell) : '—') . '</td>';
            $inner .= '<td>' . formatYearLevelCell($row['year_level'] ?? null) . '</td>';
            $inner .= '<td>' . htmlspecialchars((string) $row['email']) . '</td>';
            $inner .= '<td><span class="status-pill ' . $statusClass . '">' . htmlspecialchars(strtoupper($status)) . '</span></td>';
            $inner .= '</tr>';
        }
    }
    $inner .= '</tbody></table></div></div>';

    return renderAdminShell('/dashboard', $semester, $inner);
}

function renderAdminCollegesProgramsPage(array $semester, array $colleges, array $programs, ?array $editProgram): string
{
    $inner = '<div class="row g-4">';
    $inner .= '<div class="col-lg-6"><div class="panel mb-0"><div class="panel-header"><h3><i class="fas fa-plus-circle"></i>Add college</h3></div><div class="p-4">';
    $inner .= '<p class="small text-muted mb-3">Short unique code (e.g. COE) and full college name. Codes are stored in uppercase.</p>';
    $inner .= '<form method="POST" action="' . hpath('/admin/college') . '" class="row g-2">';
    $inner .= '<div class="col-md-4"><label class="form-label">Code</label><input class="form-control" name="code" maxlength="40" required placeholder="COE"></div>';
    $inner .= '<div class="col-md-8"><label class="form-label">Name</label><input class="form-control" name="name" maxlength="191" required placeholder="College of Engineering"></div>';
    $inner .= '<div class="col-12"><button class="btn btn-success" type="submit">Add college</button></div></form></div></div></div>';

    $isProgramEdit = $editProgram !== null;
    $programFormAction = $isProgramEdit ? hpath('/admin/program/update') : hpath('/admin/program');
    $programTitle = $isProgramEdit ? 'Edit program' : 'Add program';
    $programCode = htmlspecialchars((string) ($editProgram['code'] ?? ''));
    $programName = htmlspecialchars((string) ($editProgram['name'] ?? ''));
    $programCollegeId = (int) ($editProgram['college_id'] ?? 0);

    $inner .= '<div class="col-lg-6"><div class="panel mb-0"><div class="panel-header d-flex justify-content-between align-items-center flex-wrap gap-2"><h3 class="mb-0"><i class="fas ' . ($isProgramEdit ? 'fa-pen' : 'fa-plus-circle') . '"></i>' . $programTitle . '</h3>';
    if ($isProgramEdit) {
        $inner .= '<a class="btn btn-sm btn-outline-secondary" href="' . hpath('/admin/colleges-programs') . '">Cancel</a>';
    }
    $inner .= '</div><div class="p-4">';
    $inner .= '<p class="small text-muted mb-3">Programs belong to one college. Code must be unique within that college (e.g. BSCE).</p>';
    $inner .= '<form method="POST" action="' . $programFormAction . '" class="row g-2">';
    if ($isProgramEdit) {
        $inner .= '<input type="hidden" name="program_id" value="' . (int) $editProgram['id'] . '">';
    }
    $inner .= '<div class="col-12"><label class="form-label">College</label><select class="form-select" name="college_id" required>';
    $inner .= '<option value="">Select college</option>';
    foreach ($colleges as $c) {
        if ((int) ($c['is_active'] ?? 0) !== 1) {
            continue;
        }
        $selected = $programCollegeId === (int) $c['id'] ? ' selected' : '';
        $inner .= '<option value="' . (int) $c['id'] . '"' . $selected . '>' . htmlspecialchars((string) $c['name']) . '</option>';
    }
    $inner .= '</select></div>';
    $inner .= '<div class="col-md-4"><label class="form-label">Code</label><input class="form-control" name="code" maxlength="40" required placeholder="BSCE" value="' . $programCode . '"></div>';
    $inner .= '<div class="col-md-8"><label class="form-label">Name</label><input class="form-control" name="name" maxlength="191" required placeholder="BS Civil Engineering" value="' . $programName . '"></div>';
    $inner .= '<div class="col-12"><button class="btn btn-success" type="submit">' . ($isProgramEdit ? 'Save changes' : 'Add program') . '</button></div></form></div></div></div>';
    $inner .= '</div>';

    $inner .= '<div class="panel mt-4"><div class="panel-header"><h3><i class="fas fa-list"></i>Colleges</h3></div><div class="p-0">';
    if ($colleges === []) {
        $inner .= '<div class="p-4 text-muted">No colleges yet.</div>';
    } else {
        $inner .= '<div class="table-responsive"><table class="report-table mb-0"><thead><tr><th>Code</th><th>Name</th><th>Active</th></tr></thead><tbody>';
        foreach ($colleges as $c) {
            $inner .= '<tr><td>' . htmlspecialchars((string) $c['code']) . '</td><td>' . htmlspecialchars((string) $c['name']) . '</td>';
            $inner .= '<td>' . (((int) ($c['is_active'] ?? 0) === 1) ? 'Yes' : 'No') . '</td></tr>';
        }
        $inner .= '</tbody></table></div>';
    }
    $inner .= '</div></div>';

    $inner .= '<div class="panel mt-4"><div class="panel-header"><h3><i class="fas fa-list"></i>Programs</h3></div><div class="p-0">';
    if ($programs === []) {
        $inner .= '<div class="p-4 text-muted">No programs yet. Add a college first, then programs under it.</div>';
    } else {
        $inner .= '<div class="table-responsive"><table class="report-table mb-0"><thead><tr><th>College</th><th>Code</th><th>Program name</th><th>Active</th><th>Actions</th></tr></thead><tbody>';
        foreach ($programs as $p) {
            $inner .= '<tr><td>' . htmlspecialchars((string) $p['college_name']) . '</td>';
            $inner .= '<td>' . htmlspecialchars((string) $p['code']) . '</td>';
            $inner .= '<td>' . htmlspecialchars((string) $p['name']) . '</td>';
            $isActive = (int) ($p['is_active'] ?? 0) === 1;
            $inner .= '<td>' . ($isActive ? 'Yes' : 'No') . '</td>';
            $inner .= '<td><div class="d-flex gap-2">';
            $inner .= '<a class="btn btn-sm btn-outline-success" href="' . hpath('/admin/colleges-programs') . '?edit_program_id=' . (int) $p['id'] . '" title="Edit program"><i class="fas fa-pen"></i></a>';
            if ($isActive) {
                $inner .= '<form method="POST" action="' . hpath('/admin/program/delete') . '" onsubmit="return confirm(\'Delete this program?\');">';
                $inner .= '<input type="hidden" name="program_id" value="' . (int) $p['id'] . '">';
                $inner .= '<button class="btn btn-sm btn-outline-danger" type="submit" title="Delete program"><i class="fas fa-trash-alt"></i></button></form>';
            }
            $inner .= '</div></td></tr>';
        }
        $inner .= '</tbody></table></div>';
    }
    $inner .= '</div></div>';

    return renderAdminShell('/admin/colleges-programs', $semester, $inner);
}

function renderAdminRegisterStudentsPage(
    array $semester,
    array $colleges,
    array $programsByCollege,
    array $posted,
    array $studentsAll,
    ?array $editStudent
): string {
    $sn = htmlspecialchars((string) ($posted['student_no'] ?? ''));
    $fn = htmlspecialchars((string) ($posted['first_name'] ?? ''));
    $ln = htmlspecialchars((string) ($posted['last_name'] ?? ''));
    $em = htmlspecialchars((string) ($posted['email'] ?? ''));
    $ylPosted = (string) ($posted['year_level'] ?? '');
    $acctPosted = (string) ($posted['student_account_type'] ?? '');
    $orgPosted = (string) ($posted['student_org_position'] ?? '');
    $stayingPosted = (string) ($posted['student_staying'] ?? '');
    $campusPosted = (string) ($posted['campus'] ?? '');
    $collegePosted = (int) ($posted['college_id'] ?? 0);
    $programsJson = json_encode($programsByCollege, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE);
    if ($programsJson === false) {
        $programsJson = '{}';
    }

    $inner = '';
    if ($editStudent !== null) {
        $eCid = (int) ($editStudent['college_id'] ?? 0);
        $ePid = (int) ($editStudent['program_id'] ?? 0);
        $inner .= '<div class="panel"><div class="panel-header d-flex justify-content-between align-items-center flex-wrap gap-2"><h3 class="mb-0"><i class="fas fa-edit"></i>Edit Student</h3>';
        $inner .= '<a class="btn btn-sm btn-outline-secondary" href="' . hpath('/admin/register-students') . '">Cancel</a></div><div class="p-4">';
        $inner .= '<form method="POST" action="' . hpath('/admin/student/update') . '" class="row g-3" style="max-width:720px;">';
        $inner .= '<input type="hidden" name="user_id" value="' . (int) $editStudent['id'] . '">';
        $inner .= '<div class="col-md-6"><label class="form-label">Student number</label><input class="form-control" name="student_no" value="' . htmlspecialchars((string) ($editStudent['student_no'] ?? '')) . '" required></div>';
        $inner .= '<div class="col-md-6"><label class="form-label">Email (login)</label><input class="form-control" type="email" name="email" value="' . htmlspecialchars((string) $editStudent['email']) . '" required></div>';
        $inner .= '<div class="col-md-6"><label class="form-label">First name</label><input class="form-control" name="first_name" value="' . htmlspecialchars((string) $editStudent['first_name']) . '" required></div>';
        $inner .= '<div class="col-md-6"><label class="form-label">Last name</label><input class="form-control" name="last_name" value="' . htmlspecialchars((string) $editStudent['last_name']) . '" required></div>';
        $inner .= '<div class="col-md-6"><label class="form-label">College</label><select class="form-select" name="college_id" id="edit_college_id" required>';
        $inner .= '<option value="">Select college</option>';
        foreach ($colleges as $college) {
            $cid = (int) $college['id'];
            $sel = $eCid === $cid ? ' selected' : '';
            $inner .= '<option value="' . $cid . '"' . $sel . '>' . htmlspecialchars((string) $college['name']) . '</option>';
        }
        $inner .= '</select></div>';
        $inner .= '<div class="col-md-6"><label class="form-label">Program</label><select class="form-select" name="program_id" id="edit_program_id" required>';
        $inner .= '<option value="">Select program</option>';
        if ($eCid > 0 && isset($programsByCollege[$eCid])) {
            foreach ($programsByCollege[$eCid] as $prog) {
                $pid = (int) $prog['id'];
                $sel = $ePid === $pid ? ' selected' : '';
                $inner .= '<option value="' . $pid . '"' . $sel . '>' . htmlspecialchars($prog['name'] . ' (' . $prog['code'] . ')') . '</option>';
            }
        }
        $inner .= '</select><div class="form-text">Programs update when you change college.</div></div>';
        $eCampus = (string) ($editStudent['campus'] ?? '');
        $inner .= '<div class="col-md-6"><label class="form-label">Campus</label>';
        $inner .= renderStudentCampusSelect('campus', $eCampus, true) . '</div>';
        $eYl = (string) ($editStudent['year_level'] ?? '');
        $inner .= '<div class="col-md-6"><label class="form-label">Year level</label>';
        $inner .= renderYearLevelSelect('year_level', $eYl, true) . '</div>';
        $eAcct = (string) ($editStudent['student_account_type'] ?? '');
        $inner .= '<div class="col-md-6"><label class="form-label">Student account</label>';
        $inner .= renderStudentAccountTypeSelect('student_account_type', $eAcct, true) . '</div>';
        $eOrg = (string) ($editStudent['student_org_position'] ?? '');
        $inner .= '<div class="col-md-6"><label class="form-label">Student org. position</label>';
        $inner .= renderStudentOrgPositionSelect('student_org_position', $eOrg, true) . '</div>';
        $eStaying = (string) ($editStudent['student_staying'] ?? '');
        $inner .= '<div class="col-md-6"><label class="form-label">Students staying</label>';
        $inner .= renderStudentStayingSelect('student_staying', $eStaying, true) . '</div>';
        $inner .= '<div class="col-md-6"><label class="form-label">New password</label><input class="form-control" type="password" name="new_password" autocomplete="new-password" placeholder="Leave blank to keep current">';
        $inner .= '<div class="form-text">Optional. Min 8 characters if changing.</div></div>';
        $inner .= '<div class="col-12 d-flex gap-2"><button class="btn btn-success" type="submit">Save changes</button>';
        $inner .= '<a class="btn btn-outline-secondary" href="' . hpath('/admin/register-students') . '">Cancel</a></div></form></div></div>';
    }

    $inner .= '<div class="panel' . ($editStudent !== null ? ' mt-4' : '') . '"><div class="panel-header"><h3><i class="fas fa-user-plus"></i>Register Student</h3></div><div class="p-4">';
    $inner .= '<p class="small text-muted mb-3">Create a student account linked to a campus, college, and program. The student signs in with the email and initial password you set here.</p>';
    $inner .= '<form method="POST" action="' . hpath('/admin/register-students') . '" class="row g-3" style="max-width:720px;" id="register-student-form">';
    $inner .= '<div class="col-md-6"><label class="form-label">Student number</label><input class="form-control" name="student_no" value="' . $sn . '" required></div>';
    $inner .= '<div class="col-md-6"><label class="form-label">Email (login)</label><input class="form-control" type="email" name="email" value="' . $em . '" required></div>';
    $inner .= '<div class="col-md-6"><label class="form-label">First name</label><input class="form-control" name="first_name" value="' . $fn . '" required></div>';
    $inner .= '<div class="col-md-6"><label class="form-label">Last name</label><input class="form-control" name="last_name" value="' . $ln . '" required></div>';
    $inner .= '<div class="col-md-6"><label class="form-label">College</label><select class="form-select" name="college_id" id="register_college_id" required>';
    $inner .= '<option value="">Select college</option>';
    foreach ($colleges as $college) {
        $cid = (int) $college['id'];
        $selected = $collegePosted === $cid ? ' selected' : '';
        $inner .= '<option value="' . $cid . '"' . $selected . '>' . htmlspecialchars((string) $college['name']) . '</option>';
    }
    $inner .= '</select></div>';
    $inner .= '<div class="col-md-6"><label class="form-label">Program</label><select class="form-select" name="program_id" id="register_program_id" required>';
    $inner .= '<option value="">Select program</option>';
    if ($collegePosted > 0 && isset($programsByCollege[$collegePosted])) {
        $programPosted = (int) ($posted['program_id'] ?? 0);
        foreach ($programsByCollege[$collegePosted] as $prog) {
            $pid = (int) $prog['id'];
            $sel = $programPosted === $pid ? ' selected' : '';
            $label = htmlspecialchars($prog['name'] . ' (' . $prog['code'] . ')');
            $inner .= '<option value="' . $pid . '"' . $sel . '>' . $label . '</option>';
        }
    }
    $inner .= '</select><div class="form-text">Programs update when you change college.</div></div>';
    $inner .= '<div class="col-md-6"><label class="form-label">Campus</label>';
    $inner .= renderStudentCampusSelect('campus', $campusPosted, true) . '</div>';
    $inner .= '<div class="col-md-6"><label class="form-label">Year level</label>';
    $inner .= renderYearLevelSelect('year_level', $ylPosted, true) . '</div>';
    $inner .= '<div class="col-md-6"><label class="form-label">Student account</label>';
    $inner .= renderStudentAccountTypeSelect('student_account_type', $acctPosted, true) . '</div>';
    $inner .= '<div class="col-md-6"><label class="form-label">Student org. position</label>';
    $inner .= renderStudentOrgPositionSelect('student_org_position', $orgPosted, true) . '</div>';
    $inner .= '<div class="col-md-6"><label class="form-label">Students staying</label>';
    $inner .= renderStudentStayingSelect('student_staying', $stayingPosted, true) . '</div>';
    $inner .= '<div class="col-md-6"><label class="form-label">Initial password</label><input class="form-control" type="password" name="password" minlength="8" autocomplete="new-password" required>';
    $inner .= '<div class="form-text">At least 8 characters. Student may change it later if you add that feature.</div></div>';
    $inner .= '<div class="col-12"><button class="btn btn-success" type="submit"><i class="fas fa-user-check me-1"></i>Register student</button></div>';
    $inner .= '</form></div></div>';

    $inner .= '<div class="panel mt-4"><div class="panel-header"><h3><i class="fas fa-file-csv"></i>Bulk import (Excel → CSV)</h3></div><div class="p-4">';
    $inner .= '<p class="small mb-3"><a class="btn btn-sm btn-outline-secondary" href="' . hpath('/admin/download-students-csv-template') . '"><i class="fas fa-download me-1"></i>Download CSV template</a></p>';
    $inner .= '<p class="small text-muted mb-3">Use one <strong>full_name</strong> column in Excel (e.g. <em>Maria Santos</em>). The last word becomes the last name; the rest is the first name. Required <strong>campus</strong>: <em>puerto_princesa</em>, <em>quezon</em>, <em>rio_tuba</em>, <em>el_nido</em>, <em>canique</em>, or <em>busuanga</em> (full campus names also accepted). Optional <strong>student_account_type</strong>: <em>paying_tuition</em> or <em>not_paying_tuition</em> (defaults to paying if omitted). Optional <strong>student_org_position</strong>: <em>president</em>, <em>vice_president</em>, <em>treasurer</em>, <em>secretary</em>, <em>auditor</em>, or <em>na</em> (defaults to N/A if omitted). Optional <strong>student_staying</strong>: <em>wpu_dormitory</em>, <em>outside_dormitory</em>, or <em>commuter</em> (defaults to commuter if omitted).</p>';
    $inner .= '<form method="POST" action="' . hpath('/admin/import-students-csv') . '" enctype="multipart/form-data" class="d-flex flex-wrap align-items-end gap-3">';
    $inner .= '<div><label class="form-label">CSV file</label><input class="form-control" type="file" name="csv" accept=".csv,text/csv" required></div>';
    $inner .= '<button class="btn btn-success" type="submit"><i class="fas fa-upload me-1"></i>Import CSV</button></form></div></div>';

    $inner .= '<div class="panel mt-4"><div class="panel-header d-flex justify-content-between align-items-center flex-wrap gap-2">';
    $inner .= '<h3 class="mb-0"><i class="fas fa-list"></i>Registered students</h3>';
    if ($studentsAll !== []) {
        $inner .= '<form method="POST" action="' . hpath('/admin/students/delete-all') . '" class="d-inline" onsubmit="return confirm(\'Delete ALL student accounts and their clearance data? This cannot be undone.\');">';
        $inner .= '<button class="btn btn-sm btn-outline-danger" type="submit"><i class="fas fa-trash-alt me-1"></i>Delete all</button></form>';
    }
    $inner .= '</div><div class="p-0">';
    if ($studentsAll === []) {
        $inner .= '<div class="p-4 text-muted">No student accounts yet.</div>';
    } else {
        $inner .= '<form method="POST" action="' . hpath('/admin/students/delete-selected') . '" id="students-bulk-form" onsubmit="return confirmStudentDeleteSelected(this);">';
        $inner .= '<div class="p-3 border-bottom d-flex flex-wrap align-items-center gap-2">';
        $inner .= '<button class="btn btn-sm btn-danger" type="submit" id="delete-selected-btn" disabled><i class="fas fa-trash me-1"></i>Delete selected</button>';
        $inner .= '<span class="small text-muted" id="selected-count-label">Select students to delete.</span>';
        $inner .= '</div>';
        $inner .= '<div class="table-responsive"><table class="report-table mb-0"><thead><tr>';
        $inner .= '<th style="width:42px;"><input class="form-check-input" type="checkbox" id="select-all-students" title="Select all" aria-label="Select all students"></th>';
        $inner .= '<th>Student No.</th><th>Name</th><th>Email</th><th>Campus</th><th>College</th><th>Program</th><th>Year</th><th>Account</th><th>Org Position</th><th>Staying</th><th>Clearance</th><th>Status</th><th style="width:200px;">Actions</th>';
        $inner .= '</tr></thead><tbody>';
        foreach ($studentsAll as $st) {
            $sid = (int) $st['id'];
            $active = (int) ($st['is_active'] ?? 0) === 1;
            $cname = trim((string) ($st['college_name'] ?? ''));
            $pname = trim((string) ($st['program_name'] ?? ''));
            $ovRaw = (string) ($st['overall_status'] ?? 'pending');
            $ov = strtoupper($ovRaw);
            $ovClass = strtolower($ovRaw) === 'cleared' ? 'status-cleared' : 'status-pending';
            $inner .= '<tr>';
            $inner .= '<td><input class="form-check-input student-select-cb" type="checkbox" name="student_ids[]" value="' . $sid . '" aria-label="Select student"></td>';
            $inner .= '<td>' . htmlspecialchars((string) ($st['student_no'] ?: '—')) . '</td>';
            $inner .= '<td>' . htmlspecialchars((string) ($st['last_name'] . ', ' . $st['first_name'])) . '</td>';
            $inner .= '<td>' . htmlspecialchars((string) $st['email']) . '</td>';
            $inner .= '<td>' . formatStudentCampusCell($st['campus'] ?? null) . '</td>';
            $inner .= '<td>' . ($cname !== '' ? htmlspecialchars($cname) : '—') . '</td>';
            $inner .= '<td>' . ($pname !== '' ? htmlspecialchars($pname) : '—') . '</td>';
            $inner .= '<td>' . formatYearLevelCell($st['year_level'] ?? null) . '</td>';
            $inner .= '<td>' . formatStudentAccountTypeCell($st['student_account_type'] ?? null) . '</td>';
            $inner .= '<td>' . formatStudentOrgPositionCell($st['student_org_position'] ?? null) . '</td>';
            $inner .= '<td>' . formatStudentStayingCell($st['student_staying'] ?? null) . '</td>';
            $inner .= '<td><span class="status-pill ' . $ovClass . '">' . htmlspecialchars($ov) . '</span></td>';
            $inner .= '<td>' . ($active ? '<span class="status-pill status-cleared">Active</span>' : '<span class="status-pill status-pending">Inactive</span>') . '</td>';
            $inner .= '<td><div class="d-flex flex-wrap gap-1">';
            $inner .= '<a class="btn btn-sm btn-outline-success" href="' . hpath('/admin/register-students') . '?edit_student_id=' . $sid . '">Edit</a>';
            if ($active) {
                $inner .= '<form method="POST" action="' . hpath('/admin/student/deactivate') . '" class="d-inline" onsubmit="return confirm(\'Deactivate this student? They cannot log in until reactivated.\');">';
                $inner .= '<input type="hidden" name="user_id" value="' . $sid . '">';
                $inner .= '<button class="btn btn-sm btn-outline-danger" type="submit">Deactivate</button></form>';
            } else {
                $inner .= '<form method="POST" action="' . hpath('/admin/student/reactivate') . '" class="d-inline">';
                $inner .= '<input type="hidden" name="user_id" value="' . $sid . '">';
                $inner .= '<button class="btn btn-sm btn-outline-secondary" type="submit">Reactivate</button></form>';
            }
            $inner .= '</div></td></tr>';
        }
        $inner .= '</tbody></table></div></form>';
    }
    $inner .= '</div></div>';

    $inner .= '<script>(function(){var byCollege=' . $programsJson . ';function wire(c,p){if(!c||!p)return;function refill(){var id=parseInt(c.value,10)||0;p.innerHTML="<option value=\\"\\">Select program</option>";if(!byCollege[id])return;(byCollege[id]||[]).forEach(function(pr){var o=document.createElement("option");o.value=String(pr.id);o.textContent=pr.name+" ("+pr.code+")";p.appendChild(o);});}c.addEventListener("change",refill);}wire(document.getElementById("register_college_id"),document.getElementById("register_program_id"));wire(document.getElementById("edit_college_id"),document.getElementById("edit_program_id"));var selectAll=document.getElementById("select-all-students");var bulkForm=document.getElementById("students-bulk-form");if(selectAll&&bulkForm){var cbs=function(){return bulkForm.querySelectorAll(".student-select-cb");};var btn=document.getElementById("delete-selected-btn");var label=document.getElementById("selected-count-label");function sync(){var boxes=cbs();var n=0;boxes.forEach(function(cb){if(cb.checked)n++;});if(btn)btn.disabled=n===0;if(label)label.textContent=n===0?"Select students to delete.":(n===1?"1 student selected.":n+" students selected.");var all=boxes.length>0&&n===boxes.length;selectAll.indeterminate=n>0&&!all;selectAll.checked=all;}selectAll.addEventListener("change",function(){cbs().forEach(function(cb){cb.checked=selectAll.checked;});sync();});bulkForm.addEventListener("change",function(e){if(e.target&&e.target.classList&&e.target.classList.contains("student-select-cb"))sync();});sync();}window.confirmStudentDeleteSelected=function(form){var n=form.querySelectorAll(".student-select-cb:checked").length;if(n===0){alert("Select at least one student to delete.");return false;}return confirm("Delete "+n+" selected student account"+(n===1?"":"s")+" and their clearance data? This cannot be undone.");};})();</script>';

    return renderAdminShell('/admin/register-students', $semester, $inner);
}

function renderAdminSettingsPage(array $semester, array $profile): string
{
    $photoPath = trim((string) ($profile['profile_photo_path'] ?? ''));
    $inner = '<div class="row g-4">';
    $inner .= '<div class="col-lg-5"><div class="panel mb-0"><div class="panel-header"><h3><i class="fas fa-camera"></i>Profile Photo</h3></div><div class="p-4">';
    $inner .= '<div class="d-flex flex-column align-items-center text-center mb-3">';
    if ($photoPath !== '') {
        $inner .= '<img class="admin-settings-preview mb-3" src="' . hpath('/' . ltrim($photoPath, '/')) . '" alt="Profile photo">';
    } else {
        $inner .= '<div class="admin-settings-preview-placeholder mb-3"><i class="fas fa-user" aria-hidden="true"></i></div>';
    }
    $inner .= '<p class="small text-muted mb-0">Upload a square photo (PNG, JPG, or WEBP, max 3MB).</p></div>';
    $inner .= '<form method="POST" action="' . hpath('/admin/settings/photo') . '" enctype="multipart/form-data" class="row g-3">';
    $inner .= '<div class="col-12"><label class="form-label">Choose photo</label><input class="form-control" type="file" name="profile_photo" accept="image/png,image/jpeg,image/webp"></div>';
    if ($photoPath !== '') {
        $inner .= '<div class="col-12"><div class="form-check"><input class="form-check-input" type="checkbox" name="remove_photo" value="1" id="remove_admin_photo"><label class="form-check-label" for="remove_admin_photo">Remove current photo</label></div></div>';
    }
    $inner .= '<div class="col-12"><button class="btn btn-success" type="submit"><i class="fas fa-upload me-1"></i>Save photo</button></div>';
    $inner .= '</form></div></div></div>';

    $inner .= '<div class="col-lg-7"><div class="panel mb-0"><div class="panel-header"><h3><i class="fas fa-user-edit"></i>Edit Profile</h3></div><div class="p-4">';
    $inner .= '<form method="POST" action="' . hpath('/admin/settings/profile') . '" class="row g-3" style="max-width:720px;">';
    $inner .= '<div class="col-md-6"><label class="form-label">First name</label><input class="form-control" name="first_name" value="' . htmlspecialchars((string) $profile['first_name']) . '" required></div>';
    $inner .= '<div class="col-md-6"><label class="form-label">Last name</label><input class="form-control" name="last_name" value="' . htmlspecialchars((string) $profile['last_name']) . '" required></div>';
    $inner .= '<div class="col-12"><label class="form-label">Email (login)</label><input class="form-control" type="email" name="email" value="' . htmlspecialchars((string) $profile['email']) . '" required></div>';
    $inner .= '<div class="col-12"><hr class="my-1"><h4 class="h6 text-muted mb-0">Change password</h4><p class="small text-muted">Leave blank to keep your current password.</p></div>';
    $inner .= '<div class="col-md-4"><label class="form-label">Current password</label><input class="form-control" type="password" name="current_password" autocomplete="current-password"></div>';
    $inner .= '<div class="col-md-4"><label class="form-label">New password</label><input class="form-control" type="password" name="new_password" minlength="8" autocomplete="new-password"></div>';
    $inner .= '<div class="col-md-4"><label class="form-label">Confirm new password</label><input class="form-control" type="password" name="confirm_password" minlength="8" autocomplete="new-password"></div>';
    $inner .= '<div class="col-12"><button class="btn btn-success" type="submit"><i class="fas fa-save me-1"></i>Save profile</button></div>';
    $inner .= '</form></div></div></div>';
    $inner .= '</div>';

    return renderAdminShell('/admin/settings', $semester, $inner);
}

function renderAdminControlPanel(string $activePath): string
{
    $items = [
        '/dashboard' => ['Dashboard', 'fas fa-tachometer-alt'],
        '/admin/colleges-programs' => ['Colleges & Programs', 'fas fa-school'],
        '/admin/register-students' => ['Register Students', 'fas fa-user-plus'],
        '/admin/semester' => ['Create/Open Semester', 'fas fa-calendar-plus'],
        '/admin/add-requirement' => ['Add Requirement', 'fas fa-clipboard-list'],
        '/admin/signatories' => ['Add / Assign Signatory', 'fas fa-pen-signature'],
        '/admin/current-requirements' => ['Current Requirements', 'fas fa-tasks'],
        '/admin/final-clearance-tools' => ['Generate Final Clearance', 'fas fa-stamp'],
        '/admin/pending-departments' => ['Pending Departments', 'fas fa-hourglass-half'],
        '/admin/reports' => ['Clearance Reports', 'fas fa-file-alt'],
        '/admin/settings' => ['Account Settings', 'fas fa-user-cog'],
    ];

    $html = '<aside class="admin-sidebar"><div class="admin-sidebar-header"><div class="admin-sidebar-brand"><img src="' . hasset('wpu-logo.png') . '" alt="Western Philippines University"><div><h2>SAFE Clearance</h2><p>Office of Student Affairs</p></div></div></div><nav class="admin-nav">';
    foreach ($items as $path => $item) {
        [$label, $icon] = $item;
        $activeClass = $activePath === $path ? 'active' : '';
        $html .= '<a href="' . hpath($path) . '" class="' . htmlspecialchars($activeClass) . '"><i class="' . htmlspecialchars($icon) . '"></i><span>' . htmlspecialchars($label) . '</span></a>';
    }
    $html .= '</nav></aside>';
    return $html;
}

function renderAdminSemesterPage(array $semester, array $deadlineStatus = []): string
{
    $academicYearValue = trim((string) ($semester['academic_year'] ?? ''));
    if ($academicYearValue === 'N/A') {
        $academicYearValue = '';
    }
    $termValue = (string) ($semester['term'] ?? '1st');
    if (!in_array($termValue, ['1st', '2nd', 'summer'], true)) {
        $termValue = '1st';
    }
    $inner = '<div class="panel"><div class="panel-header"><h3><i class="fas fa-calendar-plus"></i>Create/Open Semester</h3></div><div class="p-4">';
    $inner .= '<p class="small text-muted mb-2">Set the academic year and term to open a new clearance cycle.</p>';
    $inner .= '<form method="POST" action="' . hpath('/admin/semester') . '">';
    $inner .= '<input class="form-control mb-2" name="academic_year" placeholder="2026-2027" value="' . htmlspecialchars($academicYearValue) . '" required>';
    $inner .= '<select class="form-select mb-2" name="term">';
    $inner .= '<option value="1st"' . ($termValue === '1st' ? ' selected' : '') . '>1st</option>';
    $inner .= '<option value="2nd"' . ($termValue === '2nd' ? ' selected' : '') . '>2nd</option>';
    $inner .= '<option value="summer"' . ($termValue === 'summer' ? ' selected' : '') . '>Summer</option>';
    $inner .= '</select>';
    $inner .= '<button class="btn btn-success">Save Semester</button></form>';
    $inner .= '</div></div>';

    if ((int) ($semester['id'] ?? 0) > 0) {
        $dueDateValue = trim((string) ($semester['ends_at'] ?? ''));
        $inner .= '<div class="panel mt-3"><div class="panel-header"><h3><i class="fas fa-calendar-check"></i>Completion Due Date</h3></div><div class="p-4">';
        $inner .= '<p class="small text-muted mb-3">Set when students and signatories must complete clearance. They will see this date on their dashboards and receive a daily reminder notification.</p>';
        $inner .= '<form method="POST" action="' . hpath('/admin/semester/deadline') . '" class="row g-2 align-items-end mb-3">';
        $inner .= '<div class="col-md-4"><label class="form-label">Due date</label><input class="form-control" type="date" name="completion_due_date" value="' . htmlspecialchars($dueDateValue) . '"></div>';
        $inner .= '<div class="col-md-8 d-flex flex-wrap gap-2"><button class="btn btn-success" type="submit">Save Due Date</button>';
        if ($dueDateValue !== '') {
            $inner .= '</div></form>';
            $inner .= '<form method="POST" action="' . hpath('/admin/semester/deadline') . '" class="d-inline mb-3">';
            $inner .= '<input type="hidden" name="completion_due_date" value="">';
            $inner .= '<button class="btn btn-outline-secondary" type="submit">Clear Due Date</button></form>';
        } else {
            $inner .= '</div></form>';
        }

        if ($deadlineStatus['has_deadline'] ?? false) {
            $inner .= renderClearanceDeadlineBanner($deadlineStatus);
            $inner .= '<p class="small text-muted mb-3">Students and signatories are notified once per day while a due date is set.</p>';
            if ($deadlineStatus['is_expired'] ?? false) {
                $inner .= '<div class="border rounded p-3 bg-light"><strong>After-deadline clearance window</strong>';
                $inner .= '<p class="small text-muted mb-2">Once the due date has passed, you can deactivate or reactivate clearance actions (uploads and signatory decisions).</p>';
                if ($deadlineStatus['is_window_open'] ?? false) {
                    $inner .= '<form method="POST" action="' . hpath('/admin/semester/clearance-window') . '" class="d-inline" onsubmit="return confirm(\'Deactivate the clearance window? Students cannot upload and signatories cannot record decisions until reactivated.\');">';
                    $inner .= '<input type="hidden" name="action" value="deactivate">';
                    $inner .= '<button class="btn btn-outline-danger" type="submit">Deactivate Clearance Window</button></form>';
                } else {
                    $inner .= '<form method="POST" action="' . hpath('/admin/semester/clearance-window') . '" class="d-inline">';
                    $inner .= '<input type="hidden" name="action" value="activate">';
                    $inner .= '<button class="btn btn-outline-success" type="submit">Reactivate Clearance Window</button></form>';
                }
                $inner .= '</div>';
            } else {
                $inner .= '<p class="small text-muted mb-0">The activate/deactivate controls will appear after the due date passes. Until then, clearance remains open.</p>';
            }
        } else {
            $inner .= '<p class="text-muted mb-0">No completion due date set yet.</p>';
        }
        $inner .= '</div></div>';
    }

    return renderAdminShell('/admin/semester', $semester, $inner);
}

function renderAdminAddRequirementPage(array $semester, array $offices): string
{
    $inner = '<div class="panel"><div class="panel-header"><h3><i class="fas fa-clipboard-list"></i>Add Requirement</h3></div><div class="p-4">';
    $inner .= '<form method="POST" action="' . hpath('/admin/requirement') . '" enctype="multipart/form-data"><select name="office_id" class="form-select mb-2">';
    foreach ($offices as $office) {
        $inner .= '<option value="' . (int) $office['id'] . '">' . htmlspecialchars($office['name']) . '</option>';
    }
    $inner .= '</select><input class="form-control mb-2" name="title" placeholder="Requirement title" required>';
    $inner .= '<textarea class="form-control mb-2" name="description" placeholder="Description"></textarea>';
    $inner .= '<input class="form-control mb-2" type="file" name="attachment">';
    $inner .= '<button class="btn btn-success">Add</button></form>';
    $inner .= '</div></div>';
    return renderAdminShell('/admin/add-requirement', $semester, $inner);
}

function renderAdminCurrentRequirementsPage(array $semester, array $offices, array $requirements, ?int $editRequirementId): string
{
    $inner = '<div class="panel"><div class="panel-header"><h3><i class="fas fa-tasks"></i>Current Requirements</h3></div><div class="p-4">';
    if (!$requirements) {
        $inner .= '<p class="text-muted mb-0">No requirements yet.</p>';
    } else {
        $editingRequirement = null;
        if ($editRequirementId !== null && $editRequirementId > 0) {
            foreach ($requirements as $row) {
                if ((int) $row['id'] === $editRequirementId) {
                    $editingRequirement = $row;
                    break;
                }
            }
        }

        if ($editingRequirement !== null) {
            $inner .= '<form method="POST" action="' . hpath('/admin/requirement/update') . '" enctype="multipart/form-data" class="border rounded p-3 mb-3 bg-light">';
            $inner .= '<input type="hidden" name="requirement_id" value="' . (int) $editingRequirement['id'] . '">';
            $inner .= '<div class="row g-2">';
            $inner .= '<div class="col-md-3"><label class="form-label">Office</label><select name="office_id" class="form-select">';
            foreach ($offices as $office) {
                $selected = ((int) $editingRequirement['office_id'] === (int) $office['id']) ? ' selected' : '';
                $inner .= '<option value="' . (int) $office['id'] . '"' . $selected . '>' . htmlspecialchars($office['name']) . '</option>';
            }
            $inner .= '</select></div>';
            $inner .= '<div class="col-md-3"><label class="form-label">Title</label><input class="form-control" name="title" value="' . htmlspecialchars((string) $editingRequirement['title']) . '" required></div>';
            $inner .= '<div class="col-md-4"><label class="form-label">Description</label><input class="form-control" name="description" value="' . htmlspecialchars((string) ($editingRequirement['description'] ?? '')) . '"></div>';
            $inner .= '<div class="col-md-2"><label class="form-label">Attachment</label><input type="file" class="form-control" name="attachment"></div>';
            if (!empty($editingRequirement['attachment_path'])) {
                $inner .= '<div class="col-md-3 d-flex align-items-end"><div class="form-check">';
                $inner .= '<input class="form-check-input" type="checkbox" name="remove_attachment" value="1" id="remove_attachment_admin">';
                $inner .= '<label class="form-check-label" for="remove_attachment_admin">Remove current attachment</label>';
                $inner .= '</div></div>';
            }
            $inner .= '<div class="col-md-12 d-flex align-items-end gap-2">';
            $inner .= '<button class="btn btn-success w-100" type="submit">Save</button>';
            $inner .= '<a class="btn btn-outline-secondary w-100" href="' . hpath('/admin/current-requirements') . '">Cancel</a>';
            $inner .= '</div></div></form>';
        }

        $inner .= '<div class="table-responsive"><table class="table table-sm align-middle mb-0">';
        $inner .= '<thead><tr><th>Office</th><th>Title</th><th>Description</th><th>Attachment</th><th style="width: 220px;">Actions</th></tr></thead><tbody>';
        foreach ($requirements as $requirement) {
            $inner .= '<tr>';
            $inner .= '<td>' . htmlspecialchars((string) $requirement['office_name']) . '</td>';
            $inner .= '<td>' . htmlspecialchars((string) $requirement['title']) . '</td>';
            $inner .= '<td>' . htmlspecialchars((string) ($requirement['description'] ?? '')) . '</td>';
            if (!empty($requirement['attachment_path'])) {
                $inner .= '<td><a href="' . hpath('/' . ltrim((string) $requirement['attachment_path'], '/')) . '" target="_blank" rel="noopener">' . htmlspecialchars((string) ($requirement['attachment_name'] ?? 'Download')) . '</a></td>';
            } else {
                $inner .= '<td>—</td>';
            }
            $inner .= '<td><div class="d-flex gap-1">';
            $inner .= '<a class="btn btn-sm btn-outline-success" href="' . hpath('/admin/current-requirements') . '?edit_requirement_id=' . (int) $requirement['id'] . '">Edit</a>';
            $inner .= '<form method="POST" action="' . hpath('/admin/requirement/delete') . '" onsubmit="return confirm(\'Delete this requirement?\');">';
            $inner .= '<input type="hidden" name="requirement_id" value="' . (int) $requirement['id'] . '">';
            $inner .= '<button class="btn btn-sm btn-outline-danger" type="submit">Delete</button>';
            $inner .= '</form></div></td></tr>';
        }
        $inner .= '</tbody></table></div>';
    }
    $inner .= '</div></div>';
    return renderAdminShell('/admin/current-requirements', $semester, $inner);
}

function renderAdminSignatoriesPage(
    array $semester,
    array $offices,
    array $colleges,
    array $signatories,
    array $signatoriesAll,
    ?array $editUser,
    array $assignments,
    array $deanAssignments,
    array $additionalOffices = []
): string {
    $inner = '';
    if ($editUser !== null) {
        $inner .= '<div class="panel"><div class="panel-header d-flex justify-content-between align-items-center flex-wrap gap-2"><h3 class="mb-0"><i class="fas fa-edit"></i>Edit Signatory</h3>';
        $inner .= '<a class="btn btn-sm btn-outline-secondary" href="' . hpath('/admin/signatories') . '">Cancel</a></div><div class="p-4">';
        $inner .= '<form method="POST" action="' . hpath('/admin/signatory/update') . '" class="row g-2" style="max-width:640px;">';
        $inner .= '<input type="hidden" name="user_id" value="' . (int) $editUser['id'] . '">';
        $inner .= '<div class="col-md-6"><label class="form-label">First name</label><input class="form-control" name="first_name" value="' . htmlspecialchars((string) $editUser['first_name']) . '" required></div>';
        $inner .= '<div class="col-md-6"><label class="form-label">Last name</label><input class="form-control" name="last_name" value="' . htmlspecialchars((string) $editUser['last_name']) . '" required></div>';
        $inner .= '<div class="col-md-6"><label class="form-label">Email (login)</label><input class="form-control" type="email" name="email" value="' . htmlspecialchars((string) $editUser['email']) . '" required></div>';
        $inner .= '<div class="col-md-6"><label class="form-label">New password</label><input class="form-control" type="password" name="new_password" autocomplete="new-password" placeholder="Leave blank to keep current">';
        $inner .= '<div class="form-text">Optional. Min 8 characters if changing.</div></div>';
        $inner .= '<div class="col-12 d-flex gap-2"><button class="btn btn-success" type="submit">Save changes</button>';
        $inner .= '<a class="btn btn-outline-secondary" href="' . hpath('/admin/signatories') . '">Cancel</a></div></form></div></div>';
    }

    $addPanel = '<div class="panel' . ($editUser !== null ? ' mt-4' : '') . '"><div class="panel-header"><h3><i class="fas fa-user-plus"></i>Add Signatory</h3></div><div class="p-4">';
    $addPanel .= '<p class="small text-muted mb-3">Create a signatory login. Then use <strong>Assign signatory</strong> to link them to an office for the open semester.</p>';
    $addPanel .= '<form method="POST" action="' . hpath('/admin/add-signatory') . '" class="row g-2" style="max-width:640px;">';
    $addPanel .= '<div class="col-md-6"><label class="form-label">First name</label><input class="form-control" name="first_name" required></div>';
    $addPanel .= '<div class="col-md-6"><label class="form-label">Last name</label><input class="form-control" name="last_name" required></div>';
    $addPanel .= '<div class="col-md-6"><label class="form-label">Email (login)</label><input class="form-control" type="email" name="email" required></div>';
    $addPanel .= '<div class="col-md-6"><label class="form-label">Initial password</label><input class="form-control" type="password" name="password" minlength="8" autocomplete="new-password" required></div>';
    $addPanel .= '<div class="col-12"><button class="btn btn-success" type="submit">Add signatory</button></div>';
    $addPanel .= '</form></div></div>';

    $inner .= $addPanel;

    $inner .= '<div class="panel mt-4"><div class="panel-header"><h3><i class="fas fa-sitemap"></i>Additional clearance units</h3></div><div class="p-4">';
    $inner .= '<p class="small text-muted mb-3">Add extra signatory offices under <strong>Student Affairs and Services</strong> or <strong>College Dean / Campus Administrator</strong>. Built-in units (SSC, Dormitory Coordinator, Accounting, SOA, Library) cannot be removed.</p>';
    $inner .= '<form method="POST" action="' . hpath('/admin/signatory-office/add') . '" class="row g-2 mb-4" style="max-width:720px;">';
    $inner .= '<div class="col-md-5"><label class="form-label">Under group</label><select name="parent_code" class="form-select" required>';
    foreach ($offices as $office) {
        $code = officeRowCode($office);
        if (!in_array($code, adminGroupParentCodes(), true)) {
            continue;
        }
        $inner .= '<option value="' . htmlspecialchars($code) . '">' . htmlspecialchars((string) $office['name']) . '</option>';
    }
    $inner .= '</select></div>';
    $inner .= '<div class="col-md-5"><label class="form-label">Unit name</label><input class="form-control" name="unit_name" placeholder="e.g. Guidance Office" required></div>';
    $inner .= '<div class="col-md-2 d-flex align-items-end"><button class="btn btn-success w-100" type="submit">Add unit</button></div>';
    $inner .= '</form>';
    if ($additionalOffices === []) {
        $inner .= '<div class="text-muted small">No additional units yet.</div>';
    } else {
        $inner .= '<div class="table-responsive"><table class="report-table mb-0"><thead><tr><th>Group</th><th>Unit</th><th style="width:120px;">Actions</th></tr></thead><tbody>';
        foreach ($additionalOffices as $unit) {
            $inner .= '<tr>';
            $inner .= '<td>' . htmlspecialchars((string) ($unit['parent_name'] ?? '')) . '</td>';
            $inner .= '<td>' . htmlspecialchars((string) ($unit['name'] ?? '')) . '</td>';
            $inner .= '<td><form method="POST" action="' . hpath('/admin/signatory-office/deactivate') . '" class="d-inline" onsubmit="return confirm(\'Remove this clearance unit?\');">';
            $inner .= '<input type="hidden" name="office_id" value="' . (int) ($unit['id'] ?? 0) . '">';
            $inner .= '<button class="btn btn-sm btn-outline-danger" type="submit">Remove</button></form></td></tr>';
        }
        $inner .= '</tbody></table></div>';
    }
    $inner .= '</div></div>';

    $inner .= '<div class="panel mt-4"><div class="panel-header"><h3><i class="fas fa-pen-signature"></i>Assign Signatory</h3></div><div class="p-4">';
    $inner .= '<p class="small text-muted mb-3">Pick an office and an existing signatory account for this semester. Offices are grouped under <strong>Student Affairs and Services</strong> and <strong>College Dean / Campus Administrator</strong>, including any additional units you add above.</p>';
    $inner .= '<form method="POST" action="' . hpath('/admin/assign-signatory') . '" class="row g-2" style="max-width:640px;">';
    $inner .= '<div class="col-md-6"><label class="form-label">Office</label><select name="office_id" class="form-select" required>';
    $inner .= renderAdminOfficeSelectOptions($offices);
    $inner .= '</select></div>';
    $inner .= '<div class="col-md-6"><label class="form-label">Signatory</label><select name="signatory_user_id" class="form-select" required>';
    if ($signatories === []) {
        $inner .= '<option value="">No signatories yet — add one above</option>';
    } else {
        foreach ($signatories as $signatory) {
            $label = $signatory['last_name'] . ', ' . $signatory['first_name'] . ' (' . $signatory['email'] . ')';
            $inner .= '<option value="' . (int) $signatory['id'] . '">' . htmlspecialchars($label) . '</option>';
        }
    }
    $inner .= '</select></div>';
    $inner .= '<div class="col-12"><button class="btn btn-success" type="submit"' . ($signatories === [] ? ' disabled' : '') . '>Assign to office</button></div>';
    $inner .= '</form></div></div>';

    $inner .= '<div class="panel mt-4"><div class="panel-header"><h3><i class="fas fa-user-graduate"></i>Dean by College</h3></div><div class="p-4">';
    $inner .= '<p class="small text-muted mb-3">Assign one dean per college. Students from that college will automatically appear in that dean\'s queue.</p>';
    $inner .= '<form method="POST" action="' . hpath('/admin/assign-dean-college') . '" class="row g-2" style="max-width:720px;">';
    $inner .= '<div class="col-md-6"><label class="form-label">College</label><select name="college_id" class="form-select" required>';
    foreach ($colleges as $college) {
        $label = (string) $college['name'] . ' (' . (string) $college['code'] . ')';
        $inner .= '<option value="' . (int) $college['id'] . '">' . htmlspecialchars($label) . '</option>';
    }
    $inner .= '</select></div>';
    $inner .= '<div class="col-md-6"><label class="form-label">Dean signatory</label><select name="signatory_user_id" class="form-select" required>';
    if ($signatories === []) {
        $inner .= '<option value="">No signatories yet — add one above</option>';
    } else {
        foreach ($signatories as $signatory) {
            $label = $signatory['last_name'] . ', ' . $signatory['first_name'] . ' (' . $signatory['email'] . ')';
            $inner .= '<option value="' . (int) $signatory['id'] . '">' . htmlspecialchars($label) . '</option>';
        }
    }
    $inner .= '</select></div>';
    $inner .= '<div class="col-12"><button class="btn btn-success" type="submit"' . ($signatories === [] ? ' disabled' : '') . '>Assign dean to college</button></div>';
    $inner .= '</form></div></div>';

    $inner .= '<div class="panel mt-4"><div class="panel-header"><h3><i class="fas fa-link"></i>Office assignments (this semester)</h3></div><div class="p-0">';
    if ($assignments === []) {
        $inner .= '<div class="p-4 text-muted">No office assignments yet for the open semester.</div>';
    } else {
        $assignmentPartition = partitionAssignmentsForAdminGroups($assignments, $offices);
        $inner .= '<div class="table-responsive"><table class="report-table mb-0"><thead><tr><th>Office</th><th>Signatory</th><th style="width:120px;">Actions</th></tr></thead><tbody>';
        foreach ($assignmentPartition['other'] as $a) {
            $inner .= renderAdminSignatoryAssignmentRow($a);
        }
        foreach ($assignmentPartition['groups'] as $group) {
            $inner .= renderAdminAssignmentGroupSection($group);
        }
        $inner .= '</tbody></table></div>';
    }
    $inner .= '</div></div>';

    $inner .= '<div class="panel mt-4"><div class="panel-header"><h3><i class="fas fa-school"></i>College dean assignments</h3></div><div class="p-0">';
    if ($deanAssignments === []) {
        $inner .= '<div class="p-4 text-muted">No colleges found.</div>';
    } else {
        $inner .= '<div class="table-responsive"><table class="report-table mb-0"><thead><tr><th>College</th><th>Assigned Dean</th><th>Email</th></tr></thead><tbody>';
        foreach ($deanAssignments as $row) {
            $inner .= '<tr>';
            $inner .= '<td>' . htmlspecialchars((string) $row['college_name']) . ' <span class="text-muted small">(' . htmlspecialchars((string) $row['college_code']) . ')</span></td>';
            if (!empty($row['signatory_id'])) {
                $inner .= '<td>' . htmlspecialchars((string) ($row['last_name'] . ', ' . $row['first_name'])) . '</td>';
                $inner .= '<td>' . htmlspecialchars((string) $row['email']) . '</td>';
            } else {
                $inner .= '<td class="text-muted">Unassigned</td><td class="text-muted">—</td>';
            }
            $inner .= '</tr>';
        }
        $inner .= '</tbody></table></div>';
    }
    $inner .= '</div></div>';

    $inner .= '<div class="panel mt-4"><div class="panel-header"><h3><i class="fas fa-list"></i>Signatory accounts</h3></div><div class="p-0">';
    if ($signatoriesAll === []) {
        $inner .= '<div class="p-4 text-muted">No signatory accounts yet.</div>';
    } else {
        $inner .= '<div class="table-responsive"><table class="report-table mb-0"><thead><tr><th>Name</th><th>Email</th><th>Dean College</th><th>Status</th><th style="width:220px;">Actions</th></tr></thead><tbody>';
        foreach ($signatoriesAll as $s) {
            $sid = (int) $s['id'];
            $active = (int) ($s['is_active'] ?? 0) === 1;
            $inner .= '<tr><td>' . htmlspecialchars((string) ($s['last_name'] . ', ' . $s['first_name'])) . '</td>';
            $inner .= '<td>' . htmlspecialchars((string) $s['email']) . '</td>';
            $inner .= '<td>' . (!empty($s['college_name']) ? htmlspecialchars((string) $s['college_name']) : '—') . '</td>';
            $inner .= '<td>' . ($active ? '<span class="status-pill status-cleared">Active</span>' : '<span class="status-pill status-pending">Inactive</span>') . '</td>';
            $inner .= '<td><div class="d-flex flex-wrap gap-1">';
            $inner .= '<a class="btn btn-sm btn-outline-success" href="' . hpath('/admin/signatories') . '?edit_signatory_id=' . $sid . '">Edit</a>';
            if ($active) {
                $inner .= '<form method="POST" action="' . hpath('/admin/signatory/deactivate') . '" class="d-inline" onsubmit="return confirm(\'Delete this signatory account? This will deactivate the account and unassign it from all offices.\');">';
                $inner .= '<input type="hidden" name="user_id" value="' . $sid . '">';
                $inner .= '<button class="btn btn-sm btn-outline-danger" type="submit">Delete</button></form>';
            } else {
                $inner .= '<form method="POST" action="' . hpath('/admin/signatory/reactivate') . '" class="d-inline">';
                $inner .= '<input type="hidden" name="user_id" value="' . $sid . '">';
                $inner .= '<button class="btn btn-sm btn-outline-secondary" type="submit">Reactivate</button></form>';
            }
            $inner .= '</div></td></tr>';
        }
        $inner .= '</tbody></table></div>';
    }
    $inner .= '</div></div>';

    return renderAdminShell('/admin/signatories', $semester, $inner);
}

function renderAdminFinalClearancePage(array $semester, array $students): string
{
    $inner = '<div class="panel"><div class="panel-header"><h3><i class="fas fa-stamp"></i>Generate Student Final Clearance</h3></div><div class="p-4">';
    $inner .= '<form method="GET" action="' . hpath('/admin/final-clearance') . '" class="row g-2">';
    $inner .= '<div class="col-md-9"><select name="student_id" class="form-select" required><option value="">Select student</option>';
    foreach ($students as $student) {
        $ylOpt = trim((string) ($student['year_level'] ?? ''));
        $ylSeg = $ylOpt !== '' ? ' · Yr ' . $ylOpt : '';
        $label = sprintf(
            '%s - %s, %s%s [%s]',
            (string) ($student['student_no'] ?: 'N/A'),
            $student['last_name'],
            $student['first_name'],
            $ylSeg,
            strtoupper((string) $student['overall_status'])
        );
        $inner .= '<option value="' . (int) $student['id'] . '">' . htmlspecialchars($label) . '</option>';
    }
    $inner .= '</select></div><div class="col-md-3"><button class="btn btn-success w-100">Generate</button></div></form>';
    $inner .= '</div></div>';
    return renderAdminShell('/admin/final-clearance-tools', $semester, $inner);
}

function renderFinalClearanceSignatureImage(string $signaturePath, bool $forDompdf): array
{
    if ($signaturePath === '' || !is_file(dirname(__DIR__) . '/' . ltrim($signaturePath, '/'))) {
        return ['html' => '', 'omitted' => false];
    }

    $sigAbs = dirname(__DIR__) . '/' . ltrim($signaturePath, '/');
    if ($forDompdf) {
        $dataUri = SignatureImage::filePathToDompdfDataUri($sigAbs);
        if ($dataUri !== null) {
            return [
                'html' => '<img src="' . htmlspecialchars($dataUri, ENT_QUOTES, 'UTF-8') . '" alt="Signatory signature" class="approval-signature">',
                'omitted' => false,
            ];
        }

        return ['html' => '—', 'omitted' => true];
    }

    $sigData = @file_get_contents($sigAbs);
    if ($sigData === false) {
        return ['html' => '', 'omitted' => false];
    }

    $sigMime = mime_content_type($sigAbs) ?: 'image/png';
    $sigBase64 = base64_encode($sigData);

    return [
        'html' => '<img src="data:' . htmlspecialchars($sigMime) . ';base64,' . $sigBase64 . '" alt="Signatory signature" class="approval-signature">',
        'omitted' => false,
    ];
}

function renderFinalClearanceDocument(array $data, bool $forDompdf = false, ?array $signatureOfficeCodes = null): string
{
    $student = $data['student'];
    $semester = $data['semester'];
    $offices = $data['offices'];
    $signatureOfficeCodes = $signatureOfficeCodes ?? finalClearanceSignatureOfficeCodes();
    $allowedSignatureCodes = array_map(
        static fn (string $code): string => strtoupper(trim($code)),
        $signatureOfficeCodes
    );

    $rows = '';
    $signatureOffices = [];
    $anyPdfSignatureOmitted = false;
    foreach ($offices as $office) {
        $status = strtoupper((string) $office['status']);
        $signedAt = $office['decided_at'] ? date('Y-m-d h:i A', strtotime((string) $office['decided_at'])) : '-';
        $officeCode = strtoupper(trim((string) ($office['office_code'] ?? '')));

        $rows .= '<tr>';
        $rows .= '<td>' . htmlspecialchars((string) $office['office_name']) . '</td>';
        $rows .= '<td>' . htmlspecialchars($status) . '</td>';
        $rows .= '<td>' . htmlspecialchars($signedAt) . '</td>';
        $rows .= '</tr>';

        if (in_array($officeCode, $allowedSignatureCodes, true)) {
            $signatureOffices[] = $office;
        }
    }

    usort(
        $signatureOffices,
        static function (array $left, array $right) use ($allowedSignatureCodes): int {
            $leftCode = strtoupper(trim((string) ($left['office_code'] ?? '')));
            $rightCode = strtoupper(trim((string) ($right['office_code'] ?? '')));
            $leftIndex = array_search($leftCode, $allowedSignatureCodes, true);
            $rightIndex = array_search($rightCode, $allowedSignatureCodes, true);

            return (int) $leftIndex <=> (int) $rightIndex;
        }
    );

    $signatureBlocks = '';
    foreach ($signatureOffices as $office) {
        $signedAt = $office['decided_at'] ? date('Y-m-d h:i A', strtotime((string) $office['decided_at'])) : '-';
        $signatory = trim((string) ($office['signatory_name'] ?? '')) ?: '-';
        $signaturePath = trim((string) ($office['digital_signature_path'] ?? ''));
        $signatureRender = renderFinalClearanceSignatureImage($signaturePath, $forDompdf);
        if ($signatureRender['omitted']) {
            $anyPdfSignatureOmitted = true;
        }

        $signatureImageHtml = $signatureRender['html'] !== ''
            ? $signatureRender['html']
            : '<span class="approval-signature-placeholder">—</span>';

        $signatureBlocks .= '<div class="approval-signature-block">';
        $signatureBlocks .= '<div class="approval-signature-image">' . $signatureImageHtml . '</div>';
        $signatureBlocks .= '<div class="approval-signature-line"></div>';
        $signatureBlocks .= '<div class="approval-signature-name">' . htmlspecialchars($signatory) . '</div>';
        $signatureBlocks .= '<div class="approval-signature-title">' . htmlspecialchars((string) $office['office_name']) . '</div>';
        $signatureBlocks .= '<div class="approval-signature-date">Date signed: ' . htmlspecialchars($signedAt) . '</div>';
        $signatureBlocks .= '</div>';
    }

    $pdfSigNote = '';
    if ($forDompdf && $anyPdfSignatureOmitted) {
        $pdfSigNote = '<p class="pdf-sig-note"><strong>Note:</strong> An em dash (—) above a signature means the signatory image could not be included in this PDF only (for example: enable PHP GD on the server, or signatories re-upload a JPEG). Status and date signed still record the clearance.</p>';
    }

    return '<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>SAFE Final Semestral Clearance</title>
<style>
body { font-family: DejaVu Sans, Arial, sans-serif; font-size: 12px; color: #111; }
.container { width: 100%; max-width: 800px; margin: 0 auto; }
.header { text-align: center; margin-bottom: 14px; }
.header h2 { margin: 0; font-size: 18px; }
.header p { margin: 2px 0; }
.meta { width: 100%; margin-bottom: 14px; border-collapse: collapse; }
.meta td { padding: 6px; border: 1px solid #333; }
table.clearance { width: 100%; border-collapse: collapse; }
table.clearance th, table.clearance td { border: 1px solid #333; padding: 8px; text-align: left; }
table.clearance th { background: #efefef; }
.approval-signatures { margin-top: 28px; display: table; width: 100%; table-layout: fixed; }
.approval-signature-block { display: table-cell; width: 50%; text-align: center; vertical-align: top; padding: 0 16px; }
.approval-signature-image { min-height: 70px; margin-bottom: 8px; }
.approval-signature { max-width: 180px; max-height: 60px; object-fit: contain; display: inline-block; }
.approval-signature-placeholder { color: #666; font-size: 18px; line-height: 60px; }
.approval-signature-line { border-top: 1px solid #111; margin: 0 auto 8px; width: 85%; }
.approval-signature-name { font-weight: 700; margin-bottom: 2px; }
.approval-signature-title { font-size: 11px; margin-bottom: 2px; }
.approval-signature-date { font-size: 10px; color: #444; }
.footer { margin-top: 24px; }
.pdf-sig-note { font-size: 10px; color: #333; line-height: 1.35; margin-top: 12px; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h2>Western Philippines University</h2>
    <p>College of Arts and Sciences</p>
    <p><strong>Final Semestral Clearance Form</strong></p>
  </div>
  <table class="meta">
    <tr><td><strong>Student No:</strong> ' . htmlspecialchars((string) ($student['student_no'] ?? '-')) . '</td><td><strong>Semester:</strong> ' . htmlspecialchars($semester['term']) . '</td></tr>
    <tr><td><strong>Student Name:</strong> ' . htmlspecialchars($student['last_name'] . ', ' . $student['first_name']) . '</td><td><strong>Academic Year:</strong> ' . htmlspecialchars($semester['academic_year']) . '</td></tr>
    <tr><td><strong>Year level:</strong> ' . (trim((string) ($student['year_level'] ?? '')) !== '' ? htmlspecialchars((string) $student['year_level']) : '—') . '</td><td><strong>Campus:</strong> ' . formatStudentCampusCell($student['campus'] ?? null) . '</td></tr>
    <tr><td><strong>Email:</strong> ' . htmlspecialchars($student['email']) . '</td><td></td></tr>
  </table>
  <table class="clearance">
    <thead>
      <tr>
        <th>Office</th>
        <th>Status</th>
        <th>Date Signed</th>
      </tr>
    </thead>
    <tbody>' . $rows . '</tbody>
  </table>
  <div class="approval-signatures">' . $signatureBlocks . '</div>
  <div class="footer">
    <p><strong>Certification:</strong> The student has satisfied all required office clearances for the semester.</p>
    ' . $pdfSigNote . '
  </div>
</div>
</body>
</html>';
}

function renderAdminReports(array $semester, array $rows, array $filters): string
{
    $statusOptions = ['pending', 'for_review', 'cleared', 'rejected'];
    $selectedOverall = (string) ($filters['overall_status'] ?? '');

    $inner = '<div class="panel"><div class="panel-header"><h3><i class="fas fa-chart-line"></i>Admin Clearance Reports</h3></div><div class="p-4">';
    $inner .= '<form method="GET" action="' . hpath('/admin/reports') . '" class="row g-2">';
    $inner .= '<div class="col-md-5"><label class="form-label">Overall Status</label><select class="form-select" name="overall_status">';
    $inner .= '<option value="">All</option>';
    foreach ($statusOptions as $status) {
        $selected = $selectedOverall === $status ? ' selected' : '';
        $label = ucwords(str_replace('_', ' ', $status));
        $inner .= '<option value="' . $status . '"' . $selected . '>' . htmlspecialchars($label) . '</option>';
    }
    $inner .= '</select></div>';
    $selectedCampus = trim((string) ($filters['campus'] ?? ''));
    $inner .= '<div class="col-md-4"><label class="form-label">Campus</label>';
    $inner .= renderStudentCampusSelect('campus', $selectedCampus, false, true) . '</div>';
    $inner .= '<div class="col-md-3 d-flex align-items-end"><button class="btn btn-success w-100">Apply Filters</button></div>';
    $inner .= '</form></div></div>';

    $query = http_build_query([
        'overall_status' => $selectedOverall,
        'campus' => $selectedCampus,
        'export' => 'csv',
    ]);
    $inner .= '<div class="admin-toolbar">';
    $inner .= '<span class="text-muted">Results: ' . count($rows) . '</span>';
    $inner .= '<div class="d-flex gap-2">';
    $inner .= '<a href="' . hpath('/admin/reports') . '?' . htmlspecialchars($query) . '" class="btn btn-sm btn-outline-success">Export CSV</a>';
    $inner .= '<a href="' . hpath('/dashboard') . '" class="btn btn-sm btn-outline-secondary">Back to Admin Dashboard</a>';
    $inner .= '</div></div>';

    $inner .= '<div class="panel"><div style="overflow-x:auto;"><table class="report-table">';
    $inner .= '<thead><tr><th>Student No</th><th>Name</th><th>Campus</th><th>College</th><th>Program</th><th>Year</th><th>Email</th><th>Overall Status</th></tr></thead><tbody>';
    if ($rows === []) {
        $inner .= '<tr><td colspan="8" class="text-center text-muted">No records found for current filters.</td></tr>';
    } else {
        foreach ($rows as $row) {
            $name = $row['last_name'] . ', ' . $row['first_name'];
            $collegeCell = trim((string) ($row['college_name'] ?? ''));
            $programCell = trim((string) ($row['program_name'] ?? ''));
            $inner .= '<tr>';
            $inner .= '<td>' . htmlspecialchars((string) ($row['student_no'] ?: 'N/A')) . '</td>';
            $inner .= '<td>' . htmlspecialchars($name) . '</td>';
            $inner .= '<td>' . formatStudentCampusCell($row['campus'] ?? null) . '</td>';
            $inner .= '<td>' . ($collegeCell !== '' ? htmlspecialchars($collegeCell) : '—') . '</td>';
            $inner .= '<td>' . ($programCell !== '' ? htmlspecialchars($programCell) : '—') . '</td>';
            $inner .= '<td>' . formatYearLevelCell($row['year_level'] ?? null) . '</td>';
            $inner .= '<td>' . htmlspecialchars((string) $row['email']) . '</td>';
            $overallLabel = ucwords(str_replace('_', ' ', (string) $row['overall_status']));
            $inner .= '<td>' . htmlspecialchars($overallLabel) . '</td>';
            $inner .= '</tr>';
        }
    }
    $inner .= '</tbody></table></div></div>';

    return renderAdminShell('/admin/reports', $semester, $inner);
}

function downloadAdminReportCsv(array $rows, array $semester): void
{
    $filename = sprintf(
        'wpu-clearance-report-%s-%s.csv',
        preg_replace('/[^a-zA-Z0-9]/', '-', (string) $semester['academic_year']),
        strtolower((string) $semester['term'])
    );
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');

    $out = fopen('php://output', 'w');
    if ($out === false) {
        echo 'Could not open output stream.';
        return;
    }

    fputcsv($out, ['Student No', 'Name', 'Campus', 'College', 'Program', 'Year', 'Email', 'Overall Status']);
    foreach ($rows as $row) {
        fputcsv($out, [
            (string) ($row['student_no'] ?: 'N/A'),
            (string) ($row['last_name'] . ', ' . $row['first_name']),
            ClearanceService::campusDisplayLabel((string) ($row['campus'] ?? '')),
            (string) ($row['college_name'] ?? ''),
            (string) ($row['program_name'] ?? ''),
            trim((string) ($row['year_level'] ?? '')),
            (string) $row['email'],
            ucwords(str_replace('_', ' ', (string) $row['overall_status'])),
        ]);
    }
    fclose($out);
}

function officeStatusDisplayLabel(string $status): string
{
    return match (strtolower(trim($status))) {
        'cleared' => 'Cleared',
        'for_review' => 'For Review',
        'rejected' => 'Disapproved',
        default => 'Pending',
    };
}

function pendingOfficeDisplayName(array $office): string
{
    $name = trim((string) ($office['office_name'] ?? ''));

    return $name !== '' ? $name : 'Office';
}

/** @param array<string,mixed> $filters */
function adminPendingMonitorQueryString(array $filters, array $overrides = []): string
{
    $merged = array_merge($filters, $overrides);
    $q = [];
    $officeId = (int) ($merged['office_id'] ?? 0);
    if ($officeId > 0) {
        $q['office_id'] = (string) $officeId;
    }
    $campus = trim((string) ($merged['campus'] ?? ''));
    if ($campus !== '') {
        $q['campus'] = $campus;
    }
    $collegeId = (int) ($merged['college_id'] ?? 0);
    if ($collegeId > 0) {
        $q['college_id'] = (string) $collegeId;
    }
    $programId = (int) ($merged['program_id'] ?? 0);
    if ($programId > 0) {
        $q['program_id'] = (string) $programId;
    }
    $yearLevel = trim((string) ($merged['year_level'] ?? ''));
    if ($yearLevel !== '') {
        $q['year_level'] = $yearLevel;
    }
    $searchName = trim((string) ($merged['search_name'] ?? ''));
    if ($searchName !== '') {
        $q['search_name'] = $searchName;
    }
    $officeStatus = strtolower(trim((string) ($merged['office_status'] ?? '')));
    if (in_array($officeStatus, ['pending', 'for_review', 'rejected'], true)) {
        $q['office_status'] = $officeStatus;
    }

    return $q === [] ? '' : '?' . http_build_query($q);
}

/**
 * @param array{offices:list<array<string,mixed>>,students:list<array<string,mixed>>,stats:array<string,int>} $monitor
 * @param array<string,mixed> $filters
 * @param list<array<string,mixed>> $colleges
 * @param array<int, list<array{id:int, code:string, name:string}>> $programsByCollege
 */
function renderAdminPendingDepartments(
    array $semester,
    array $monitor,
    array $filters,
    array $colleges,
    array $programsByCollege
): string {
    $offices = $monitor['offices'] ?? [];
    $students = $monitor['students'] ?? [];
    $stats = $monitor['stats'] ?? [];
    $selectedOfficeId = (int) ($filters['office_id'] ?? 0);
    $selectedCampus = trim((string) ($filters['campus'] ?? ''));
    $selectedCollege = (int) ($filters['college_id'] ?? 0);
    $selectedProgram = (int) ($filters['program_id'] ?? 0);
    $selectedYear = trim((string) ($filters['year_level'] ?? ''));
    $searchName = trim((string) ($filters['search_name'] ?? ''));
    $selectedStatus = strtolower(trim((string) ($filters['office_status'] ?? '')));

    $selectedOfficeName = '';
    foreach ($offices as $office) {
        if ((int) ($office['office_id'] ?? 0) === $selectedOfficeId) {
            $selectedOfficeName = pendingOfficeDisplayName($office);
            break;
        }
    }

    $inner = '<div class="panel"><div class="panel-header"><h3><i class="fas fa-hourglass-half"></i>Pending Departments</h3></div><div class="p-4">';
    $inner .= '<p class="small text-muted mb-3">See which offices still need to clear each student. Click a department card to list only students pending in that office.</p>';
    $inner .= '<form method="GET" action="' . hpath('/admin/pending-departments') . '" class="row g-2 align-items-end">';
    $inner .= '<div class="col-md-3"><label class="form-label">Campus</label>';
    $inner .= renderStudentCampusSelect('campus', $selectedCampus, false, true) . '</div>';
    $inner .= '<div class="col-md-3"><label class="form-label">College</label><select class="form-select" name="college_id" id="monitor_filter_college_id">';
    $inner .= '<option value="0"' . ($selectedCollege === 0 ? ' selected' : '') . '>All colleges</option>';
    foreach ($colleges as $college) {
        $cid = (int) ($college['id'] ?? 0);
        $sel = $selectedCollege === $cid ? ' selected' : '';
        $inner .= '<option value="' . $cid . '"' . $sel . '>' . htmlspecialchars((string) ($college['name'] ?? '')) . '</option>';
    }
    $inner .= '</select></div>';
    $inner .= '<div class="col-md-3"><label class="form-label">Program</label><select class="form-select" name="program_id" id="monitor_filter_program_id">';
    $inner .= '<option value="0"' . ($selectedProgram === 0 ? ' selected' : '') . '>All programs</option>';
    if ($selectedCollege > 0 && isset($programsByCollege[$selectedCollege])) {
        foreach ($programsByCollege[$selectedCollege] as $prog) {
            $pid = (int) ($prog['id'] ?? 0);
            $sel = $selectedProgram === $pid ? ' selected' : '';
            $inner .= '<option value="' . $pid . '"' . $sel . '>' . htmlspecialchars((string) ($prog['name'] ?? '') . ' (' . (string) ($prog['code'] ?? '') . ')') . '</option>';
        }
    }
    $inner .= '</select></div>';
    $inner .= '<div class="col-md-3"><label class="form-label">Year level</label><select class="form-select" name="year_level">';
    $yearOptions = ['' => 'All years', '1' => '1', '2' => '2', '3' => '3', '4' => '4', '5+' => '5+'];
    foreach ($yearOptions as $val => $label) {
        $valStr = (string) $val;
        $sel = $selectedYear === $valStr ? ' selected' : '';
        $inner .= '<option value="' . htmlspecialchars($valStr) . '"' . $sel . '>' . htmlspecialchars((string) $label) . '</option>';
    }
    $inner .= '</select></div>';
    $inner .= '<div class="col-md-3"><label class="form-label">Department status</label><select class="form-select" name="office_status">';
    $statusOptions = [
        '' => 'All incomplete',
        'pending' => 'Pending',
        'for_review' => 'For Review',
        'rejected' => 'Disapproved',
    ];
    foreach ($statusOptions as $val => $label) {
        $sel = $selectedStatus === (string) $val ? ' selected' : '';
        $inner .= '<option value="' . htmlspecialchars((string) $val) . '"' . $sel . '>' . htmlspecialchars($label) . '</option>';
    }
    $inner .= '</select></div>';
    $inner .= '<div class="col-md-5"><label class="form-label">Search student</label>';
    $inner .= '<input class="form-control" name="search_name" value="' . htmlspecialchars($searchName) . '" placeholder="Name or student number"></div>';
    if ($selectedOfficeId > 0) {
        $inner .= '<input type="hidden" name="office_id" value="' . $selectedOfficeId . '">';
    }
    $inner .= '<div class="col-md-4 d-flex gap-2"><button class="btn btn-success" type="submit">Apply filters</button>';
    $inner .= '<a class="btn btn-outline-secondary" href="' . hpath('/admin/pending-departments') . '">Reset</a></div>';
    $inner .= '</form></div></div>';

    $inner .= '<div class="cards-grid">';
    $inner .= '<div class="stat-card"><div class="stat-title"><i class="fas fa-users me-1"></i>Students in view</div><div class="stat-value">' . (int) ($stats['total_students'] ?? 0) . '</div></div>';
    $inner .= '<div class="stat-card"><div class="stat-title"><i class="fas fa-hourglass-half me-1"></i>With pending departments</div><div class="stat-value">' . (int) ($stats['students_with_pending'] ?? 0) . '</div></div>';
    $inner .= '<div class="stat-card"><div class="stat-title"><i class="fas fa-check-circle me-1"></i>Fully cleared</div><div class="stat-value">' . (int) ($stats['fully_cleared'] ?? 0) . '</div></div>';
    $inner .= '</div>';

    $inner .= '<div class="monitor-office-grid">';
    $allQs = adminPendingMonitorQueryString($filters, ['office_id' => 0]);
    $inner .= '<a class="monitor-office-card' . ($selectedOfficeId === 0 ? ' active' : '') . '" href="' . hpath('/admin/pending-departments') . $allQs . '">';
    $inner .= '<div class="monitor-office-name">All departments</div>';
    $inner .= '<div class="monitor-office-count">' . (int) ($stats['students_with_pending'] ?? 0) . '</div>';
    $inner .= '<div class="monitor-office-meta">Students still incomplete</div></a>';
    foreach ($offices as $office) {
        $oid = (int) ($office['office_id'] ?? 0);
        $incomplete = (int) ($office['incomplete'] ?? 0);
        $active = $selectedOfficeId === $oid ? ' active' : '';
        $cardQs = adminPendingMonitorQueryString($filters, ['office_id' => $oid]);
        $inner .= '<a class="monitor-office-card' . $active . '" href="' . hpath('/admin/pending-departments') . $cardQs . '">';
        $inner .= '<div class="monitor-office-name">' . htmlspecialchars(pendingOfficeDisplayName($office)) . '</div>';
        $inner .= '<div class="monitor-office-count">' . $incomplete . '</div>';
        $inner .= '<div class="monitor-office-meta">Pending ' . (int) ($office['pending'] ?? 0)
            . ' · Review ' . (int) ($office['for_review'] ?? 0)
            . ' · Disapproved ' . (int) ($office['rejected'] ?? 0)
            . '</div></a>';
    }
    $inner .= '</div>';

    $csvQs = adminPendingMonitorQueryString($filters);
    $csvHref = hpath('/admin/pending-departments') . ($csvQs === '' ? '?export=csv' : $csvQs . '&export=csv');
    $inner .= '<div class="admin-toolbar">';
    $inner .= '<span class="text-muted">';
    if ($selectedOfficeName !== '') {
        $inner .= 'Showing students not yet cleared by <strong>' . htmlspecialchars($selectedOfficeName) . '</strong>. ';
    }
    $inner .= 'Results: ' . count($students) . '</span>';
    $inner .= '<div class="d-flex gap-2">';
    $inner .= '<a href="' . htmlspecialchars($csvHref) . '" class="btn btn-sm btn-outline-success">Export CSV</a>';
    $inner .= '<a href="' . hpath('/dashboard') . '" class="btn btn-sm btn-outline-secondary">Back to Admin Dashboard</a>';
    $inner .= '</div></div>';

    $inner .= '<div class="panel"><div style="overflow-x:auto;"><table class="report-table">';
    $inner .= '<thead><tr><th>Student No</th><th>Name</th><th>Campus</th><th>College</th><th>Program</th><th>Year</th><th>Pending departments</th></tr></thead><tbody>';
    if ($students === []) {
        $inner .= '<tr><td colspan="7" class="text-center text-muted">No students with pending departments for the current filters.</td></tr>';
    } else {
        foreach ($students as $row) {
            $name = (string) ($row['last_name'] ?? '') . ', ' . (string) ($row['first_name'] ?? '');
            $collegeCell = trim((string) ($row['college_name'] ?? ''));
            $programCell = trim((string) ($row['program_name'] ?? ''));
            $inner .= '<tr>';
            $inner .= '<td>' . htmlspecialchars((string) (($row['student_no'] ?? '') !== '' ? $row['student_no'] : 'N/A')) . '</td>';
            $inner .= '<td>' . htmlspecialchars($name) . '</td>';
            $inner .= '<td>' . formatStudentCampusCell($row['campus'] ?? null) . '</td>';
            $inner .= '<td>' . ($collegeCell !== '' ? htmlspecialchars($collegeCell) : '—') . '</td>';
            $inner .= '<td>' . ($programCell !== '' ? htmlspecialchars($programCell) : '—') . '</td>';
            $inner .= '<td>' . formatYearLevelCell($row['year_level'] ?? null) . '</td>';
            $inner .= '<td>';
            $pendingOffices = $row['pending_offices'] ?? [];
            if (!is_array($pendingOffices) || $pendingOffices === []) {
                $inner .= '<span class="text-muted">—</span>';
            } else {
                foreach ($pendingOffices as $pendingOffice) {
                    $st = strtolower((string) ($pendingOffice['status'] ?? 'pending'));
                    $chipClass = 'dept-chip dept-chip-' . (in_array($st, ['pending', 'for_review', 'rejected'], true) ? $st : 'pending');
                    $label = pendingOfficeDisplayName($pendingOffice) . ' · ' . officeStatusDisplayLabel($st);
                    $inner .= '<span class="' . $chipClass . '">' . htmlspecialchars($label) . '</span>';
                }
            }
            $inner .= '</td></tr>';
        }
    }
    $inner .= '</tbody></table></div></div>';

    $programsJson = json_encode($programsByCollege, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE);
    if ($programsJson === false) {
        $programsJson = '{}';
    }
    $inner .= '<script>(function(){var byCollege=' . $programsJson . ';var c=document.getElementById("monitor_filter_college_id");var p=document.getElementById("monitor_filter_program_id");if(!c||!p)return;function refill(preserveSel){var id=parseInt(c.value,10)||0;var prev=preserveSel!==undefined?preserveSel:0;p.innerHTML="<option value=\\"0\\">All programs</option>";if(!byCollege[id])return;(byCollege[id]||[]).forEach(function(pr){var o=document.createElement("option");o.value=String(pr.id);o.textContent=pr.name+" ("+pr.code+")";if(prev&&parseInt(o.value,10)===prev)o.selected=true;p.appendChild(o);});}c.addEventListener("change",function(){refill(0);});})();</script>';

    return renderAdminShell('/admin/pending-departments', $semester, $inner);
}

function downloadAdminPendingDepartmentsCsv(array $rows, array $semester): void
{
    $filename = sprintf(
        'wpu-pending-departments-%s-%s.csv',
        preg_replace('/[^a-zA-Z0-9]/', '-', (string) $semester['academic_year']),
        strtolower((string) $semester['term'])
    );
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');

    $out = fopen('php://output', 'w');
    if ($out === false) {
        echo 'Could not open output stream.';
        return;
    }

    fputcsv($out, ['Student No', 'Name', 'Campus', 'College', 'Program', 'Year', 'Pending Departments']);
    foreach ($rows as $row) {
        $pendingLabels = [];
        foreach ($row['pending_offices'] ?? [] as $pendingOffice) {
            $pendingLabels[] = pendingOfficeDisplayName($pendingOffice)
                . ' (' . officeStatusDisplayLabel((string) ($pendingOffice['status'] ?? 'pending')) . ')';
        }
        fputcsv($out, [
            (string) (($row['student_no'] ?? '') !== '' ? $row['student_no'] : 'N/A'),
            (string) (($row['last_name'] ?? '') . ', ' . ($row['first_name'] ?? '')),
            ClearanceService::campusDisplayLabel((string) ($row['campus'] ?? '')),
            (string) ($row['college_name'] ?? ''),
            (string) ($row['program_name'] ?? ''),
            trim((string) ($row['year_level'] ?? '')),
            implode('; ', $pendingLabels),
        ]);
    }
    fclose($out);
}
