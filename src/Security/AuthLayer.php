<?php

declare(strict_types=1);

namespace App\Security;

/**
 * Authentication layer: encrypted sessions, CSRF, cookie hardening, and session binding.
 */
final class AuthLayer
{
    private const IDLE_SECONDS = 1800;
    private const ABSOLUTE_SECONDS = 28800;
    private const REGENERATE_SECONDS = 900;
    private const CSRF_KEY = '_csrf';
    private const META_KEY = '_auth';

    private static bool $booted = false;
    private static bool $expired = false;
    private static ?EncryptedSessionHandler $handler = null;

    public static function boot(): void
    {
        if (self::$booted) {
            return;
        }
        self::$booted = true;

        self::sendSecurityHeaders();

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        $savePath = EncryptedSessionHandler::directory();
        if (!is_dir($savePath) && !mkdir($savePath, 0700, true) && !is_dir($savePath)) {
            throw new \RuntimeException('Unable to create encrypted session storage.');
        }
        self::$handler = new EncryptedSessionHandler($savePath);
        session_set_save_handler(self::$handler, true);
        session_save_path($savePath);
        session_name('SAFESESSID');

        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Lax');
        ini_set('session.gc_maxlifetime', (string) self::ABSOLUTE_SECONDS);
        ini_set('session.sid_length', '48');
        ini_set('session.sid_bits_per_character', '6');

        $secure = self::isHttps();
        if ($secure) {
            ini_set('session.cookie_secure', '1');
        }

        session_set_cookie_params([
            'lifetime' => 0,
            'path' => self::cookiePath(),
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        session_start();
        self::ensureCsrfToken();
        self::validateExistingSession();
    }

    public static function sendSecurityHeaders(): void
    {
        if (headers_sent()) {
            return;
        }

        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
        header('Cache-Control: no-store, no-cache, must-revalidate, private');
        header('Pragma: no-cache');
        header(
            "Content-Security-Policy: default-src 'self'; "
            . "base-uri 'self'; "
            . "form-action 'self'; "
            . "frame-ancestors 'none'; "
            . "object-src 'none'; "
            . "script-src 'self' 'unsafe-inline'; "
            . "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            . "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            . "img-src 'self' data:; "
            . "connect-src 'self'"
        );
        if (self::isHttps()) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
    }

    /**
     * Local-only debug output (never enable APP_DEBUG in production).
     */
    public static function allowsAuthDebugOutput(): bool
    {
        if (getenv('APP_DEBUG') !== '1') {
            return false;
        }
        $env = strtolower(trim((string) (getenv('APP_ENV') ?: '')));

        return in_array($env, ['local', 'development', 'dev'], true);
    }

    public static function csrfToken(): string
    {
        self::ensureCsrfToken();

        return (string) ($_SESSION[self::CSRF_KEY] ?? '');
    }

    public static function csrfField(): string
    {
        $token = htmlspecialchars(self::csrfToken(), ENT_QUOTES, 'UTF-8');

        return '<input type="hidden" name="_csrf" value="' . $token . '">';
    }

    public static function csrfMeta(): string
    {
        $token = htmlspecialchars(self::csrfToken(), ENT_QUOTES, 'UTF-8');

        return '<meta name="csrf-token" content="' . $token . '">';
    }

    public static function csrfScript(): string
    {
        return '<script>(function(){var t=document.querySelector("meta[name=\\"csrf-token\\"]");if(!t)return;var v=t.getAttribute("content")||"";document.querySelectorAll("form").forEach(function(f){var method=(f.getAttribute("method")||"get").toLowerCase();if(method!=="post")return;if(f.querySelector("input[name=\\"_csrf\\"]"))return;var i=document.createElement("input");i.type="hidden";i.name="_csrf";i.value=v;f.appendChild(i);});})();</script>';
    }

    public static function csrfIsValid(): bool
    {
        $posted = (string) ($_POST['_csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
        $expected = self::csrfToken();
        if ($posted === '' || $expected === '') {
            return false;
        }

        return hash_equals($expected, $posted);
    }

    /**
     * @param array<string, mixed> $user
     */
    public static function login(array $user): void
    {
        $now = time();
        session_regenerate_id(true);
        $_SESSION['user'] = $user;
        $_SESSION[self::META_KEY] = [
            'created_at' => $now,
            'last_activity' => $now,
            'last_regenerated' => $now,
            'fingerprint' => self::fingerprint(),
        ];
        $_SESSION[self::CSRF_KEY] = bin2hex(random_bytes(32));
        self::$expired = false;
    }

    public static function logout(): void
    {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', [
                'expires' => time() - 42000,
                'path' => $params['path'] ?: '/',
                'domain' => $params['domain'] ?: '',
                'secure' => (bool) $params['secure'],
                'httponly' => (bool) $params['httponly'],
                'samesite' => $params['samesite'] ?: 'Lax',
            ]);
        }
        session_destroy();
        session_start();
        self::ensureCsrfToken();
        self::$expired = false;
    }

    /**
     * @param array<string, mixed> $user
     */
    public static function refreshUser(array $user): void
    {
        $_SESSION['user'] = $user;
        if (isset($_SESSION[self::META_KEY]) && is_array($_SESSION[self::META_KEY])) {
            $_SESSION[self::META_KEY]['last_activity'] = time();
        }
    }

    public static function expired(): bool
    {
        return self::$expired;
    }

    public static function clientIp(): string
    {
        $remote = trim((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
        $trustProxy = getenv('APP_TRUST_PROXY') === '1';
        if ($trustProxy) {
            $forwarded = trim((string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
            if ($forwarded !== '') {
                $first = trim(explode(',', $forwarded)[0]);
                if (filter_var($first, FILTER_VALIDATE_IP)) {
                    return $first;
                }
            }
        }

        return $remote !== '' ? $remote : '0.0.0.0';
    }

    public static function isHttps(): bool
    {
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            return true;
        }
        if ((int) ($_SERVER['SERVER_PORT'] ?? 0) === 443) {
            return true;
        }
        $forwarded = strtolower(trim((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')));

        return $forwarded === 'https';
    }

    private static function validateExistingSession(): void
    {
        if (!isset($_SESSION['user']) || !is_array($_SESSION['user'])) {
            return;
        }

        $meta = $_SESSION[self::META_KEY] ?? null;
        if (!is_array($meta)) {
            self::expireAuthenticatedSession();
            return;
        }

        $now = time();
        $created = (int) ($meta['created_at'] ?? 0);
        $lastActivity = (int) ($meta['last_activity'] ?? 0);
        $fingerprint = (string) ($meta['fingerprint'] ?? '');

        if ($created <= 0 || ($now - $created) > self::ABSOLUTE_SECONDS) {
            self::expireAuthenticatedSession();
            return;
        }
        if ($lastActivity > 0 && ($now - $lastActivity) > self::IDLE_SECONDS) {
            self::expireAuthenticatedSession();
            return;
        }
        if ($fingerprint === '' || !hash_equals($fingerprint, self::fingerprint())) {
            self::expireAuthenticatedSession();
            return;
        }

        $_SESSION[self::META_KEY]['last_activity'] = $now;
        $lastRegen = (int) ($meta['last_regenerated'] ?? 0);
        if (($now - $lastRegen) >= self::REGENERATE_SECONDS) {
            session_regenerate_id(true);
            $_SESSION[self::META_KEY]['last_regenerated'] = $now;
        }
    }

    private static function expireAuthenticatedSession(): void
    {
        self::$expired = isset($_SESSION['user']);
        unset($_SESSION['user'], $_SESSION[self::META_KEY]);
        session_regenerate_id(true);
        self::ensureCsrfToken(true);
    }

    private static function ensureCsrfToken(bool $rotate = false): void
    {
        if ($rotate || empty($_SESSION[self::CSRF_KEY]) || !is_string($_SESSION[self::CSRF_KEY])) {
            $_SESSION[self::CSRF_KEY] = bin2hex(random_bytes(32));
        }
    }

    private static function fingerprint(): string
    {
        $ua = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');

        return Crypto::hmac('ua|' . $ua);
    }

    private static function cookiePath(): string
    {
        $scriptName = str_replace('\\', '/', (string) ($_SERVER['SCRIPT_NAME'] ?? '/index.php'));
        $path = str_replace('\\', '/', dirname($scriptName));
        $path = rtrim($path, '/');
        if ($path === '' || $path === '.' || $path === '\\') {
            return '/';
        }

        return $path;
    }
}
