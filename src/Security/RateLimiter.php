<?php

declare(strict_types=1);

namespace App\Security;

use PDO;
use PDOException;

final class RateLimiter
{
    private const LOGIN_IP_MAX = 12;
    private const LOGIN_EMAIL_MAX = 5;
    private const LOGIN_WINDOW = 900;
    private const LOGIN_LOCK = 900;

    private const FORGOT_IP_MAX = 8;
    private const FORGOT_EMAIL_MAX = 3;
    private const FORGOT_WINDOW = 1800;
    private const FORGOT_LOCK = 1800;

    private const RESET_IP_MAX = 8;
    private const RESET_WINDOW = 900;
    private const RESET_LOCK = 900;

    private const REGISTER_IP_MAX = 8;
    private const REGISTER_WINDOW = 1800;
    private const REGISTER_LOCK = 1800;

    public function __construct(private readonly PDO $pdo)
    {
        self::ensureSchema($this->pdo);
    }

    public static function ensureSchema(PDO $pdo): void
    {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS auth_rate_limits (
                limiter_key CHAR(64) NOT NULL,
                action VARCHAR(40) NOT NULL,
                attempts INT UNSIGNED NOT NULL DEFAULT 0,
                window_started_at DATETIME NOT NULL,
                locked_until DATETIME NULL,
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (limiter_key),
                INDEX idx_auth_rate_limits_locked_until (locked_until)
            ) ENGINE=InnoDB
        ");
    }

    public function loginBlocked(string $ip, string $email): ?string
    {
        return $this->blockedMessage([
            $this->inspect('login_ip', $ip, self::LOGIN_IP_MAX, self::LOGIN_WINDOW),
            $this->inspect('login_email', $email, self::LOGIN_EMAIL_MAX, self::LOGIN_WINDOW),
        ], 'sign-in');
    }

    public function recordLoginFailure(string $ip, string $email): void
    {
        $this->hit('login_ip', $ip, self::LOGIN_IP_MAX, self::LOGIN_WINDOW, self::LOGIN_LOCK);
        if (trim($email) !== '') {
            $this->hit('login_email', $email, self::LOGIN_EMAIL_MAX, self::LOGIN_WINDOW, self::LOGIN_LOCK);
        }
    }

    public function clearLoginFailures(string $email): void
    {
        if (trim($email) === '') {
            return;
        }
        $this->clear('login_email', $email);
    }

    public function forgotPasswordBlocked(string $ip, string $email): ?string
    {
        return $this->blockedMessage([
            $this->inspect('forgot_ip', $ip, self::FORGOT_IP_MAX, self::FORGOT_WINDOW),
            $this->inspect('forgot_email', $email, self::FORGOT_EMAIL_MAX, self::FORGOT_WINDOW),
        ], 'password reset');
    }

    public function recordForgotPassword(string $ip, string $email): void
    {
        $this->hit('forgot_ip', $ip, self::FORGOT_IP_MAX, self::FORGOT_WINDOW, self::FORGOT_LOCK);
        if (trim($email) !== '') {
            $this->hit('forgot_email', $email, self::FORGOT_EMAIL_MAX, self::FORGOT_WINDOW, self::FORGOT_LOCK);
        }
    }

    public function resetPasswordBlocked(string $ip): ?string
    {
        return $this->blockedMessage([
            $this->inspect('reset_ip', $ip, self::RESET_IP_MAX, self::RESET_WINDOW),
        ], 'password reset');
    }

    public function recordResetPasswordFailure(string $ip): void
    {
        $this->hit('reset_ip', $ip, self::RESET_IP_MAX, self::RESET_WINDOW, self::RESET_LOCK);
    }

    public function registerBlocked(string $ip): ?string
    {
        return $this->blockedMessage([
            $this->inspect('register_ip', $ip, self::REGISTER_IP_MAX, self::REGISTER_WINDOW),
        ], 'registration');
    }

    public function recordRegistration(string $ip): void
    {
        $this->hit('register_ip', $ip, self::REGISTER_IP_MAX, self::REGISTER_WINDOW, self::REGISTER_LOCK);
    }

    /**
     * @return array{allowed:bool, retry_after:int, remaining:int}
     */
    private function inspect(string $action, string $subject, int $maxAttempts, int $windowSeconds): array
    {
        $subject = trim($subject);
        if ($subject === '') {
            return ['allowed' => true, 'retry_after' => 0, 'remaining' => $maxAttempts];
        }

        $row = $this->fetch(Crypto::identifierHash($action, $subject));
        if ($row === null) {
            return ['allowed' => true, 'retry_after' => 0, 'remaining' => $maxAttempts];
        }

        $now = time();
        $lockedUntil = $this->toTimestamp($row['locked_until'] ?? null);
        if ($lockedUntil !== null && $lockedUntil > $now) {
            return ['allowed' => false, 'retry_after' => $lockedUntil - $now, 'remaining' => 0];
        }

        $windowStart = $this->toTimestamp($row['window_started_at'] ?? null) ?? $now;
        if (($now - $windowStart) >= $windowSeconds) {
            return ['allowed' => true, 'retry_after' => 0, 'remaining' => $maxAttempts];
        }

        $attempts = (int) ($row['attempts'] ?? 0);
        if ($attempts >= $maxAttempts) {
            $retry = max(1, $windowSeconds - ($now - $windowStart));

            return ['allowed' => false, 'retry_after' => $retry, 'remaining' => 0];
        }

        return [
            'allowed' => true,
            'retry_after' => 0,
            'remaining' => max(0, $maxAttempts - $attempts),
        ];
    }

    private function hit(string $action, string $subject, int $maxAttempts, int $windowSeconds, int $lockSeconds): void
    {
        $subject = trim($subject);
        if ($subject === '') {
            return;
        }

        $key = Crypto::identifierHash($action, $subject);
        $now = time();
        $this->pdo->beginTransaction();
        try {
            $row = $this->fetchForUpdate($key);
            if ($row === null) {
                $insert = $this->pdo->prepare("
                    INSERT INTO auth_rate_limits
                        (limiter_key, action, attempts, window_started_at, locked_until, updated_at)
                    VALUES
                        (:limiter_key, :action, 1, :window_started_at, NULL, :updated_at)
                ");
                $insert->execute([
                    'limiter_key' => $key,
                    'action' => $action,
                    'window_started_at' => date('Y-m-d H:i:s', $now),
                    'updated_at' => date('Y-m-d H:i:s', $now),
                ]);
                $this->pdo->commit();
                return;
            }

            $windowStart = $this->toTimestamp($row['window_started_at'] ?? null) ?? $now;
            $attempts = (int) ($row['attempts'] ?? 0);
            $lockedUntil = $this->toTimestamp($row['locked_until'] ?? null);

            if (($now - $windowStart) >= $windowSeconds && ($lockedUntil === null || $lockedUntil <= $now)) {
                $windowStart = $now;
                $attempts = 0;
                $lockedUntil = null;
            }

            $attempts++;
            if ($attempts >= $maxAttempts) {
                $lockedUntil = $now + $lockSeconds;
            }

            $update = $this->pdo->prepare("
                UPDATE auth_rate_limits
                SET attempts = :attempts,
                    window_started_at = :window_started_at,
                    locked_until = :locked_until,
                    updated_at = :updated_at
                WHERE limiter_key = :limiter_key
                LIMIT 1
            ");
            $update->execute([
                'attempts' => $attempts,
                'window_started_at' => date('Y-m-d H:i:s', $windowStart),
                'locked_until' => $lockedUntil !== null ? date('Y-m-d H:i:s', $lockedUntil) : null,
                'updated_at' => date('Y-m-d H:i:s', $now),
                'limiter_key' => $key,
            ]);
            $this->pdo->commit();
        } catch (PDOException $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            if (str_contains($e->getMessage(), 'Duplicate')) {
                return;
            }
            throw $e;
        }
    }

    private function clear(string $action, string $subject): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM auth_rate_limits WHERE limiter_key = :limiter_key LIMIT 1');
        $stmt->execute(['limiter_key' => Crypto::identifierHash($action, $subject)]);
    }

    /**
     * @param list<array{allowed:bool, retry_after:int, remaining:int}> $results
     */
    private function blockedMessage(array $results, string $actionLabel): ?string
    {
        $retryAfter = 0;
        foreach ($results as $result) {
            if (!($result['allowed'] ?? true)) {
                $retryAfter = max($retryAfter, (int) ($result['retry_after'] ?? 0));
            }
        }
        if ($retryAfter <= 0) {
            return null;
        }

        $minutes = max(1, (int) ceil($retryAfter / 60));
        header('Retry-After: ' . (string) $retryAfter);

        return 'Too many ' . $actionLabel . ' attempts. Please wait ' . $minutes
            . ' minute' . ($minutes === 1 ? '' : 's') . ' and try again.';
    }

    /**
     * @return array<string, mixed>|null
     */
    private function fetch(string $key): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM auth_rate_limits WHERE limiter_key = :limiter_key LIMIT 1');
        $stmt->execute(['limiter_key' => $key]);
        $row = $stmt->fetch();

        return is_array($row) ? $row : null;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function fetchForUpdate(string $key): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM auth_rate_limits WHERE limiter_key = :limiter_key LIMIT 1 FOR UPDATE');
        $stmt->execute(['limiter_key' => $key]);
        $row = $stmt->fetch();

        return is_array($row) ? $row : null;
    }

    private function toTimestamp(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }
        $ts = strtotime((string) $value);

        return $ts === false ? null : $ts;
    }
}
