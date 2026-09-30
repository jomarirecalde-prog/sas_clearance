<?php

declare(strict_types=1);

namespace App\Security;

final class PasswordHasher
{
    /** Valid bcrypt hash used only to keep verify timing consistent on unknown accounts. */
    private const DUMMY_HASH = '$2y$10$hY4OWMTnfzoZJKbJziENUOCMQQW672vTNEhZthO/HWub5inaPPsnC';

    /**
     * @return array<string, int>
     */
    private static function argonOptions(): array
    {
        return [
            'memory_cost' => 19456,
            'time_cost' => 2,
            'threads' => 1,
        ];
    }

    public static function hash(string $password): string
    {
        if (defined('PASSWORD_ARGON2ID') && in_array('argon2id', password_algos(), true)) {
            $hash = password_hash($password, PASSWORD_ARGON2ID, self::argonOptions());
        } else {
            $hash = password_hash($password, PASSWORD_DEFAULT);
        }
        if (!is_string($hash) || $hash === '') {
            throw new \RuntimeException('Unable to hash password.');
        }

        return $hash;
    }

    public static function verify(string $password, string $hash): bool
    {
        if ($hash === '') {
            self::dummyVerify($password);

            return false;
        }

        return password_verify($password, $hash);
    }

    public static function needsRehash(string $hash): bool
    {
        if (defined('PASSWORD_ARGON2ID') && in_array('argon2id', password_algos(), true)) {
            return password_needs_rehash($hash, PASSWORD_ARGON2ID, self::argonOptions());
        }

        return password_needs_rehash($hash, PASSWORD_DEFAULT);
    }

    public static function dummyVerify(string $password): void
    {
        password_verify($password, self::DUMMY_HASH);
    }
}
