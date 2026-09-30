<?php

declare(strict_types=1);

namespace App\Security;

use RuntimeException;

/**
 * AES-256-GCM encryption for authentication data at rest (sessions, tokens).
 */
final class Crypto
{
    private const CIPHER = 'aes-256-gcm';
    private const KEY_BYTES = 32;
    private const NONCE_BYTES = 12;
    private const TAG_BYTES = 16;
    private const VERSION = 'v1';

    private static ?string $key = null;

    public static function key(): string
    {
        if (self::$key !== null) {
            return self::$key;
        }

        $fromEnv = trim((string) (getenv('APP_ENCRYPTION_KEY') ?: ''));
        if ($fromEnv !== '') {
            self::$key = self::parseKey($fromEnv);
            return self::$key;
        }

        $path = self::keyPath();
        if (is_file($path)) {
            $stored = trim((string) file_get_contents($path));
            if ($stored !== '') {
                self::$key = self::parseKey($stored);
                return self::$key;
            }
        }

        $raw = random_bytes(self::KEY_BYTES);
        self::persistKey($path, bin2hex($raw));
        self::$key = $raw;

        return self::$key;
    }

    public static function encrypt(string $plaintext): string
    {
        $nonce = random_bytes(self::NONCE_BYTES);
        $tag = '';
        $cipher = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            self::key(),
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            '',
            self::TAG_BYTES
        );
        if ($cipher === false || strlen($tag) !== self::TAG_BYTES) {
            throw new RuntimeException('Unable to encrypt authentication data.');
        }

        return self::VERSION . ':' . base64_encode($nonce . $tag . $cipher);
    }

    public static function decrypt(string $payload): string
    {
        $prefix = self::VERSION . ':';
        if (!str_starts_with($payload, $prefix)) {
            throw new RuntimeException('Unsupported encrypted payload.');
        }

        $raw = base64_decode(substr($payload, strlen($prefix)), true);
        if ($raw === false || strlen($raw) < (self::NONCE_BYTES + self::TAG_BYTES)) {
            throw new RuntimeException('Malformed encrypted payload.');
        }

        $nonce = substr($raw, 0, self::NONCE_BYTES);
        $tag = substr($raw, self::NONCE_BYTES, self::TAG_BYTES);
        $cipher = substr($raw, self::NONCE_BYTES + self::TAG_BYTES);
        $plain = openssl_decrypt(
            $cipher,
            self::CIPHER,
            self::key(),
            OPENSSL_RAW_DATA,
            $nonce,
            $tag
        );
        if ($plain === false) {
            throw new RuntimeException('Unable to decrypt authentication data.');
        }

        return $plain;
    }

    public static function hmac(string $value): string
    {
        return hash_hmac('sha256', $value, self::key());
    }

    public static function identifierHash(string $action, string $subject): string
    {
        return hash_hmac('sha256', strtolower($action) . "\0" . strtolower($subject), self::key());
    }

    public static function keyPath(): string
    {
        return dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'app.key';
    }

    private static function parseKey(string $value): string
    {
        $value = trim($value);
        if (str_starts_with($value, 'base64:')) {
            $decoded = base64_decode(substr($value, 7), true);
            if (is_string($decoded) && strlen($decoded) === self::KEY_BYTES) {
                return $decoded;
            }
        }
        if (preg_match('/^[a-f0-9]{64}$/i', $value) === 1) {
            $decoded = hex2bin($value);
            if (is_string($decoded) && strlen($decoded) === self::KEY_BYTES) {
                return $decoded;
            }
        }
        $decoded = base64_decode($value, true);
        if (is_string($decoded) && strlen($decoded) === self::KEY_BYTES) {
            return $decoded;
        }

        throw new RuntimeException('APP_ENCRYPTION_KEY must be a 32-byte key (hex or base64).');
    }

    private static function persistKey(string $path, string $hexKey): void
    {
        $dir = dirname($path);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException('Unable to create storage directory for the encryption key.');
        }

        $written = file_put_contents($path, $hexKey, LOCK_EX);
        if ($written === false) {
            throw new RuntimeException('Unable to persist the application encryption key.');
        }
        @chmod($path, 0600);
    }
}
