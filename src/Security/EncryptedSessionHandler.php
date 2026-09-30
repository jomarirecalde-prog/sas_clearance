<?php

declare(strict_types=1);

namespace App\Security;

use SessionHandlerInterface;
use SessionUpdateTimestampHandlerInterface;

/**
 * Stores PHP session payloads encrypted with AES-256-GCM.
 */
final class EncryptedSessionHandler implements SessionHandlerInterface, SessionUpdateTimestampHandlerInterface
{
    public function __construct(private readonly string $savePath)
    {
    }

    public function open(string $path, string $name): bool
    {
        if (!is_dir($this->savePath) && !mkdir($this->savePath, 0700, true) && !is_dir($this->savePath)) {
            return false;
        }

        return true;
    }

    public function close(): bool
    {
        return true;
    }

    public function read(string $id): string|false
    {
        $file = $this->filePath($id);
        if ($file === null || !is_file($file)) {
            return '';
        }

        $payload = file_get_contents($file);
        if (!is_string($payload) || $payload === '') {
            return '';
        }

        try {
            return Crypto::decrypt($payload);
        } catch (\Throwable) {
            return '';
        }
    }

    public function write(string $id, string $data): bool
    {
        $file = $this->filePath($id);
        if ($file === null) {
            return false;
        }

        try {
            $encrypted = Crypto::encrypt($data);
        } catch (\Throwable) {
            return false;
        }

        $ok = file_put_contents($file, $encrypted, LOCK_EX);
        if ($ok === false) {
            return false;
        }
        @chmod($file, 0600);

        return true;
    }

    public function destroy(string $id): bool
    {
        $file = $this->filePath($id);
        if ($file === null || !is_file($file)) {
            return true;
        }

        return @unlink($file);
    }

    public function gc(int $max_lifetime): int|false
    {
        $deleted = 0;
        $files = glob($this->savePath . DIRECTORY_SEPARATOR . '*.sess') ?: [];
        $cutoff = time() - $max_lifetime;
        foreach ($files as $file) {
            $mtime = @filemtime($file);
            if ($mtime !== false && $mtime < $cutoff) {
                if (@unlink($file)) {
                    $deleted++;
                }
            }
        }

        return $deleted;
    }

    public function validateId(string $id): bool
    {
        $file = $this->filePath($id);
        return $file !== null && is_file($file);
    }

    public function updateTimestamp(string $id, string $data): bool
    {
        $file = $this->filePath($id);
        if ($file === null || !is_file($file)) {
            return false;
        }

        return @touch($file);
    }

    public static function directory(): string
    {
        return dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'sessions';
    }

    private function filePath(string $id): ?string
    {
        if (preg_match('/^[a-zA-Z0-9,-]+$/', $id) !== 1) {
            return null;
        }

        return $this->savePath . DIRECTORY_SEPARATOR . hash('sha256', $id) . '.sess';
    }
}
