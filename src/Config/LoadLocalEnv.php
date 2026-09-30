<?php

declare(strict_types=1);

namespace App\Config;

/**
 * Loads KEY=VALUE lines from a .env file when Apache/CLI has not already set them.
 */
final class LoadLocalEnv
{
    public static function load(string $path): void
    {
        if (!is_readable($path)) {
            return;
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            return;
        }

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $eq = strpos($line, '=');
            if ($eq === false) {
                continue;
            }
            $key = trim(substr($line, 0, $eq));
            if ($key === '') {
                continue;
            }
            if (getenv($key) !== false) {
                continue;
            }
            $value = trim(substr($line, $eq + 1));
            if (
                strlen($value) >= 2
                && (($value[0] === '"' && $value[strlen($value) - 1] === '"')
                    || ($value[0] === "'" && $value[strlen($value) - 1] === "'"))
            ) {
                $value = substr($value, 1, -1);
            }
            putenv($key . '=' . $value);
            $_ENV[$key] = $value;
        }
    }
}
