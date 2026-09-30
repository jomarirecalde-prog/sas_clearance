<?php

declare(strict_types=1);

namespace App\Config;

use PDO;
use PDOException;

final class Database
{
    private const DEFAULT_HOST = '127.0.0.1';
    private const DEFAULT_PORT = 3306;
    private const DEFAULT_DBNAME = 'wpu_clearance';
    private const DEFAULT_USERNAME = 'root';
    private const DEFAULT_PASSWORD = '';

    public static function pdo(): PDO
    {
        $host = self::env('DB_HOST', self::DEFAULT_HOST);
        $port = (int) self::env('DB_PORT', (string) self::DEFAULT_PORT);
        if ($port <= 0) {
            $port = self::DEFAULT_PORT;
        }
        $dbname = self::env('DB_NAME', self::DEFAULT_DBNAME);
        $username = self::env('DB_USER', self::DEFAULT_USERNAME);
        $password = self::env('DB_PASSWORD', self::DEFAULT_PASSWORD);

        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
            $host,
            $port,
            $dbname
        );

        try {
            $pdo = new PDO(
                $dsn,
                $username,
                $password,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                ]
            );
            self::ensureYearLevelColumn($pdo);
            self::ensureStudentAccountTypeColumn($pdo);
            self::ensureStudentOrgPositionColumn($pdo);
            self::ensureStudentStayingColumn($pdo);
            self::ensureStudentCampusColumn($pdo);

            return $pdo;
        } catch (PDOException $exception) {
            error_log('Database connection failed: ' . $exception->getMessage());
            http_response_code(500);
            header('Content-Type: application/json');
            echo json_encode([
                'error' => 'Service unavailable.',
            ]);
            exit;
        }
    }

    private static function env(string $key, string $default): string
    {
        $value = getenv($key);

        return $value === false ? $default : $value;
    }

    /**
     * Adds users.year_level when missing (e.g. SQL migration not applied yet).
     */
    private static function ensureYearLevelColumn(PDO $pdo): void
    {
        static $checked = false;
        if ($checked) {
            return;
        }
        $checked = true;

        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = :schema AND TABLE_NAME = :tbl AND COLUMN_NAME = :col'
        );
        $stmt->execute([
            'schema' => self::env('DB_NAME', self::DEFAULT_DBNAME),
            'tbl' => 'users',
            'col' => 'year_level',
        ]);
        if ((int) $stmt->fetchColumn() > 0) {
            return;
        }

        try {
            $pdo->exec(
                "ALTER TABLE users ADD COLUMN year_level ENUM('1', '2', '3', '4', '5+') NULL"
            );
        } catch (PDOException $e) {
            if (!str_contains($e->getMessage(), 'Duplicate column name')) {
                throw $e;
            }
        }

        $pdo->exec("UPDATE users SET year_level = '1' WHERE role = 'student' AND year_level IS NULL");
    }

    /**
     * Adds users.student_account_type when missing (e.g. SQL migration not applied yet).
     */
    private static function ensureStudentAccountTypeColumn(PDO $pdo): void
    {
        static $checked = false;
        if ($checked) {
            return;
        }
        $checked = true;

        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = :schema AND TABLE_NAME = :tbl AND COLUMN_NAME = :col'
        );
        $stmt->execute([
            'schema' => self::env('DB_NAME', self::DEFAULT_DBNAME),
            'tbl' => 'users',
            'col' => 'student_account_type',
        ]);
        if ((int) $stmt->fetchColumn() > 0) {
            return;
        }

        try {
            $pdo->exec(
                "ALTER TABLE users ADD COLUMN student_account_type ENUM('paying_tuition', 'not_paying_tuition') NULL"
            );
        } catch (PDOException $e) {
            if (!str_contains($e->getMessage(), 'Duplicate column name')) {
                throw $e;
            }
        }

        $pdo->exec(
            "UPDATE users SET student_account_type = 'paying_tuition' WHERE role = 'student' AND student_account_type IS NULL"
        );
    }

    /**
     * Adds users.student_org_position when missing (e.g. SQL migration not applied yet).
     */
    private static function ensureStudentOrgPositionColumn(PDO $pdo): void
    {
        static $checked = false;
        if ($checked) {
            return;
        }
        $checked = true;

        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = :schema AND TABLE_NAME = :tbl AND COLUMN_NAME = :col'
        );
        $stmt->execute([
            'schema' => self::env('DB_NAME', self::DEFAULT_DBNAME),
            'tbl' => 'users',
            'col' => 'student_org_position',
        ]);
        if ((int) $stmt->fetchColumn() > 0) {
            return;
        }

        try {
            $pdo->exec(
                "ALTER TABLE users ADD COLUMN student_org_position ENUM('president', 'vice_president', 'treasurer', 'secretary', 'auditor', 'na') NULL"
            );
        } catch (PDOException $e) {
            if (!str_contains($e->getMessage(), 'Duplicate column name')) {
                throw $e;
            }
        }

        $pdo->exec(
            "UPDATE users SET student_org_position = 'na' WHERE role = 'student' AND student_org_position IS NULL"
        );
    }

    /**
     * Adds users.student_staying when missing (e.g. SQL migration not applied yet).
     */
    private static function ensureStudentStayingColumn(PDO $pdo): void
    {
        static $checked = false;
        if ($checked) {
            return;
        }
        $checked = true;

        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = :schema AND TABLE_NAME = :tbl AND COLUMN_NAME = :col'
        );
        $stmt->execute([
            'schema' => self::env('DB_NAME', self::DEFAULT_DBNAME),
            'tbl' => 'users',
            'col' => 'student_staying',
        ]);
        if ((int) $stmt->fetchColumn() > 0) {
            return;
        }

        try {
            $pdo->exec(
                "ALTER TABLE users ADD COLUMN student_staying ENUM('wpu_dormitory', 'outside_dormitory', 'commuter') NULL"
            );
        } catch (PDOException $e) {
            if (!str_contains($e->getMessage(), 'Duplicate column name')) {
                throw $e;
            }
        }
    }

    /**
     * Adds users.campus when missing (e.g. SQL migration not applied yet).
     */
    private static function ensureStudentCampusColumn(PDO $pdo): void
    {
        static $checked = false;
        if ($checked) {
            return;
        }
        $checked = true;

        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = :schema AND TABLE_NAME = :tbl AND COLUMN_NAME = :col'
        );
        $stmt->execute([
            'schema' => self::env('DB_NAME', self::DEFAULT_DBNAME),
            'tbl' => 'users',
            'col' => 'campus',
        ]);
        if ((int) $stmt->fetchColumn() === 0) {
            try {
                $pdo->exec(
                    "ALTER TABLE users ADD COLUMN campus ENUM('puerto_princesa', 'quezon', 'rio_tuba', 'el_nido', 'canique', 'busuanga') NULL AFTER program_id"
                );
            } catch (PDOException $e) {
                if (!str_contains($e->getMessage(), 'Duplicate column name')) {
                    throw $e;
                }
            }
        }

        $demoCampuses = [
            'student@wpu.edu.ph' => 'puerto_princesa',
            'maria.santos@wpu.edu.ph' => 'canique',
            'pedro.reyes@wpu.edu.ph' => 'quezon',
            'ana.cruz@wpu.edu.ph' => 'el_nido',
            'jose.ramos@wpu.edu.ph' => 'rio_tuba',
            'liza.mendoza@wpu.edu.ph' => 'busuanga',
        ];
        $update = $pdo->prepare(
            "UPDATE users SET campus = :campus WHERE role = 'student' AND email = :email AND campus IS NULL"
        );
        foreach ($demoCampuses as $email => $campus) {
            $update->execute(['campus' => $campus, 'email' => $email]);
        }
    }
}
