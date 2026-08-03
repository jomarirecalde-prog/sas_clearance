<?php

declare(strict_types=1);

namespace App\Config;

use PDO;
use PDOException;

final class Database
{
    private const HOST = '127.0.0.1';
    private const PORT = 3306;
    private const DBNAME = 'wpu_clearance';
    private const USERNAME = 'root';
    private const PASSWORD = '';

    public static function pdo(): PDO
    {
        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
            self::HOST,
            self::PORT,
            self::DBNAME
        );

        try {
            $pdo = new PDO(
                $dsn,
                self::USERNAME,
                self::PASSWORD,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                ]
            );
            self::ensureYearLevelColumn($pdo);
            self::ensureStudentAccountTypeColumn($pdo);
            self::ensureStudentOrgPositionColumn($pdo);
            self::ensureStudentStayingColumn($pdo);

            return $pdo;
        } catch (PDOException $exception) {
            http_response_code(500);
            header('Content-Type: application/json');
            echo json_encode([
                'error' => 'Database connection failed.',
                'details' => $exception->getMessage(),
            ]);
            exit;
        }
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
            'schema' => self::DBNAME,
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
            'schema' => self::DBNAME,
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
            'schema' => self::DBNAME,
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
            'schema' => self::DBNAME,
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
}
