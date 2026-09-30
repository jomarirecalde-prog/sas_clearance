<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/Config/LoadLocalEnv.php';

\App\Config\LoadLocalEnv::load(dirname(__DIR__) . '/.env');

$host = getenv('DB_HOST') ?: '127.0.0.1';
$port = (int) (getenv('DB_PORT') ?: 3306);
$user = getenv('DB_USER') ?: 'root';
$pass = getenv('DB_PASSWORD') ?: '';
$dbName = getenv('DB_NAME') ?: 'wpu_clearance';
$root = dirname(__DIR__);

try {
    $pdo = new PDO(
        sprintf('mysql:host=%s;port=%d;charset=utf8mb4', $host, $port),
        $user,
        $pass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (PDOException $e) {
    fwrite(STDERR, "Connection failed: " . $e->getMessage() . PHP_EOL);
    exit(1);
}

$quotedDb = '`' . str_replace('`', '``', $dbName) . '`';
$pdo->exec("DROP DATABASE IF EXISTS $quotedDb");
$pdo->exec(
    sprintf(
        'CREATE DATABASE %s CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci',
        $quotedDb
    )
);
$pdo->exec("USE $quotedDb");

foreach (['schema.sql', 'seed.sql'] as $file) {
    $path = $root . '/database/' . $file;
    if (!is_file($path)) {
        fwrite(STDERR, "Missing: $path" . PHP_EOL);
        exit(1);
    }
    $sql = file_get_contents($path);
    if ($sql === false || trim($sql) === '') {
        fwrite(STDERR, "Empty SQL: $path" . PHP_EOL);
        exit(1);
    }
    $pdo->exec($sql);
    echo "Imported $file" . PHP_EOL;
}

$count = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
echo "Database ready ($dbName). Users in seed: $count" . PHP_EOL;
