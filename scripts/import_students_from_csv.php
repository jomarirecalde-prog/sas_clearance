<?php

declare(strict_types=1);

/**
 * CLI: bulk-import students from a CSV (save from Excel as CSV).
 *
 * Usage: php import_students_from_csv.php path\to\file.csv
 */

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "Run this script from the command line only.\n");
    exit(1);
}

$csvPath = $argv[1] ?? '';
if ($csvPath === '' || !is_readable($csvPath)) {
    fwrite(STDERR, "Usage: php import_students_from_csv.php <path-to.csv>\n");
    fwrite(STDERR, "File not found or not readable: {$csvPath}\n");
    exit(1);
}

require_once dirname(__DIR__) . '/src/Config/Database.php';
require_once dirname(__DIR__) . '/src/Services/ClearanceService.php';
require_once dirname(__DIR__) . '/src/Services/StudentCsvImporter.php';

use App\Config\Database;
use App\Services\ClearanceService;
use App\Services\StudentCsvImporter;

echo "File: {$csvPath}\n";

$pdo = Database::pdo();
$service = new ClearanceService($pdo);
$importer = new StudentCsvImporter($service);

$result = $importer->importFromPath($csvPath);

if ($result['errors'] !== [] && $result['saved'] === 0 && $result['failed'] === 0) {
    foreach ($result['errors'] as $e) {
        fwrite(STDERR, $e . "\n");
    }
    exit(1);
}

if ($result['no_data']) {
    if ($result['errors'] === []) {
        echo "No data rows imported (only header or empty rows?).\n";
    }
    exit(3);
}

echo "Import finished: {$result['saved']} saved, {$result['failed']} failed.\n";
foreach ($result['errors'] as $e) {
    echo $e . "\n";
}

exit($result['failed'] > 0 ? 2 : 0);
