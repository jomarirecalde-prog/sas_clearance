<?php

declare(strict_types=1);

require __DIR__ . '/../src/Support/StudentPwa.php';

App\Support\StudentPwa::ensureIcons();
foreach ([192, 512] as $size) {
    $path = App\Support\StudentPwa::iconPath($size);
    echo $size . ' ' . filesize($path) . ' ' . $path . PHP_EOL;
}
