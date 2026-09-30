<?php

declare(strict_types=1);

$path = dirname(__DIR__) . '/public/index.php';
$s = file_get_contents($path);

$paths = [
    '/logout',
    '/login',
    '/forgot-password',
    '/reset-password',
    '/dashboard',
    '/assets/wpu-logo.png',
    '/student/clearance-message/send',
    '/signatory/clearance-message/send',
    '/student/final-clearance',
    '/student/deadline-countdown',
    '/student/upload',
    '/signatory/office-requirement/add',
    '/signatory/office-requirement/update',
    '/signatory/office-requirement/delete',
    '/signatory/decision',
    '/signatory/signature/upload',
    '/admin/signatories',
    '/admin/register-students',
    '/admin/settings',
    '/admin/settings/profile',
    '/admin/settings/photo',
    '/admin/colleges-programs',
    '/admin/final-clearance',
    '/admin/reports',
    '/admin/pending-departments',
    '/admin/college',
    '/admin/program/delete',
    '/admin/student/update',
    '/admin/download-students-csv-template',
    '/admin/import-students-csv',
    '/admin/semester',
    '/admin/semester/deadline',
    '/admin/semester/clearance-window',
    '/admin/requirement',
    '/admin/requirement/update',
    '/admin/current-requirements',
    '/admin/requirement/delete',
    '/admin/signatory/update',
    '/admin/add-signatory',
    '/admin/signatory-office/add',
    '/admin/signatory-office/deactivate',
    '/admin/assign-signatory',
    '/admin/assign-dean-college',
    '/admin/signatory/remove-assignment',
    '/admin/signatory/deactivate',
    '/admin/signatory/reactivate',
    '/admin/student/deactivate',
    '/admin/student/reactivate',
    '/admin/students/delete-selected',
    '/admin/students/delete-all',
];

foreach ($paths as $p) {
    foreach (['action', 'href', 'src'] as $attr) {
        $old = $attr . '="' . $p . '"';
        $new = $attr . '="' . "' . hpath('" . $p . "') . " . chr(34);
        $s = str_replace($old, $new, $s);
    }
}

file_put_contents($path, $s);
echo "Done.\n";
