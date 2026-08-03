<?php



declare(strict_types=1);



namespace App\Services;



final class StudentCsvImporter

{

    private const REQUIRED = ['student_no', 'email', 'password', 'college_code', 'program_code', 'year_level'];



    /** @var list<string> */

    private const FULL_NAME_COLUMNS = ['full_name', 'name', 'student_name'];



    public function __construct(private readonly ClearanceService $clearance)

    {

    }



    /**

     * @return array{saved:int, failed:int, errors:list<string>, no_data:bool}

     */

    public function importFromPath(string $csvPath): array

    {

        $raw = file_get_contents($csvPath);

        if ($raw === false || $raw === '') {

            return ['saved' => 0, 'failed' => 0, 'errors' => ['Cannot read CSV or file is empty.'], 'no_data' => true];

        }

        $raw = preg_replace('/^\xEF\xBB\xBF/', '', $raw) ?? $raw;

        if (str_starts_with($raw, "\xFF\xFE")) {

            if (!function_exists('mb_convert_encoding')) {

                return [

                    'saved' => 0,

                    'failed' => 0,

                    'errors' => ['UTF-16 CSV: enable php_mbstring or save as UTF-8 CSV from Excel.'],

                    'no_data' => true,

                ];

            }

            $raw = mb_convert_encoding(substr($raw, 2), 'UTF-8', 'UTF-16LE');

        }



        if (!preg_match('/^[^\r\n]++/', $raw, $m)) {

            return ['saved' => 0, 'failed' => 0, 'errors' => ['CSV has no lines.'], 'no_data' => true];

        }

        $firstLine = $m[0];

        $delimiter = substr_count($firstLine, ';') > substr_count($firstLine, ',') ? ';' : ',';



        $stream = fopen('php://temp', 'r+b');

        if ($stream === false) {

            return ['saved' => 0, 'failed' => 0, 'errors' => ['Internal error opening stream.'], 'no_data' => true];

        }

        fwrite($stream, $raw);

        rewind($stream);



        $headerRow = fgetcsv($stream, 0, $delimiter);

        if ($headerRow === false || $headerRow === [null]) {

            fclose($stream);



            return ['saved' => 0, 'failed' => 0, 'errors' => ['Missing header row.'], 'no_data' => true];

        }



        $colIndex = [];

        foreach ($headerRow as $i => $cell) {

            $key = self::normalizeHeaderCell((string) $cell);

            if ($key !== '') {

                $colIndex[$key] = $i;

            }

        }



        $missing = [];

        foreach (self::REQUIRED as $name) {

            if (!isset($colIndex[$name])) {

                $missing[] = $name;

            }

        }

        $fullNameKey = self::resolveFullNameColumnKey($colIndex);

        $hasSeparateNames = isset($colIndex['first_name'], $colIndex['last_name']);

        if ($fullNameKey === null && !$hasSeparateNames) {

            $missing[] = 'full_name (or first_name and last_name)';

        }

        if ($missing !== []) {

            fclose($stream);



            return [

                'saved' => 0,

                'failed' => 0,

                'errors' => [

                    'Missing column(s): ' . implode(', ', $missing),

                    'Required: ' . implode(', ', self::REQUIRED) . ', full_name',

                    'Found: ' . implode(', ', array_keys($colIndex)),

                ],

                'no_data' => true,

            ];

        }



        $ok = 0;

        $fail = 0;

        $errors = [];

        $lineNo = 1;



        $cell = static function (array $row, array $colIndex, string $name): string {

            $idx = $colIndex[$name];



            return trim((string) ($row[$idx] ?? ''));

        };



        while (($row = fgetcsv($stream, 0, $delimiter)) !== false) {

            $lineNo++;

            if ($row === [null] || $row === []) {

                continue;

            }

            $nonEmpty = false;

            foreach ($row as $c) {

                if (trim((string) $c) !== '') {

                    $nonEmpty = true;

                    break;

                }

            }

            if (!$nonEmpty) {

                continue;

            }



            $sn = $cell($row, $colIndex, 'student_no');

            if ($sn === '' && $cell($row, $colIndex, 'email') === '') {

                continue;

            }



            if ($hasSeparateNames) {

                $firstName = $cell($row, $colIndex, 'first_name');

                $lastName = $cell($row, $colIndex, 'last_name');

            } else {

                [$firstName, $lastName] = self::splitFullName($cell($row, $colIndex, (string) $fullNameKey));

            }



            $acctType = 'paying_tuition';
            if (isset($colIndex['student_account_type'])) {
                $acctType = $cell($row, $colIndex, 'student_account_type');
            } elseif (isset($colIndex['student_account'])) {
                $acctType = $cell($row, $colIndex, 'student_account');
            }

            $orgPos = 'na';
            if (isset($colIndex['student_org_position'])) {
                $orgPos = $cell($row, $colIndex, 'student_org_position');
            } elseif (isset($colIndex['org_position'])) {
                $orgPos = $cell($row, $colIndex, 'org_position');
            }

            $staying = 'commuter';
            if (isset($colIndex['student_staying'])) {
                $staying = $cell($row, $colIndex, 'student_staying');
            } elseif (isset($colIndex['students_staying'])) {
                $staying = $cell($row, $colIndex, 'students_staying');
            }

            $result = $this->clearance->registerStudentWithCollegeProgramByCodes(

                $sn,

                $firstName,

                $lastName,

                $cell($row, $colIndex, 'email'),

                $cell($row, $colIndex, 'password'),

                $cell($row, $colIndex, 'college_code'),

                $cell($row, $colIndex, 'program_code'),

                $cell($row, $colIndex, 'year_level'),

                $acctType,

                $orgPos,

                $staying

            );

            if ($result['ok']) {

                $ok++;

            } else {

                $fail++;

                $errors[] = 'Line ' . $lineNo . ' (' . $sn . ' / ' . $cell($row, $colIndex, 'email') . '): ' . $result['message'];

            }

        }



        fclose($stream);



        return [

            'saved' => $ok,

            'failed' => $fail,

            'errors' => $errors,

            'no_data' => $ok === 0 && $fail === 0,

        ];

    }



    private static function normalizeHeaderCell(string $h): string

    {

        $h = trim($h);

        $h = trim($h, "\"\xEF\xBB\xBF");

        $h = strtolower($h);

        $h = preg_replace('/[\s\-]+/', '_', $h) ?? $h;



        return $h;

    }



    /**

     * @param array<string, int> $colIndex

     */

    private static function resolveFullNameColumnKey(array $colIndex): ?string

    {

        foreach (self::FULL_NAME_COLUMNS as $key) {

            if (isset($colIndex[$key])) {

                return $key;

            }

        }



        return null;

    }



    /**

     * @return array{0: string, 1: string}

     */

    public static function splitFullName(string $full): array

    {

        $full = trim(preg_replace('/\s+/u', ' ', $full) ?? '');

        if ($full === '') {

            return ['', ''];

        }

        $pos = strrpos($full, ' ');

        if ($pos === false) {

            return [$full, $full];

        }



        return [trim(substr($full, 0, $pos)), trim(substr($full, $pos + 1))];

    }

}

