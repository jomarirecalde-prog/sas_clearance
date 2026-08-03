<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Services\ClearanceService;

final class ClearanceController
{
    public function __construct(private readonly ClearanceService $clearanceService)
    {
    }

    public function health(): void
    {
        $this->json([
            'ok' => true,
            'service' => 'wpu-clearance',
        ]);
    }

    public function studentOverview(int $studentId, int $semesterId): void
    {
        $data = $this->clearanceService->getStudentClearanceOverview($studentId, $semesterId);
        $this->json(['data' => $data]);
    }

    public function officeDecision(
        int $officeId,
        int $studentId,
        int $semesterId,
        int $signatoryId,
        string $status,
        ?string $reason
    ): void {
        $result = $this->clearanceService->decideOfficeClearance(
            $officeId,
            $studentId,
            $semesterId,
            $status,
            $signatoryId,
            $reason
        );

        $this->json($result, $result['ok'] ? 200 : 422);
    }

    private function json(array $payload, int $statusCode = 200): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        echo json_encode($payload);
    }
}
