<?php
namespace Controllers;

use Core\Request;
use Core\Response;
use Config\Database;
use PDO;

class ReportController {
    private $conn;

    public function __construct() {
        $this->conn = Database::getConnection();
    }

    public function generate(Request $request, $period) {
        $validPeriods = ['daily', 'weekly', 'monthly'];
        if (!in_array($period, $validPeriods)) {
            Response::error('Invalid period. Must be daily, weekly, or monthly.', 400);
        }

        $dateFilter = "";
        if ($period == 'daily') {
            $dateFilter = "AND created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)";
        } elseif ($period == 'weekly') {
            $dateFilter = "AND created_at >= DATE_SUB(NOW(), INTERVAL 1 WEEK)";
        } elseif ($period == 'monthly') {
            $dateFilter = "AND created_at >= DATE_SUB(NOW(), INTERVAL 1 MONTH)";
        }

        $stmt = $this->conn->query("
            SELECT 
                id, source_type, attack_type, attack_name, threat_score, threat_level, 
                source_ip, username, event_time, status, created_at 
            FROM attacks 
            WHERE 1=1 $dateFilter
            ORDER BY created_at DESC
        ");
        
        $attacks = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $summaryStmt = $this->conn->query("
            SELECT 
                COUNT(*) as total_attacks,
                SUM(CASE WHEN threat_level = 'high' THEN 1 ELSE 0 END) as high_severity,
                SUM(CASE WHEN threat_level = 'medium' THEN 1 ELSE 0 END) as medium_severity,
                SUM(CASE WHEN threat_level = 'low' THEN 1 ELSE 0 END) as low_severity
            FROM attacks
            WHERE 1=1 $dateFilter
        ");
        $summary = $summaryStmt->fetch(PDO::FETCH_ASSOC);

        $report = [
            'period' => $period,
            'generated_at' => date('Y-m-d H:i:s'),
            'summary' => [
                'total_attacks' => (int)($summary['total_attacks'] ?? 0),
                'high_severity' => (int)($summary['high_severity'] ?? 0),
                'medium_severity' => (int)($summary['medium_severity'] ?? 0),
                'low_severity' => (int)($summary['low_severity'] ?? 0)
            ],
            'attacks' => $attacks
        ];

        Response::success($report, ['message' => ucfirst($period) . ' report generated successfully']);
    }
}
