<?php
namespace Controllers;

use Core\Request;
use Core\Response;
use Config\Database;
use PDO;

class DashboardController {
    private $conn;

    public function __construct() {
        $this->conn = Database::getConnection();
    }

    public function stats(Request $request) {
        $stats = [
            'totalAttacks' => 0,
            'highSeverity' => 0,
            'activeThreats' => 0,
            'resolved' => 0
        ];

        $stmt = $this->conn->query("
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN threat_level = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved
            FROM attacks
        ");

        if ($row = $stmt->fetch()) {
            $stats['totalAttacks'] = (int) $row['total'];
            $stats['highSeverity'] = (int) $row['high'];
            $stats['activeThreats'] = (int) $row['active'];
            $stats['resolved'] = (int) $row['resolved'];
        }

        Response::success($stats);
    }

    public function charts(Request $request) {
        $stmtOverTime = $this->conn->query("
            SELECT DATE(created_at) as date, COUNT(*) as count 
            FROM attacks 
            GROUP BY DATE(created_at) 
            ORDER BY date DESC LIMIT 7
        ");
        $attacksOverTime = $stmtOverTime->fetchAll();

        $stmtSeverity = $this->conn->query("
            SELECT threat_level as severity, COUNT(*) as count 
            FROM attacks 
            GROUP BY threat_level
        ");
        $severityDistribution = $stmtSeverity->fetchAll();

        Response::success([
            'attacksOverTime' => $attacksOverTime,
            'severityDistribution' => $severityDistribution
        ]);
    }
}
