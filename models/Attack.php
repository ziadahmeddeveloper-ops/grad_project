<?php
namespace Models;

use Config\Database;
use PDO;

class Attack {
    private $conn;

    public function __construct() {
        $this->conn = Database::getConnection();
    }

    public function create($data) {
        $stmt = $this->conn->prepare("
            INSERT INTO attacks (source_type, attack_type, attack_name, threat_score, threat_level, source_ip, username, event_time, recommended_actions, raw_context, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        $source_type = $data['source_type'] ?? null;
        $attack_type = $data['attack_type'] ?? 'unknown';
        $attack_name = $data['attack_name'] ?? 'unknown';
        $threat_score = $data['threat_score'] ?? 0;
        $threat_level = $data['threat_level'] ?? 'low';
        $source_ip = $data['source_ip'] ?? null;
        $username = $data['username'] ?? null;
        $event_time = $data['event_time'] ?? date('Y-m-d H:i:s');
        $recommended_actions = $data['recommended_actions'] ?? null;
        $raw_context = $data['raw_context'] ?? null;
        $status = 'active';

        $stmt->execute([$source_type, $attack_type, $attack_name, $threat_score, $threat_level, $source_ip, $username, $event_time, $recommended_actions, $raw_context, $status]);
        return $this->conn->lastInsertId();
    }

    public function addLog($attackId, $logText) {
        $stmt = $this->conn->prepare("INSERT INTO attack_logs (attack_id, log_text) VALUES (?, ?)");
        return $stmt->execute([$attackId, $logText]);
    }

    public function addTimeline($attackId, $timestamp, $description) {
        $stmt = $this->conn->prepare("INSERT INTO attack_timelines (attack_id, timestamp, description) VALUES (?, ?, ?)");
        return $stmt->execute([$attackId, $timestamp, $description]);
    }

    public function getAll($page = 1, $limit = 10, $filters = []) {
        $offset = ($page - 1) * $limit;
        
        $query = "SELECT * FROM attacks WHERE 1=1";
        $params = [];

        if (!empty($filters['threat_level'])) {
            $query .= " AND threat_level = ?";
            $params[] = $filters['threat_level'];
        }
        
        if (!empty($filters['attack_type'])) {
            $query .= " AND attack_type LIKE ?";
            $params[] = "%" . $filters['attack_type'] . "%";
        }
        
        if (!empty($filters['status'])) {
            $query .= " AND status = ?";
            $params[] = $filters['status'];
        }
        
        if (!empty($filters['source_ip'])) {
            $query .= " AND source_ip LIKE ?";
            $params[] = "%" . $filters['source_ip'] . "%";
        }

        // Count total
        $countQuery = str_replace("SELECT *", "SELECT COUNT(*) as total", $query);
        $countStmt = $this->conn->prepare($countQuery);
        $countStmt->execute($params);
        $total = $countStmt->fetch()['total'];

        // Get data
        $query .= " ORDER BY id DESC LIMIT $limit OFFSET $offset";
        
        // Ensure limit/offset are ints to prevent SQL syntax errors
        $query = str_replace(['$limit', '$offset'], [(int)$limit, (int)$offset], $query);
        
        $stmt = $this->conn->prepare($query);
        $stmt->execute($params);
        $data = $stmt->fetchAll();

        return [
            'data' => $data,
            'total' => $total,
            'page' => (int)$page,
            'limit' => (int)$limit,
            'total_pages' => ceil($total / $limit)
        ];
    }

    public function getById($id) {
        $stmt = $this->conn->prepare("SELECT * FROM attacks WHERE id = ?");
        $stmt->execute([$id]);
        $attack = $stmt->fetch();

        if ($attack) {
            // Get logs
            $logsStmt = $this->conn->prepare("SELECT log_text FROM attack_logs WHERE attack_id = ?");
            $logsStmt->execute([$id]);
            $attack['logs'] = $logsStmt->fetchAll(PDO::FETCH_COLUMN);

            // Get timeline
            $timelineStmt = $this->conn->prepare("SELECT timestamp, description FROM attack_timelines WHERE attack_id = ? ORDER BY id ASC");
            $timelineStmt->execute([$id]);
            $attack['timeline'] = $timelineStmt->fetchAll();
        }

        return $attack;
    }

    public function updateStatus($id, $status) {
        $stmt = $this->conn->prepare("UPDATE attacks SET status = ? WHERE id = ?");
        return $stmt->execute([$status, $id]);
    }

    public function delete($id) {
        $stmt = $this->conn->prepare("DELETE FROM attacks WHERE id = ?");
        return $stmt->execute([$id]);
    }

    public function getRecent($limit = 10) {
        // Need to turn off emulate prepares or bind limit explicitly
        $this->conn->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
        $stmt = $this->conn->prepare("SELECT * FROM attacks ORDER BY created_at DESC, id DESC LIMIT ?");
        $stmt->execute([$limit]);
        return $stmt->fetchAll();
    }
}
