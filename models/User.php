<?php
namespace Models;

use Config\Database;
use PDO;

class User {
    private $conn;

    public function __construct() {
        $this->conn = Database::getConnection();
    }

    public function findByUsername($username) {
        $stmt = $this->conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        return $stmt->fetch();
    }

    public function create($name, $username, $password) {
        $stmt = $this->conn->prepare("INSERT INTO users (name, username, password) VALUES (?, ?, ?)");
        return $stmt->execute([$name, $username, password_hash($password, PASSWORD_DEFAULT)]);
    }

    public function createToken($userId) {
        $token = bin2hex(random_bytes(32));
        $expires = date('Y-m-d H:i:s', strtotime('+7 days'));
        
        $stmt = $this->conn->prepare("INSERT INTO tokens (user_id, token, expires_at) VALUES (?, ?, ?)");
        if ($stmt->execute([$userId, $token, $expires])) {
            return $token;
        }
        return null;
    }

    public function findByToken($token) {
        $query = "SELECT u.id, u.name, u.username FROM users u JOIN tokens t ON u.id = t.user_id WHERE t.token = ? AND t.expires_at > NOW()";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$token]);
        return $stmt->fetch();
    }

    public function deleteToken($token) {
        $stmt = $this->conn->prepare("DELETE FROM tokens WHERE token = ?");
        return $stmt->execute([$token]);
    }
}
