<?php
namespace Config;

use PDO;
use PDOException;

class Database {
    private static $conn = null;

    public static function getConnection() {
        if (self::$conn === null) {
            // Check for Railway MySQL variables, otherwise fallback to local XAMPP settings
            $host = getenv('MYSQLHOST') ?: (getenv('DB_HOST') ?: "localhost");
            $db_name = getenv('MYSQLDATABASE') ?: (getenv('DB_DATABASE') ?: "ai_cyber_defender");
            $username = getenv('MYSQLUSER') ?: (getenv('DB_USERNAME') ?: "root");
            // getenv() for password can return false if empty string, so we need strict checks
            $password = getenv('MYSQLPASSWORD') !== false ? getenv('MYSQLPASSWORD') : (getenv('DB_PASSWORD') !== false ? getenv('DB_PASSWORD') : "");
            $port = getenv('MYSQLPORT') ?: (getenv('DB_PORT') ?: "3306");

            try {
                $dsn = "mysql:host=" . $host . ";port=" . $port . ";dbname=" . $db_name;
                self::$conn = new PDO($dsn, $username, $password);
                self::$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                self::$conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            } catch(PDOException $exception) {
                http_response_code(500);
                echo json_encode(["error" => "Database connection error: " . $exception->getMessage()]);
                exit;
            }
        }
        return self::$conn;
    }
}
