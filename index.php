<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

spl_autoload_register(function ($class) {
    $file = __DIR__ . DIRECTORY_SEPARATOR . str_replace('\\', DIRECTORY_SEPARATOR, $class) . '.php';
    $parts = explode(DIRECTORY_SEPARATOR, $file);
    if (count($parts) >= 2) {
        $parts[count($parts)-2] = strtolower($parts[count($parts)-2]);
    }
    $file = implode(DIRECTORY_SEPARATOR, $parts);
    
    if (file_exists($file)) {
        require $file;
    }
});

use Core\Request;
use Core\Response;

// Handle CORS
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PATCH, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit;
}

try {
    $request = new Request();
    $router = require __DIR__ . '/routes/api.php';
    $router->dispatch($request);
} catch (Exception $e) {
    Response::error("Internal Server Error: " . $e->getMessage(), 500);
}
