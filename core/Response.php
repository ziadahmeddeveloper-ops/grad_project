<?php
namespace Core;

class Response {
    public static function success($data = null, $meta = null, $statusCode = 200) {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        
        $response = [];
        if ($data !== null) {
            $response['data'] = $data;
        }
        if ($meta !== null) {
            $response['meta'] = $meta;
        }
        
        echo json_encode($response);
        exit;
    }

    public static function error($message, $statusCode = 400) {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        echo json_encode([
            "error" => $message
        ]);
        exit;
    }
}
