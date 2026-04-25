<?php
namespace Core;

class Request {
    private $method;
    private $uri;
    private $params;
    private $body;
    private $headers;
    public $user = null;

    public function __construct() {
        $this->method = $_SERVER['REQUEST_METHOD'];
        $this->uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        
        // Remove base directory if app is running in a subfolder (like /grad_project)
        $baseDir = dirname($_SERVER['SCRIPT_NAME']);
        if ($baseDir !== '/' && strpos($this->uri, $baseDir) === 0) {
            $this->uri = substr($this->uri, strlen($baseDir));
        }
        
        // Ensure starting with /
        if (empty($this->uri) || $this->uri[0] !== '/') {
            $this->uri = '/' . ltrim($this->uri, '/');
        }
        
        $this->params = $_GET;
        $this->body = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        
        // Some servers don't have getallheaders
        if (function_exists('getallheaders')) {
            $this->headers = getallheaders();
        } else {
            $this->headers = [];
            foreach ($_SERVER as $name => $value) {
                if (substr($name, 0, 5) == 'HTTP_') {
                    $this->headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
                }
            }
        }
    }

    public function getMethod() {
        return $this->method;
    }

    public function getUri() {
        return $this->uri;
    }

    public function getParam($key, $default = null) {
        return isset($this->params[$key]) ? $this->params[$key] : $default;
    }

    public function getBodyParam($key, $default = null) {
        return isset($this->body[$key]) ? $this->body[$key] : $default;
    }

    public function getBody() {
        return $this->body;
    }

    public function getHeader($key) {
        $key = strtolower($key);
        foreach ($this->headers as $k => $v) {
            if (strtolower($k) === $key) return $v;
        }
        return null;
    }
}
