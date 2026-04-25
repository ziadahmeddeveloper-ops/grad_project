<?php
namespace Core;

class Router {
    private $routes = [];

    public function get($path, $action, $middleware = []) {
        $this->addRoute('GET', $path, $action, $middleware);
    }

    public function post($path, $action, $middleware = []) {
        $this->addRoute('POST', $path, $action, $middleware);
    }

    public function patch($path, $action, $middleware = []) {
        $this->addRoute('PATCH', $path, $action, $middleware);
    }

    public function delete($path, $action, $middleware = []) {
        $this->addRoute('DELETE', $path, $action, $middleware);
    }

    private function addRoute($method, $path, $action, $middleware) {
        $regex = preg_replace('/\{([a-zA-Z0-9_]+)\}/', '(?P<\1>[a-zA-Z0-9_-]+)', $path);
        $regex = '#^' . $regex . '$#';

        $this->routes[] = [
            'method' => $method,
            'path' => $path,
            'regex' => $regex,
            'action' => $action,
            'middleware' => $middleware
        ];
    }

    public function dispatch(Request $request) {
        $method = $request->getMethod();
        $uri = $request->getUri();

        foreach ($this->routes as $route) {
            if ($route['method'] === $method && preg_match($route['regex'], $uri, $matches)) {
                
                foreach ($route['middleware'] as $middleware) {
                    $middlewareObj = new $middleware();
                    if (method_exists($middlewareObj, 'handle')) {
                        $middlewareObj->handle($request);
                    }
                }

                $controllerName = $route['action'][0];
                $methodName = $route['action'][1];

                $controller = new $controllerName();
                
                $params = array_filter($matches, 'is_string', ARRAY_FILTER_USE_KEY);
                
                call_user_func_array([$controller, $methodName], array_merge([$request], array_values($params)));
                return;
            }
        }

        Response::error('Route not found', 404);
    }
}
