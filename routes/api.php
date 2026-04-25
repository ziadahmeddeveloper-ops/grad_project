<?php
use Core\Router;
use Core\AuthMiddleware;

$router = new Router();

// Auth Routes
$router->post('/api/auth/login', ['Controllers\AuthController', 'login']);
$router->post('/api/auth/register', ['Controllers\AuthController', 'register']);
$router->post('/api/auth/logout', ['Controllers\AuthController', 'logout'], [AuthMiddleware::class]);
$router->get('/api/auth/me', ['Controllers\AuthController', 'me'], [AuthMiddleware::class]);

// Attacks Module
$router->get('/api/attacks', ['Controllers\AttackController', 'index'], [AuthMiddleware::class]);
$router->get('/api/attacks/recent', ['Controllers\AttackController', 'recent'], [AuthMiddleware::class]);
$router->get('/api/attacks/{id}', ['Controllers\AttackController', 'show'], [AuthMiddleware::class]);
$router->patch('/api/attacks/{id}/status', ['Controllers\AttackController', 'updateStatus'], [AuthMiddleware::class]);
$router->delete('/api/attacks/{id}', ['Controllers\AttackController', 'destroy'], [AuthMiddleware::class]);

// Dashboard APIs
$router->get('/api/dashboard/stats', ['Controllers\DashboardController', 'stats'], [AuthMiddleware::class]);
$router->get('/api/dashboard/charts', ['Controllers\DashboardController', 'charts'], [AuthMiddleware::class]);

// Statistics Module
$router->get('/api/statistics', ['Controllers\StatisticsController', 'index'], [AuthMiddleware::class]);

// AI Integration
$router->post('/api/ai/analyze', ['Controllers\AiController', 'analyzeLog']); // Unprotected

// Reports
$router->get('/api/reports/{period}', ['Controllers\ReportController', 'generate'], [AuthMiddleware::class]);

return $router;
