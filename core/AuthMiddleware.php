<?php
namespace Core;

use Models\User;

class AuthMiddleware {
    public function handle(Request $request) {
        $authHeader = $request->getHeader('Authorization');
        if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            Response::error('Unauthorized', 401);
        }

        $token = $matches[1];
        
        $userModel = new User();
        $user = $userModel->findByToken($token);

        if (!$user) {
            Response::error('Invalid or expired token', 401);
        }

        $request->user = $user;
    }
}
