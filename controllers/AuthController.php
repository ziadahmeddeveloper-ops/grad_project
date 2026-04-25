<?php
namespace Controllers;

use Core\Request;
use Core\Response;
use Models\User;

class AuthController {
    private $userModel;

    public function __construct() {
        $this->userModel = new User();
    }

    public function login(Request $request) {
        $username = $request->getBodyParam('username');
        $password = $request->getBodyParam('password');

        if (!$username || !$password) {
            Response::error('Username and password required');
        }

        $user = $this->userModel->findByUsername($username);

        if (!$user || !password_verify($password, $user['password'])) {
            Response::error('Invalid credentials', 401);
        }

        $token = $this->userModel->createToken($user['id']);

        Response::success([
            'token' => $token,
            'user' => [
                'id' => $user['id'],
                'name' => $user['name'],
                'username' => $user['username']
            ]
        ], ['message' => 'Login successful']);
    }

    public function register(Request $request) {
        $name = $request->getBodyParam('name');
        $username = $request->getBodyParam('username');
        $password = $request->getBodyParam('password');

        if (!$name || !$username || !$password) {
            Response::error('All fields are required');
        }

        $existingUser = $this->userModel->findByUsername($username);
        if ($existingUser) {
            Response::error('Username already taken');
        }

        if ($this->userModel->create($name, $username, $password)) {
            Response::success(null, ['message' => 'Registration successful'], 201);
        } else {
            Response::error('Failed to create user', 500);
        }
    }

    public function logout(Request $request) {
        $authHeader = $request->getHeader('Authorization');
        if ($authHeader && preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            $token = $matches[1];
            $this->userModel->deleteToken($token);
        }
        
        Response::success(null, ['message' => 'Logged out successfully']);
    }

    public function me(Request $request) {
        Response::success([
            'user' => [
                'id' => $request->user['id'],
                'name' => $request->user['name'],
                'username' => $request->user['username']
            ]
        ]);
    }
}
