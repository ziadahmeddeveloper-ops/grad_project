<?php
namespace Controllers;

use Core\Request;
use Core\Response;
use Models\Attack;

class AttackController {
    private $attackModel;

    public function __construct() {
        $this->attackModel = new Attack();
    }

    public function index(Request $request) {
        $page = (int) $request->getParam('page', 1);
        $limit = (int) $request->getParam('limit', 10);
        
        $filters = [
            'severity' => $request->getParam('severity'),
            'type' => $request->getParam('type'),
            'status' => $request->getParam('status'),
            'ip' => $request->getParam('ip')
        ];

        $result = $this->attackModel->getAll($page, $limit, $filters);

        Response::success($result['data'], [
            'pagination' => [
                'total' => $result['total'],
                'page' => $result['page'],
                'limit' => $result['limit'],
                'total_pages' => $result['total_pages']
            ]
        ]);
    }

    public function show(Request $request, $id) {
        $attack = $this->attackModel->getById($id);
        if (!$attack) {
            Response::error('Attack not found', 404);
        }
        Response::success($attack);
    }

    public function updateStatus(Request $request, $id) {
        $status = $request->getBodyParam('status');
        if (!$status) {
            Response::error('Status required');
        }

        if ($this->attackModel->updateStatus($id, $status)) {
            Response::success(null, ['message' => 'Status updated']);
        } else {
            Response::error('Failed to update status', 500);
        }
    }

    public function destroy(Request $request, $id) {
        if ($this->attackModel->delete($id)) {
            Response::success(null, ['message' => 'Attack deleted']);
        } else {
            Response::error('Failed to delete attack', 500);
        }
    }

    public function recent(Request $request) {
        $limit = (int) $request->getParam('limit', 10);
        $attacks = $this->attackModel->getRecent($limit);
        Response::success($attacks);
    }
}
