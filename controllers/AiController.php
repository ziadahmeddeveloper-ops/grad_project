<?php
namespace Controllers;

use Core\Request;
use Core\Response;
use Models\Attack;

class AiController {
    private $attackModel;

    public function __construct() {
        $this->attackModel = new Attack();
    }

    public function analyzeLog(Request $request) {
        $data = $request->getBody();
        $inputText = $data['input_text'] ?? null;
        $logs = $data['logs'] ?? null;

        if (!$inputText && !$logs) {
            Response::error('Missing input_text or logs', 400);
        }

        $results = [];
        $hasLogsArray = is_array($logs) && count($logs) > 0;
        $itemsToProcess = $hasLogsArray ? $logs : [$inputText];

        foreach ($itemsToProcess as $logText) {
            if (!$logText) continue;

            $ch = curl_init('http://localhost:5000/api/predict');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['input_text' => $logText]));
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlError = curl_error($ch);
            curl_close($ch);

            if ($response === false) {
                Response::error('Failed to connect to the new AI system. cURL Error: ' . $curlError, 500);
            }

            $aiResult = json_decode($response, true);
            
            if (isset($aiResult['error'])) {
                 Response::error("AI System Error on log '$logText': " . $aiResult['error'], $httpCode >= 400 ? $httpCode : 400);
            }

            if ($httpCode !== 200) {
                 Response::error("Unexpected response from AI system. HTTP Code: $httpCode", 500);
            }

            $results[] = ['original_text' => $logText, 'ai_result' => $aiResult];
        }

        $responseData = [];

        foreach ($results as $item) {
            $result = $item['ai_result'];
            $originalText = $item['original_text'];
            $attackId = null;

            if (isset($result['prediction']) && $result['prediction'] === 'anomaly') {
                $explanation = '';
                if (!empty($result['recommended_actions'])) {
                    $actions = $result['recommended_actions'];
                    if (is_array($actions)) {
                        $flatActions = [];
                        array_walk_recursive($actions, function($a) use (&$flatActions) { 
                            $flatActions[] = $a; 
                        });
                        $explanation = implode(' ', $flatActions);
                    } else {
                        $explanation = $actions;
                    }
                }

                $attackId = $this->attackModel->create([
                    'source_type' => $result['source_type'] ?? null,
                    'attack_type' => $result['attack_type'] ?? 'unknown',
                    'attack_name' => $result['attack_name'] ?? 'unknown',
                    'threat_score' => $result['threat_score'] ?? 0,
                    'threat_level' => $result['threat_level'] ?? 'low',
                    'source_ip' => $result['source_ip'] ?? null,
                    'username' => $result['username'] ?? null,
                    'event_time' => $result['event_time'] ?? date('Y-m-d H:i:s'),
                    'recommended_actions' => $explanation,
                    'raw_context' => isset($result['raw_context']) ? json_encode($result['raw_context']) : null
                ]);

                if ($attackId) {
                    $this->attackModel->addLog($attackId, $originalText);
                    $this->attackModel->addTimeline($attackId, date('Y-m-d H:i:s'), 'Attack detected by AI analysis');
                }
            }
            $result['attack_id'] = $attackId;
            $responseData[] = $result;
        }

        if (!$hasLogsArray) {
            $responseData = $responseData[0] ?? null;
        }

        Response::success($responseData, ['message' => 'Analysis complete'], 200);
    }
}
