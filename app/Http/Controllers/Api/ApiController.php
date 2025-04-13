<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;

class ApiController extends Controller
{
    protected function successResponse($message, $data = null, $status = 200)
    {
        $response = ['message' => $message];
        if ($data) {
            $response['data'] = $data;
        }
        return response()->json($response, $status);
    }

    protected function handleException(\Exception $e)
    {
        return response()->json([
            'error' => $e->getMessage(),
        ], $e->getCode() ?: 500);
    }
}