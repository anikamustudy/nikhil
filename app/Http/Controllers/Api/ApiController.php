<?php

namespace App\Http\Controllers\Api;

use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;
use Illuminate\Validation\ValidationException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
class ApiController extends Controller
{
    protected function successResponse(string $message = 'Success', $data = [], int $code = 200)
    {
        if ($data instanceof ResourceCollection) {
            $data = $data->toArray(request());
        } elseif (!is_array($data)) {
            $data = [$data];
        }

        return response()->json([
            'status' => 'success',
            'message' => $message,
            'data' => $data
        ], $code);
    }

    protected function errorResponse(string $message = 'Error', int $code = 400, ?array $errors = null)
    {
        return response()->json([
            'status' => 'error',
            'message' => $message,
            'errors' => $errors,
            'data' => null,
        ], $code);
    }

    protected function handleException(Exception $exception): JsonResponse
    {
        if ($exception instanceof ValidationException) {
            return $this->errorResponse(
                'Validation failed',
                422,
                $exception->errors()
            );
        }
        if ($exception instanceof \Illuminate\Auth\AuthenticationException) {
            return $this->errorResponse('Invalid credentials', 401);
        }

        if ($exception instanceof ModelNotFoundException) {
            return $this->errorResponse('Resource not found', 404);
        }

        // Log the exception for debugging
        Log::error('Unhandled exception: ' . $exception->getMessage(), [
            'exception' => $exception,
        ]);
        Log::error('Where have i failed: ' . $exception->getMessage(), [
            'trace' => $exception->getTraceAsString(),
        ]);

        return $this->errorResponse('An unexpected error occurred', 500);
    }
}
