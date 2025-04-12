<?php
namespace App\Traits;

use Illuminate\Http\JsonResponse;
use Exception;

trait HandlesApiActions
{
  protected function withExceptionHandling(callable $action): JsonResponse
  {
    try {
      return $action();
    } catch (Exception $e) {
      return $this->handleException($e);
    }
  }
}