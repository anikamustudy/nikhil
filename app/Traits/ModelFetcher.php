<?php

namespace App\Traits;

use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Support\Facades\Log;

trait ModelFetcher
{
  protected function findModelBySlug(string $modelClass, string $slug, string $logLabel): mixed
  {
    $model = $modelClass::where('slug', $slug)->firstOrFail();
    Log::info("{$logLabel} Found:", ["{$logLabel}_id" => $model->id]);
    return $model;
  }

  protected function findModelById(string $modelClass, int $id, string $logLabel): mixed
  {
    $model = $modelClass::findOrFail($id);
    Log::info("{$logLabel} Found:", ["{$logLabel}_id" => $model->id]);
    return $model;
  }
}