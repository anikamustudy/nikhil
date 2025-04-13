<?php

namespace App\Traits;

trait ModelFetcher
{
    protected function findModelBySlug($model, $slug, $type)
    {
        $instance = $model::where('slug', $slug)->first();
        if (!$instance) {
            throw new \Exception("{$type} not found.", 404);
        }
        return $instance;
    }
}