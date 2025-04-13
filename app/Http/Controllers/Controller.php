<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;

/**
 * @OA\Info(
 *     title="Laravel API",
 *     version="1.0.0",
 *     description="API documentation for the Cloudways-hosted Laravel backend",
 *     @OA\Contact(
 *         email="support@yourdomain.com"
 *     )
 * )
 * @OA\SecurityScheme(
 *     type="http",
 *     securityScheme="sanctum",
 *     scheme="bearer",
 *     bearerFormat="Sanctum Token"
 * )
 */
class Controller extends BaseController
{
    use AuthorizesRequests, ValidatesRequests;
}