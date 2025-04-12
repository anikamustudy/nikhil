<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\RoleController;
use App\Http\Controllers\Api\StatusController;
use App\Http\Controllers\Api\BankTypeController;
use App\Http\Controllers\Api\MembershipRequestController;

Route::post('/membership-request', [MembershipRequestController::class, 'store']);
Route::post('/login', [AuthController::class, 'login']);
Route::post('/reset-password', [AuthController::class, 'resetPassword']);
Route::get('/roles', [RoleController::class, 'index']);
Route::get('/bank-types', [BankTypeController::class, 'index']);

Route::middleware(['auth:sanctum'])->group(function () {
    Route::get('/current-user', [AuthController::class, 'getCurrentUser']);
    Route::post('/logout', [AuthController::class, 'logout']);

    Route::prefix('admin')
        ->middleware(['role:admin'])
        ->group(function () {

            Route::get('/bank-types', [BankTypeController::class, 'index']);
            Route::post('/bank-types', [BankTypeController::class, 'store']);
            Route::get('/bank-types/create', [BankTypeController::class, 'create']);
            Route::put('/bank-types/{bank_type}', [BankTypeController::class, 'update']);
            Route::delete('/bank-types/{bank_type}', [BankTypeController::class, 'destroy']);

            Route::get('/roles', [RoleController::class, 'index']);
            Route::post('/roles', [RoleController::class, 'store']);
            Route::get('/roles/create', [RoleController::class, 'create']);
            Route::put('/roles/{role}', [RoleController::class, 'update']);
            Route::delete('/roles/{role}', [RoleController::class, 'destroy']);

            Route::get('/status', [StatusController::class, 'index']);
            Route::post('/status', [StatusController::class, 'store']);
            Route::get('/status/create', [StatusController::class, 'create']);
            Route::put('/status/{status}', [StatusController::class, 'update']);
            Route::delete('/status/{status}', [StatusController::class, 'destroy']);

            Route::get('/membership-requests', [MembershipRequestController::class, 'index']);
            Route::put('/membership-request/{user}/status', [MembershipRequestController::class, 'updateStatus']);

        });
});
