<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Requests\LoginRequest;
use Illuminate\Support\Facades\Log;
use App\Http\Resources\UserResource;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Services\NotificationService;
use App\Http\Controllers\Api\ApiController;
use Illuminate\Support\Facades\RateLimiter;

class AuthController extends ApiController
{
    protected $notificationService;

    public function __construct(NotificationService $notificationService)
    {
        $this->notificationService = $notificationService;
    }

    public function login(LoginRequest $request)
    {
        try {
            $credentials = $request->only('email', 'password');
            if (Auth::attempt($credentials)) {
                $user = Auth::user();

                Log::info('Trying login', [
                    'User' => [
                        $user->status->slug,
                        $user->password_updated,
                        $user->role->slug
                    ]
                ]);

                if (!$user->status || $user->status->slug !== 'approved') {
                    Auth::logout();
                    return $this->errorResponse('Account not approved', 403);
                }
                if (!$user->password_updated || $user->password === null) {
                    Auth::logout();
                    return $this->errorResponse('Password must be updated before login', 403);
                }
                $token = $user->createToken($request->email)->plainTextToken;
                $user->load(['status', 'role', 'bankType']);
                return $this->successResponse(
                    'Login successful',
                    ['token' => $token, 'user' => new UserResource($user)]
                );
            }
            return $this->errorResponse('Invalid credentials', 401);
        } catch (\Exception $e) {
            return $this->handleException($e);
        }
    }


    public function getCurrentUser(Request $request)
    {
        try {
            $user = $request->user();
            if (!$user) {
                return $this->errorResponse('Unauthenticated', 401);
            }
            $user->load(['role', 'status', 'bankType']);
            return $this->successResponse('User fetched successfully', [
                'user' => new UserResource($user)
            ], 200);
        } catch (\Exception $e) {
            return $this->handleException($e);
        }
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        return $this->successResponse('Logged out successfully');
    }

    public function resetPassword(Request $request)
    {
        $key = 'reset-password:' . $request->ip();
        if (RateLimiter::tooManyAttempts($key, 5)) {
            return $this->errorResponse('Too many attempts. Please try again later.', 429);
        }
        try {
            $request->validate([
                'email' => 'required|email|exists:users,email',
                'temporary_password' => 'required|string',
                'token' => 'required|string',
                'new_password' => 'required|string|min:8|confirmed',
            ]);

            Log::info('Reset password attempt', [
                'email' => $request->email,
                'new_password' => $request->new_password,
                'temporary_password' => $request->temporary_password,
                'token' => substr($request->token, 0, 10) . '...',
            ]);


            $user = User::where('email', $request->email)
                ->where('password_reset_token', $request->token)
                ->where('password_reset_token_expires_at', '>', now())
                ->first();

            if (!$user) {
                Log::warning('Invalid reset attempt: user or token not found or expired', [
                    'email' => $request->email,
                    'token' => substr($request->token, 0, 10) . '...',
                ]);
                return $this->errorResponse('Invalid or expired reset request', 403);
            }

            if (!Hash::check($request->temporary_password, $user->password)) {
                Log::warning('Invalid temporary password', [
                    'user_id' => $user->id,
                    'email' => $user->email,
                    'provided' => $request->temporary_password,
                    'stored_hash' => substr($user->password, 0, 20) . '...', // Partial hash for debugging
                ]);
                // $this->notificationService->sendStatusUpdate($user, $user->status, auth()->user()->id);
                return $this->errorResponse('Invalid reset request', 403);
            }

            // Update password
            $user->password = Hash::make($request->new_password);
            $user->password_reset_token = null;
            $user->password_reset_token_expires_at = null;
            $user->password_updated = true;
            $user->save();

            Log::info('Password reset successful', [
                'user_id' => $user->id,
                'email' => $user->email,
            ]);
            RateLimiter::clear($key);
            $this->notificationService->sendPasswordResetSuccessNotification($user);
            return $this->successResponse('Password updated successfully');
        } catch (\Exception $e) {
            RateLimiter::hit($key, 60);
            Log::error('Password reset failed', [
                'email' => $request->email,
                'error' => $e->getMessage(),
            ]);
            return $this->handleException($e);
        }
    }


}