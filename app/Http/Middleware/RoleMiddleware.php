<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;

class RoleMiddleware
{
    public function handle(Request $request, Closure $next, $role)
    {
        if (!Auth::check()) {
            Log::info(
                "RoleMiddleware: Unauthenticated",
                ['user' => Auth::user(), 'token' => $request->bearerToken()]
            );
            return response()->json([
                'message' => 'Unauthenticated'
            ], 401);
        }

        $user = Auth::user();
        Log::info("RoleMiddleware: Checking role", [
            'user_id' => $user->id,
            'role_id' => $user->role_id,
            'role_slug' => $user->role ? $user->role->slug : 'null',
            'expected_role' => $role,
        ]);
        if ($user->role->slug !== $role) {
            return response()->json([
                'message' => 'Forbidden: Insufficient role permissions'
            ], 403);
        }

        return $next($request);
    }
}
