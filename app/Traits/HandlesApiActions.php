<?php

namespace App\Http\Controllers\Api;

use App\Traits\HandlesApiActions;
use Illuminate\Http\Request;

class MembershipRequestController extends ApiController
{
    use HandlesApiActions; // ModelFetcher excluded until verified

    protected $notificationService;

    /**
     * @OA\Post(
     *     path="/membership-request",
     *     summary="Submit a membership request",
     *     tags={"Membership Requests"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="name", type="string", example="John Doe"),
     *             @OA\Property(property="email", type="string", example="john@example.com"),
     *             @OA\Property(property="phone", type="string", example="+1234567890"),
     *             @OA\Property(property="message", type="string", example="I want to join")
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Membership request submitted",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Request submitted successfully"),
     *             @OA\Property(property="request", type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="John Doe")
     *             )
     *         )
     *     ),
     *     @OA\Response(response=422, description="Validation error")
     * )
     */
    public function store(Request $request)
    {
        return $this->withExceptionHandling(function () use ($request) {
            $validated = $request->validate([
                'name' => 'required|string|max:255',
                'email' => 'required|email|max:255',
                'phone' => 'nullable|string|max:20',
                'message' => 'nullable|string',
            ]);

            // Replace with your actual logic (e.g., save to database)
            $requestData = array_merge($validated, ['id' => 1]); // Mock ID for example
            return response()->json([
                'message' => 'Request submitted successfully',
                'request' => $requestData,
            ], 201);
        });
    }

    /**
     * @OA\Get(
     *     path="/admin/membership-requests",
     *     summary="List all membership requests (Admin)",
     *     tags={"Membership Requests"},
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="List of membership requests",
     *         @OA\JsonContent(
     *             type="array",
     *             @OA\Items(
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="John Doe"),
     *                 @OA\Property(property="email", type="string", example="john@example.com"),
     *                 @OA\Property(property="status", type="string", example="pending")
     *             )
     *         )
     *     ),
     *     @OA\Response(response=401, description="Unauthenticated"),
     *     @OA\Response(response=403, description="Unauthorized (not admin)")
     * )
     */
    public function index()
    {
        return $this->withExceptionHandling(function () {
            // Replace with your actual logic (e.g., fetch from database)
            $requests = [
                ['id' => 1, 'name' => 'John Doe', 'email' => 'john@example.com', 'status' => 'pending'],
            ];
            return response()->json($requests);
        });
    }

    /**
     * @OA\Put(
     *     path="/admin/membership-request/{user}/status",
     *     summary="Update membership request status (Admin)",
     *     tags={"Membership Requests"},
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="user",
     *         in="path",
     *         required=true,
     *         description="User ID",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="approved", enum={"pending", "approved", "rejected"})
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Status updated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Status updated to approved"),
     *             @OA\Property(property="request", type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="status", type="string", example="approved")
     *             )
     *         )
     *     ),
     *     @OA\Response(response=401, description="Unauthenticated"),
     *     @OA\Response(response=403, description="Unauthorized (not admin)"),
     *     @OA\Response(response=404, description="Request not found")
     * )
     */
    public function updateStatus(Request $request, $user)
    {
        return $this->withExceptionHandling(function () use ($request, $user) {
            $validated = $request->validate([
                'status' => 'required|string|in:pending,approved,rejected',
            ]);

            // Replace with your actual logic (e.g., update database)
            return response()->json([
                'message' => "Status updated to {$validated['status']}",
                'request' => ['id' => $user, 'status' => $validated['status']],
            ]);
        });
    }
}