<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use App\Models\Status;
use App\Models\Role;
use App\Models\BankType;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use App\Traits\HandlesApiActions;
use App\Traits\ModelFetcher;
use Illuminate\Support\Facades\Log;
use App\Services\NotificationService;
use App\Http\Requests\StoreJoinUsRequest;
use App\Http\Resources\MembershipRequestResource;
use App\Http\Resources\MembershipRequestCollection;

class MembershipRequestController extends ApiController
{
    use HandlesApiActions, ModelFetcher;

    protected $notificationService;

    public function __construct(NotificationService $notificationService)
    {
        $this->notificationService = $notificationService;
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
     *             @OA\Property(property="message", type="string", example="Membership requests retrieved successfully"),
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="members", type="array",
     *                     @OA\Items(
     *                         @OA\Property(property="id", type="integer", example=1),
     *                         @OA\Property(property="name", type="string", example="John Doe"),
     *                         @OA\Property(property="email", type="string", example="john@example.com"),
     *                         @OA\Property(property="role", type="object",
     *                             @OA\Property(property="id", type="integer", example=2),
     *                             @OA\Property(property="name", type="string", example="Member")
     *                         ),
     *                         @OA\Property(property="status", type="object",
     *                             @OA\Property(property="id", type="integer", example=1),
     *                             @OA\Property(property="name", type="string", example="Pending")
     *                         ),
     *                         @OA\Property(property="bank_type", type="object", nullable=true,
     *                             @OA\Property(property="id", type="integer", example=1),
     *                             @OA\Property(property="name", type="string", example="Savings")
     *                         )
     *                     )
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(response=401, description="Unauthenticated"),
     *     @OA\Response(response=403, description="Unauthorized (not admin)"),
     *     @OA\Response(response=500, description="Server error")
     * )
     */
    public function index(Request $request)
    {
        return $this->withExceptionHandling(function () use ($request) {
            $adminRole = $this->findModelBySlug(Role::class, 'admin', 'admin_role');
            $users = $this->fetchNonAdminMembers($adminRole->id);
            return $this->successResponse(
                'Membership requests retrieved successfully',
                ['members' => new MembershipRequestCollection($users)],
                200
            );
        });
    }

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
     *             @OA\Property(property="role", type="string", example="member"),
     *             @OA\Property(property="bank_type_id", type="integer", example=1, nullable=true),
     *             @OA\Property(property="message", type="string", example="I want to join", nullable=true)
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Membership request submitted",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Registration request submitted successfully. You will receive your password once approved.")
     *         )
     *     ),
     *     @OA\Response(response=422, description="Validation error"),
     *     @OA\Response(response=500, description="Server error")
     * )
     */
    public function store(StoreJoinUsRequest $request)
    {
        return $this->withExceptionHandling(function () use ($request) {
            $this->validateEmailAvailability($request->email);
            $role = $this->fetchRole($request->role);
            $bankType = $this->fetchBankTypeIfApplicable($request);
            $status = $this->fetchPendingStatus();
            $user = $this->createUser($request, $role, $bankType, $status);
            $this->sendRequestReceivedNotification($user, $request, $bankType);

            return $this->successResponse(
                'Registration request submitted successfully. You will receive your password once approved.',
                null,
                201
            );
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
     *             @OA\Property(property="status_id", type="integer", example=2),
     *             @OA\Property(property="message", type="string", example="Status updated to approved")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Status updated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="User status updated to Approved"),
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="member", type="object",
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="name", type="string", example="John Doe"),
     *                     @OA\Property(property="email", type="string", example="john@example.com"),
     *                     @OA\Property(property="status", type="object",
     *                         @OA\Property(property="id", type="integer", example=2),
     *                         @OA\Property(property="name", type="string", example="Approved")
     *                     )
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(response=401, description="Unauthenticated"),
     *     @OA\Response(response=403, description="Unauthorized (not admin)"),
     *     @OA\Response(response=404, description="User or status not found"),
     *     @OA\Response(response=422, description="Validation error"),
     *     @OA\Response(response=500, description="Server error")
     * )
     */
    public function updateStatus(Request $request, $userId)
    {
        return $this->withExceptionHandling(function () use ($request, $userId) {
            $this->validateStatusUpdateRequest($request);
            $user = $this->fetchUser($userId);
            $newStatus = $this->fetchStatus($request->status_id);

            if ($this->isStatusUnchanged($user, $newStatus)) {
                return $this->successResponse('No status change detected.', [], 200);
            }
            $this->updateUserStatus($user, $newStatus);
            return $this->successResponse(
                "User status updated to {$newStatus->name}.",
                ['member' => new MembershipRequestResource($user)],
                200
            );
        });
    }

    private function fetchNonAdminMembers($adminRoleId)
    {
        return User::where('role_id', '!=', $adminRoleId)
            ->with(['role', 'status', 'bankType'])
            ->get();
    }

    private function validateEmailAvailability($email)
    {
        if (User::where('email', $email)->exists()) {
            throw new \Exception('Email already registered. Please contact support.', 422);
        }
    }

    private function fetchRole($roleSlug)
    {
        $role = Role::where('slug', $roleSlug)->first();
        if (!$role) {
            throw new \Exception('Please select appropriate role.', 404);
        }
        return $role;
    }

    private function fetchBankTypeIfApplicable(Request $request)
    {
        if ($request->role !== 'bank' || !$request->input('bank_type_id')) {
            return null;
        }

        $bankType = BankType::where('id', $request->bank_type_id)->first();
        if (!$bankType) {
            throw new \Exception('Selected bank type does not exist.', 404);
        }
        return $bankType;
    }

    private function fetchPendingStatus()
    {
        $status = Status::where('slug', 'pending')->first();
        if (!$status) {
            throw new \Exception('Pending status not found.', 500);
        }
        return $status;
    }

    private function createUser(Request $request, Role $role, ?BankType $bankType, Status $status)
    {
        $userData = [
            'email' => $request->email,
            'name' => $request->name,
            'role_id' => $role->id,
            'status_id' => $status->id,
            'bank_type_id' => $bankType ? $bankType->id : null,
            'message' => $request->message,
            'password' => null,
            'created_by' => null,
            'updated_by' => null,
        ];

        $user = User::create($userData);
        return $user;
    }

    private function sendRequestReceivedNotification(User $user, Request $request, ?BankType $bankType)
    {
        $submittedData = $request->only(['email', 'name', 'role', 'bank_type_id', 'message']);
        if ($bankType) {
            $submittedData['bank_type_name'] = $bankType->name;
        }
        $submittedData['tempPassword'] = Str::random(12);
        $user->password = Hash::make($submittedData['tempPassword']);
        $user->save();
        $this->notificationService->sendRequestReceivedNotification($user, $submittedData);
    }

    private function validateStatusUpdateRequest(Request $request)
    {
        $request->validate([
            'status_id' => 'required|exists:statuses,id',
            'message' => 'required|string|max:1000',
        ]);
    }

    private function fetchUser($userId)
    {
        $user = User::find($userId);
        if (!$user) {
            throw new \Exception('User not found.', 404);
        }
        return $user;
    }

    private function fetchStatus($statusId)
    {
        $status = Status::find($statusId);
        if (!$status) {
            throw new \Exception('Selected status not found.', 404);
        }
        return $status;
    }

    private function isStatusUnchanged(User $user, Status $newStatus)
    {
        return $user->status_id === $newStatus->id;
    }

    private function updateUserStatus(User $user, Status $newStatus)
    {
        $user->status_id = $newStatus->id;
        $user->updated_by = auth()->user()->id;

        $tempPassword = null;
        if ($newStatus->slug === 'approved') {
            $tempPassword = Str::random(12);
            $hashedPassword = Hash::make($tempPassword);
            $user->password = $hashedPassword;
            $user->password_reset_token = Str::random(60);
            $user->password_reset_token_expires_at = now()->addHours(32);
            $user->password_updated = false;
            $user->save();
        } else {
            $user->save();
        }
        Log::info('User status updated', ['user_id' => $user->id, 'email' => $user->email, 'status' => $newStatus->slug]);
        $this->sendStatusNotification($user, $newStatus, $tempPassword);
    }

    private function sendStatusNotification(User $user, Status $newStatus, ?string $tempPassword = null)
    {
        Log::info('Sending status notification', [
            'user_id' => $user->id,
            'email' => $user->email,
            'status' => $newStatus->slug,
        ]);

        if ($newStatus->slug === 'approved') {
            $this->notificationService->sendApprovalNotification($user, $tempPassword);
        } else {
            $this->notificationService->sendStatusUpdate($user, $newStatus, auth()->user()->id);
        }
    }
}