<?php

namespace App\Services;

use App\Models\User;
use App\Models\Status;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use App\Mail\StatusUpdateNotification;
use App\Models\UserNotificationMessage;

class NotificationService
{
  private const FRONTEND_URL = 'APP_FRONTEND_URL';
  private $sentNotifications = [];

  public function sendRequestReceivedNotification(User $user, array $submittedData): void
  {
    $message = $this->buildRequestReceivedMessage($submittedData);
    $this->sendNotification($user, $user->status, $message, null, 'pending');
  }

  public function sendApprovalNotification(User $user, string $tempPassword): void
  {
    $resetUrl = $this->buildResetUrl($user);
    $message = $this->buildApprovalMessage($tempPassword, $resetUrl);
    Log::info('Preparing approval notification', [
      'user_id' => $user->id,
      'email' => $user->email,
    ]);
    $this->sendNotification($user, $user->status, $message, $resetUrl, 'approved');
  }

  public function sendPasswordResetSuccessNotification(User $user): void
  {
    $message = $this->buildPasswordResetSuccessMessage($user);
    $this->sendNotification($user, $user->status, $message, null, 'sent');
  }

  public function sendStatusUpdate(User $user, Status $status, ?int $updatedBy = null): void
  {
    $key = "{$user->id}-{$status->slug}-" . time();
    if (in_array($key, $this->sentNotifications)) {
      Log::warning('Duplicate notification attempt prevented', [
        'user_id' => $user->id,
        'status' => $status->slug,
        'key' => $key,
      ]);
      return;
    }

    Log::info('Preparing status update notification', [
      'user_id' => $user->id,
      'status' => $status->slug,
      'updatedBy' => $updatedBy,
    ]);

    switch ($status->slug) {
      case 'rejected':
        $this->sendRejectedNotification($user, $status, $updatedBy);
        break;
      case 'suspended':
        $this->sendSuspendedNotification($user, $status, $updatedBy);
        break;
      case 'pending':
      case 'approved':
        break;
      default:
        $this->sendGenericStatusUpdate($user, $status, $updatedBy);
        break;
    }

    $this->sentNotifications[] = $key;
  }

  private function sendRejectedNotification(User $user, Status $status, ?int $updatedBy): void
  {
    $message = $this->buildStatusUpdateMessage($user, $status, "Your registration request has been rejected.");
    $this->sendNotification($user, $status, $message, null, 'sent', $updatedBy);
  }

  private function sendSuspendedNotification(User $user, Status $status, ?int $updatedBy): void
  {
    $message = $this->buildStatusUpdateMessage($user, $status, "Your registration has been suspended.");
    $this->sendNotification($user, $status, $message, null, 'sent', $updatedBy);
  }

  private function sendGenericStatusUpdate(User $user, Status $status, ?int $updatedBy): void
  {
    $message = $this->buildStatusUpdateMessage($user, $status, "Your registration status has been updated to {$status->name}.");
    $this->sendNotification($user, $status, $message, null, 'sent', $updatedBy);
  }

  private function buildRequestReceivedMessage(array $submittedData): string
  {
    $details = [
      'Name' => $submittedData['name'] ?? 'N/A',
      'Email' => $submittedData['email'] ?? 'N/A',
      'Role' => ucfirst($submittedData['role']) ?? 'N/A',
    ];

    if (isset($submittedData['bank_type_name'])) {
      $details['Bank Type'] = $submittedData['bank_type_name'];
    }

    $details['Message'] = $submittedData['message'] ?? 'N/A';

    try {
      return json_encode([
        'title' => 'Membership Request Received',
        'intro' => 'Your membership request has been received. Here’s what we’ve recorded:',
        'details' => $details,
      ], JSON_THROW_ON_ERROR);
    } catch (\JsonException $e) {
      Log::error('Failed to encode JSON for request received', [
        'error' => $e->getMessage(),
      ]);
      return json_encode([
        'title' => 'Membership Request Received',
        'intro' => 'Your membership request has been received.',
        'details' => ['Error' => 'Unable to load details'],
      ]);
    }
  }

  private function buildApprovalMessage(string $tempPassword, string $resetUrl): string
  {
    return json_encode([
      'title' => 'Membership Request Approved',
      'intro' => 'Your membership request has been approved!',
      'tempPassword' => $tempPassword,
      'resetUrl' => htmlspecialchars($resetUrl),
    ], JSON_THROW_ON_ERROR);
  }

  private function buildPasswordResetSuccessMessage(User $user): string
  {
    $details = [
      'Name' => $user->name ?? 'N/A',
      'Email' => $user->email,
      'Updated On' => now()->format('Y-m-d H:i:s'),
    ];

    try {
      return json_encode([
        'title' => 'Password Reset Successful',
        'intro' => 'Your password has been successfully updated. You can now log in with your new password.',
        'details' => $details,
      ], JSON_THROW_ON_ERROR);
    } catch (\JsonException $e) {
      Log::error('Failed to encode JSON for password reset success', [
        'user_id' => $user->id,
        'error' => $e->getMessage(),
      ]);
      return json_encode([
        'title' => 'Password Reset Successful',
        'intro' => 'Your password has been successfully updated.',
        'details' => ['Error' => 'Unable to load details'],
      ]);
    }
  }

  private function buildStatusUpdateMessage(User $user, Status $status, string $statusMessage): string
  {
    $role = $user->role ? $user->role->name : 'N/A';
    $bankType = ($user->role && $user->role->slug === 'bank')
      ? ($user->bankType->name ?? 'N/A')
      : null;

    $details = [
      'Name' => $user->name ?? 'N/A',
      'Email' => $user->email ?? 'N/A',
      'Applied On' => $user->created_at ? $user->created_at->format('Y-m-d H:i:s') : 'N/A',
      'Current Status' => $status->name ?? 'N/A',
      'Role' => $role,
    ];

    if ($bankType) {
      $details['Bank Type'] = $bankType;
    }

    try {
      return json_encode([
        'title' => 'Membership Status Update',
        'intro' => $statusMessage,
        'details' => $details,
      ], JSON_THROW_ON_ERROR);
    } catch (\JsonException $e) {
      Log::error('Failed to encode JSON for status update', [
        'user_id' => $user->id,
        'error' => $e->getMessage(),
      ]);
      return json_encode([
        'title' => 'Membership Status Update',
        'intro' => $statusMessage,
        'details' => ['Error' => 'Unable to load details'],
      ]);
    }
  }

  private function buildResetUrl(User $user): string
  {
    $frontendUrl = env(self::FRONTEND_URL, 'http://localhost:5173');
    return "{$frontendUrl}/reset-password?email=" . urlencode($user->email) . "&token=" . $user->password_reset_token;
  }

  private function sendNotification(
    User $user,
    Status $status,
    string $message,
    ?string $resetUrl,
    string $initialDeliveryStatus,
    ?int $createdBy = null
  ): void {
    $notification = $this->createNotification($user, $status, $message, $initialDeliveryStatus, $createdBy);
    $emailSent = $this->sendEmail($user, $status, $message, $resetUrl, $notification);
    $this->updateNotificationStatus($notification, $emailSent);
    $this->handleEmailFailure($user, $status, $emailSent);
  }

  private function createNotification(
    User $user,
    Status $status,
    string $message,
    string $deliveryStatus,
    ?int $createdBy
  ): UserNotificationMessage {
    return UserNotificationMessage::create([
      'user_id' => $user->id,
      'status_id' => $status->id,
      'message' => $message,
      'delivery_status' => $deliveryStatus,
      'created_by' => $createdBy,
    ]);
  }

  private function sendEmail(
    User $user,
    Status $status,
    string $message,
    ?string $resetUrl,
    UserNotificationMessage $notification
  ): bool {
    try {
      Log::info('Attempting to send email', [
        'user_id' => $user->id,
        'email' => $user->email,
        'status' => $status->slug,
      ]);
      Mail::to($user->email)->send(
        new StatusUpdateNotification($user, $status, $message, $resetUrl)
      );
      Log::info('Email sent successfully', ['user_id' => $user->id, 'email' => $user->email]);
      return true;
    } catch (\Exception $e) {
      Log::error('Failed to send notification email', [
        'user_id' => $user->id,
        'email' => $user->email,
        'status' => $status->slug,
        'error' => $e->getMessage(),
        'trace' => $e->getTraceAsString(),
      ]);
      return false;
    }
  }

  private function updateNotificationStatus(UserNotificationMessage $notification, bool $emailSent): void
  {
    $notification->update([
      'delivery_status' => $emailSent ? 'sent' : 'failed',
      'sent_at' => $emailSent ? now() : null,
    ]);
  }

  private function handleEmailFailure(User $user, Status $status, bool $emailSent): void
  {
    if (!$emailSent) {
      Log::warning('Email delivery failed', [
        'user_id' => $user->id,
        'email' => $user->email,
        'status' => $status->slug,
      ]);
    }
  }
}