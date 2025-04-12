<?php

namespace App\Http\Resources;

use Illuminate\Http\Resources\Json\JsonResource;

class UserResource extends JsonResource
{
    public function toArray($request)
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'slug' => $this->slug,
            'email' => $this->email,
            'message' => $this->message,
            'role' => $this->when($this->role, fn() => [
                'id' => $this->role->id,
                'name' => $this->role->name,
                'slug' => $this->role->slug,
                'description' => $this->role->description,
                'created_by' => $this->role->creator ? $this->role->creator->name : null,
                'updated_by' => $this->role->updater ? $this->role->updater->name : null,
                'created_at' => $this->role->created_at ? $this->role->created_at->toDayDateTimeString() : null,
                'updated_at' => $this->role->updated_at ? $this->role->updated_at->toDayDateTimeString() : null,
            ]),
            'status' => $this->when($this->status, fn() => [
                'id' => $this->status->id,
                'name' => $this->status->name,
                'slug' => $this->status->slug,
                'description' => $this->status->description,
                'created_by' => $this->status->creator ? $this->status->creator->name : null,
                'updated_by' => $this->status->updater ? $this->status->updater->name : null,
                'created_at' => $this->status->created_at ? $this->status->created_at->toDayDateTimeString() : null,
                'updated_at' => $this->status->updated_at ? $this->status->updated_at->toDayDateTimeString() : null,
            ]),
            'bankType' => $this->when($this->bankType, fn() => [
                'id' => $this->bankType->id,
                'name' => $this->bankType->name,
                'slug' => $this->bankType->slug,
                'description' => $this->bankType->description,
                'created_by' => $this->bankType->creator ? $this->bankType->creator->name : null,
                'updated_by' => $this->bankType->updater ? $this->bankType->updater->name : null,
                'created_at' => $this->bankType->created_at ? $this->bankType->created_at->toDayDateTimeString() : null,
                'updated_at' => $this->bankType->updated_at ? $this->bankType->updated_at->toDayDateTimeString() : null,
            ]),
            'password_updated' => $this->password_updated,
            'created_by' => $this->role->creator ? $this->role->creator->name : null,
            'updated_by' => $this->role->updater ? $this->role->updater->name : null,
            'created_at' => $this->role->created_at ? $this->role->created_at->toDayDateTimeString() : null,
            'updated_at' => $this->role->updated_at ? $this->role->updated_at->toDayDateTimeString() : null,
        ];
    }
}