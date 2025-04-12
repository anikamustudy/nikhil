<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class UserNotificationMessage extends Model
{
    protected $fillable = [
        'user_id',
        'status_id',
        'message',
        'delivery_status',
        'sent_at',
        'created_by',
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public function status()
    {
        return $this->belongsTo(Status::class);
    }

    public function creator()
    {
        return $this->belongsTo(User::class, 'created_by');
    }
}
