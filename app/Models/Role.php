<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class Role extends Model
{
    protected $fillable = [
        'name',
        'slug',
        'description',
        'created_by',
        'updated_by'
    ];

    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            $model->slug = Str::slug($model->name);
            $model->created_by = auth()->id() ?? null;
            $model->updated_by = auth()->id() ?? null;
        });

        static::updating(function ($model) {
            $model->slug = Str::slug($model->name);
            $model->updated_by = auth()->id() ?? null;
        });
    }

    public function users()
    {
        return $this->hasMany(User::class, 'role_id');
    }

    public function creator()
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    public function updater()
    {
        return $this->belongsTo(User::class, 'updated_by');
    }
}
