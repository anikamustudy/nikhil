<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class BankType extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'slug',
        'status',
        'description',
        'created_by',
        'updated_by'
    ];

    protected $attributes = [
        'status' => true,
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

    public function creator()
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    public function updater()
    {
        return $this->belongsTo(User::class, 'updated_by');
    }
}
