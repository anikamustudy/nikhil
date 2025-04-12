<?php

namespace App\Http\Resources;

use App\Models\Role;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\ResourceCollection;

class RoleCollection extends ResourceCollection
{

    public function toArray(Request $request): array
    {
        return $this->collection->map(function ($role) {
            return new RoleResource($role);
        })->all();
    }
}
