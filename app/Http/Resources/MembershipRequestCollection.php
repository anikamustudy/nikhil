<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\ResourceCollection;

class MembershipRequestCollection extends ResourceCollection
{

    public function toArray(Request $request): array
    {
        return $this->collection->map(function ($member) {
            return new MembershipRequestResource($member);
        })->all();
    }
}
