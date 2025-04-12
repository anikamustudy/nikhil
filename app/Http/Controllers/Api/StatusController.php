<?php

namespace App\Http\Controllers\Api;

use App\Models\Status;
use App\Http\Resources\StatusResource;
use App\Http\Requests\StoreStatusRequest;
use App\Http\Requests\UpdateStatusRequest;

class StatusController extends ApiController
{
    public function index()
    {
        try {
            $statuses = Status::all();
            return $this->successResponse('Status retrieved successfully', [
                'statuses' => StatusResource::collection($statuses)
            ], 200);
        } catch (\Exception $e) {
            return $this->handleException($e);
        }
    }


    public function store(StoreStatusRequest $request)
    {
        try {
            $status = Status::create($request->validated());
            return $this->successResponse('Status created successfully', [
                'status' => new StatusResource($status)
            ], 200);
        } catch (\Exception $e) {
            return $this->handleException($e);
        }
    }

    public function update(UpdateStatusRequest $request, Status $status)
    {
        try {
            $status->update($request->validated());
            return $this->successResponse('Status updated successfully', [
                'status' => new StatusResource($status),
            ], 201);
        } catch (\Exception $e) {
            return $this->handleException($e);
        }
    }

    public function destroy(Status $status)
    {
        try {
            $status->delete();
            return $this->successResponse('Status deleted successfully', [], 201);
        } catch (\Exception $e) {
            return $this->handleException($e);
        }
    }

}
