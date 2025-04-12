<?php

namespace App\Http\Controllers\Api;

use App\Http\Resources\BankTypeCollection;
use App\Models\BankType;
use App\Http\Resources\BankTypeResource;
use App\Http\Requests\StoreBankTypeRequest;
use App\Http\Requests\UpdateBankTypeRequest;

class BankTypeController extends ApiController
{
    public function index()
    {
        try {
            $bankTypes = BankType::all();
            return $this->successResponse('Bank Type retrieved successfully', [
                'bankTypes' => new BankTypeCollection($bankTypes)
            ], 200);
        } catch (\Exception $e) {
            return $this->handleException($e);
        }

    }

    public function store(StoreBankTypeRequest $request)
    {
        try {
            $bankType = BankType::create($request->validated());
            return $this->successResponse('Bank Type created successfully', [
                'bankType' => new BankTypeResource($bankType)
            ], 201);
        } catch (\Exception $e) {
            return $this->handleException($e);
        }
    }

    public function update(UpdateBankTypeRequest $request, BankType $bankType)
    {
        try {
            $bankType->update($request->validated());
            return $this->successResponse('Bank Type updated successfully', [
                'bankType' => new BankTypeResource($bankType)
            ], 200);

        } catch (\Exception $e) {
            return $this->handleException($e);
        }
    }

    public function destroy(BankType $bankType)
    {
        try {
            $bankType->delete();
            return $this->successResponse('Bank Type deleted successfully', [], 200);
        } catch (\Exception $e) {
            return $this->handleException($e);
        }
    }
}
