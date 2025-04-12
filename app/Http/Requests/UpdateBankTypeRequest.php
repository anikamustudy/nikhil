<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Log;

class UpdateBankTypeRequest extends FormRequest
{
    public function authorize()
    {
        return true;
    }

    public function rules()
    {
        // Use the resolved BankType model instance
        $bankType = $this->route('bank_type');
        $bankTypeId = $bankType instanceof \App\Models\BankType ? $bankType->id : null;
        \Log::info("BankType ID for validation: " . ($bankTypeId ?? 'null')); // Debug log
        return [
            'name' => "required|string|unique:bank_types,name,{$bankTypeId}",
            'description' => 'nullable|string',
            'status' => 'required|boolean',
        ];
    }

    public function messages()
    {
        return [
            'name.required' => 'The name field is required.',
            'name.unique' => 'This name is already taken.',
            'status.required' => 'The status field is required.',
            'status.boolean' => 'The status must be true or false.',
        ];
    }
}

