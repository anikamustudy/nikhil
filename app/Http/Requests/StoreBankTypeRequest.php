<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;


class StoreBankTypeRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'name' => 'required|string|max:255|unique:bank_types,name',
            'description' => 'nullable|string',
            'status' => 'boolean',
        ];
    }
}