<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateStatusRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules()
    {

        $statusId = $this->route('status');
        \Log::info("Status ID for validation: " . ($statusId ?? 'null'));
        return [
            'name' => [
                'required',
                'string',
                Rule::unique('statuses', 'name')->ignore($statusId),
            ],
            'description' => 'nullable|string',
        ];
    }

    public function messages()
    {
        return [
            'name.required' => 'The name field is required.',
            'name.unique' => 'This name is already taken.',
        ];
    }
}
