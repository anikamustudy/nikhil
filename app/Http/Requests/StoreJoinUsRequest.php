<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreJoinUsRequest extends FormRequest
{

    public function authorize(): bool
    {
        return true;
    }


    public function rules(): array
    {
        return [
            'email' => 'required|email|unique:users,email',
            'name' => 'required|string|max:255',
            'role' => 'required|string|exists:roles,slug',
            'bank_type_id' => 'nullable|integer|exists:bank_types,id|required_if:role,bank',
            'message' => 'required|string|max:1000',
        ];
    }

    public function messages(): array
    {
        return [
            'email.required' => 'Email is required.',
            'email.email' => 'Email must be a valid email address.',
            'email.unique' => 'This email is already registered.',
            'name.required' => 'Organization name is required.',
            // 'password.required' => 'Password is required.',
            // 'password.min' => 'Password must be at least 8 characters.',
            'role.required' => 'Role is required.',
            'role.exists' => 'The selected role is invalid.',
            'bank_type_id.exists' => 'The selected bank type is invalid.',
            'message.required' => 'Reason for joining is required.',
            'message.max' => 'Reason for joining must not exceed 1000 characters.',
        ];
    }

    protected function prepareForValidation()
    {
        $this->merge([
            'message' => $this->input('message', ''),
        ]);
    }
}
