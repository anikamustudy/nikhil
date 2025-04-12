<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UpdateRoleRequest extends FormRequest
{

    public function authorize(): bool
    {
        return true;
    }

    public function rules()
    {

        $role = $this->route('roles');
        return [
            'name' => "required|string|unique:roles,name,{$role}",
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
