<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Auth;

class StoreRoleRequest extends FormRequest
{
    public function authorize()
    {
        return true; 
    }

    public function rules()
    {
        return [
            'name' => 'required|string|unique:roles,name',
            'description' => 'required|string',
        ];
    }

    public function messages()
    {
        return [
            'name.required' => 'The name field is required.',
            'name.unique' => 'This role name is already taken.',
            'description.required' => 'The description field is required.',
        ];
    }
}
