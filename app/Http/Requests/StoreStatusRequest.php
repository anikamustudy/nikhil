<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreStatusRequest extends FormRequest
{
    public function authorize()
    {
        return true;
    }

    public function rules()
    {
        return [
            'name' => 'required|string|unique:statuses,name',
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
