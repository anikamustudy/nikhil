<?php

namespace App\Http\Controllers\Api;

use App\Http\Resources\RoleResource;
use App\Models\Role;
use App\Http\Resources\RoleCollection;
use App\Http\Requests\StoreRoleRequest;
use App\Http\Requests\UpdateRoleRequest;

class RoleController extends ApiController
{
    public function index()
    {
        try {
            $roles = Role::where('slug', '!=', 'admin')->get();
            return $this->successResponse('Roles retrieved successfully', [
                'roles' => new RoleCollection($roles)
            ], 200);
        } catch (\Exception $e) {
            return $this->handleException($e);
        }
    }


    public function store(StoreRoleRequest $request)
    {
        try {

            $role = Role::create($request->validated());
            return $this->successResponse('Role created successfully', [
                'role' => new RoleResource($role)
            ], 201);
        } catch (\Exception $e) {
            return $this->handleException($e);
        }
    }

    public function update(UpdateRoleRequest $request, Role $role)
    {
        try {
            $role->update($request->validated());
            return $this->successResponse('Role updated successfully', [
                'role' => new RoleResource($role)
            ], 201);
        } catch (\Exception $e) {
            return $this->handleException($e);
        }
    }

    public function destroy(Role $role)
    {
        try {
            $role->delete();
            return $this->successResponse('Role deleted successfully', [], 201);
        } catch (\Exception $e) {
            return $this->handleException($e);
        }
    }


}
