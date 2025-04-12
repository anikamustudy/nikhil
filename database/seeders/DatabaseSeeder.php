<?php

namespace Database\Seeders;

use App\Models\BankType;
use App\Models\Role;
use App\Models\User;
use App\Models\Status;
// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        Status::create(['name' => 'Pending', 'slug' => 'pending', 'description' => 'Awaiting approval', 'created_by' => 1]);
        Status::create(['name' => 'Approved', 'slug' => 'approved', 'description' => 'Approved user', 'created_by' => 1]);
        Status::create(['name' => 'Rejected', 'slug' => 'rejected', 'description' => 'Rejected user', 'created_by' => 1]);
        Status::create(['name' => 'Suspended', 'slug' => 'suspended', 'description' => 'Suspended user', 'created_by' => 1]);

        // Seed roles
        Role::create(['name' => 'Admin', 'slug' => 'admin', 'description' => 'Administrator', 'created_by' => 1]);
        Role::create(['name' => 'Bank', 'slug' => 'bank', 'description' => 'Bank user', 'created_by' => 1]);
        Role::create(['name' => 'Valuer', 'slug' => 'valuer', 'description' => 'Valuer user', 'created_by' => 1]);

        // Seed initial admin user
        User::create([
            'name' => 'Admin',
            'email' => 'admin@example.com',
            'password' => Hash::make('password'),
            'role_id' => Role::where('slug', 'admin')->first()->id,
            'status_id' => Status::where('name', 'approved')->first()->id,
            'password_updated' => true,
            'message' => 'Why do i need message huh!',
            'created_by' => null,
            'updated_by' => null,
        ]);

        BankType::create(['name' => 'Commercial Bank', 'slug' => 'commercial-bank', 'description' => 'Governed by NRB', 'created_by' => 1, 'updated_by' => 1]);
        BankType::create(['name' => 'Government Bank', 'slug' => 'government-bank', 'description' => 'Governed by NRB', 'created_by' => 1, 'updated_by' => 1]);
        BankType::create(['name' => 'Development Bank', 'slug' => 'development-bank', 'description' => 'Governed by NRB', 'created_by' => 1, 'updated_by' => 1]);
    }
}
