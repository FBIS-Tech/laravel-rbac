<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $tables = config('rbac.table_names');

        Schema::create($tables['permissions'], function (Blueprint $table) {
            $table->id();
            $table->string('type');
            $table->string('name');
            $table->string('parent')->nullable();
            $table->timestamps();

            $table->unique(['type', 'name']);
        });

        Schema::create($tables['roles'], function (Blueprint $table) {
            $table->id();
            $table->string('type');
            $table->string('name');
            $table->unsignedBigInteger('tenant_id')->nullable();
            $table->boolean('is_system')->default(false);
            $table->timestamps();

            $table->index(['type', 'tenant_id']);
        });

        Schema::create($tables['role_permissions'], function (Blueprint $table) use ($tables) {
            $table->foreignId('role_id')->constrained($tables['roles'])->cascadeOnDelete();
            $table->foreignId('permission_id')->constrained($tables['permissions'])->cascadeOnDelete();
            $table->boolean('can_read')->default(true);
            $table->boolean('can_add')->default(false);
            $table->boolean('can_edit')->default(false);
            $table->boolean('can_delete')->default(false);

            $table->primary(['role_id', 'permission_id']);
        });

        Schema::create($tables['model_roles'], function (Blueprint $table) use ($tables) {
            $table->foreignId('role_id')->constrained($tables['roles'])->cascadeOnDelete();
            $table->morphs('model');
            $table->timestamps();

            $table->primary(['role_id', 'model_type', 'model_id']);
        });
    }

    public function down(): void
    {
        $tables = config('rbac.table_names');

        Schema::dropIfExists($tables['model_roles']);
        Schema::dropIfExists($tables['role_permissions']);
        Schema::dropIfExists($tables['roles']);
        Schema::dropIfExists($tables['permissions']);
    }
};
