<?php

namespace FbisTech\Rbac\Tests;

use FbisTech\Rbac\RbacServiceProvider;
use FbisTech\Rbac\RoleManager;
use FbisTech\Rbac\Tests\Fixtures\User;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [RbacServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('cache.default', 'array');
        $app['config']->set('rbac.permissions', [
            'ADMIN' => [
                'CLIENTS',
                'ANALYTICS',
                'VTU_MANAGEMENT' => ['VTU_LIST', 'VTU_FUNDING'],
                'ADMIN_MANAGEMENT',
            ],
            'CORPORATE' => [
                'AUDIT_TRAILS',
                'AUTO_TOPUP',
                'SETTINGS' => ['ACCOUNT_SETTINGS', 'IP_WHITELISTING'],
            ],
        ]);
        $app['config']->set('rbac.system_roles', [
            'ADMIN' => 'Super Admin',
            'CORPORATE' => 'Corporate Admin',
        ]);
    }

    protected function defineDatabaseMigrations(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('email')->nullable();
            $table->boolean('auto_topup')->default(true);
            $table->timestamps();
        });

        (require __DIR__.'/../database/migrations/create_rbac_tables.php')->up();
    }

    protected function roles(): RoleManager
    {
        return $this->app->make(RoleManager::class);
    }

    protected function syncedRoles(): RoleManager
    {
        $roles = $this->roles();
        $roles->syncFromConfig();

        return $roles;
    }

    protected function makeUser(array $attributes = []): User
    {
        return User::query()->create($attributes);
    }
}
