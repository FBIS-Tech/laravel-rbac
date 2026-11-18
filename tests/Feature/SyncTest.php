<?php

namespace FbisTech\Rbac\Tests\Feature;

use FbisTech\Rbac\Models\Permission;
use FbisTech\Rbac\Models\Role;
use FbisTech\Rbac\Tests\TestCase;

class SyncTest extends TestCase
{
    public function test_command_creates_permissions_with_parents_and_system_roles(): void
    {
        $this->artisan('rbac:sync')->assertSuccessful();

        $this->assertSame(6, Permission::query()->ofType('ADMIN')->count());
        $this->assertSame(5, Permission::query()->ofType('CORPORATE')->count());
        $this->assertSame('VTU_MANAGEMENT', Permission::query()->where('name', 'VTU_LIST')->value('parent'));
        $this->assertNull(Permission::query()->where('name', 'CLIENTS')->value('parent'));

        $superAdmin = Role::query()->where('is_system', true)->ofType('ADMIN')->sole();
        $this->assertSame('Super Admin', $superAdmin->name);
        $this->assertCount(6, $superAdmin->permissions);
        $this->assertTrue(collect($superAdmin->grants())->every(fn ($g) => $g['canRead'] && $g['canAdd'] && $g['canEdit'] && $g['canDelete']));
    }

    public function test_sync_is_idempotent(): void
    {
        $this->artisan('rbac:sync')->assertSuccessful();
        $this->artisan('rbac:sync')->assertSuccessful();

        $this->assertSame(11, Permission::query()->count());
        $this->assertSame(2, Role::query()->count());
    }

    public function test_new_config_permission_is_granted_to_existing_system_role(): void
    {
        $this->artisan('rbac:sync');

        config()->set('rbac.permissions.ADMIN', [...config('rbac.permissions.ADMIN'), 'REFUNDS']);
        $this->artisan('rbac:sync');

        $superAdmin = Role::query()->where('is_system', true)->ofType('ADMIN')->sole();
        $this->assertTrue($superAdmin->permissions->contains('name', 'REFUNDS'));
    }

    public function test_prune_removes_permissions_dropped_from_config_only_when_asked(): void
    {
        $this->artisan('rbac:sync');
        config()->set('rbac.permissions.ADMIN', ['CLIENTS']);

        $this->artisan('rbac:sync');
        $this->assertSame(6, Permission::query()->ofType('ADMIN')->count());

        $this->artisan('rbac:sync --prune')->assertSuccessful();
        $this->assertSame(['CLIENTS'], Permission::query()->ofType('ADMIN')->pluck('name')->all());
        $this->assertSame(5, Permission::query()->ofType('CORPORATE')->count());
    }
}
