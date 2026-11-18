<?php

namespace FbisTech\Rbac\Tests\Feature;

use FbisTech\Rbac\Exceptions\RbacException;
use FbisTech\Rbac\Models\Permission;
use FbisTech\Rbac\Models\Role;
use FbisTech\Rbac\Tests\TestCase;
use Illuminate\Support\Facades\DB;

class RoleManagerTest extends TestCase
{
    public function test_create_role_accepts_ids_keys_and_snake_case_flags(): void
    {
        $roles = $this->syncedRoles();
        $clients = Permission::query()->where('name', 'CLIENTS')->sole();

        $role = $roles->createRole('ADMIN', 'Ops', [
            ['id' => $clients->id, 'canRead' => true, 'canAdd' => true],
            ['permission' => 'Vtu Funding', 'can_read' => true, 'can_delete' => true],
        ]);

        $grants = collect($role->grants())->keyBy('key');
        $this->assertSame(['canRead' => true, 'canAdd' => true, 'canEdit' => false, 'canDelete' => false], array_intersect_key($grants['CLIENTS'], array_flip(['canRead', 'canAdd', 'canEdit', 'canDelete'])));
        $this->assertTrue($grants['VTU_FUNDING']['canDelete']);
        $this->assertFalse($role->is_system);
    }

    public function test_create_role_rejects_permissions_of_another_type(): void
    {
        $this->expectException(RbacException::class);
        $this->expectExceptionMessage('AUDIT_TRAILS');

        $this->syncedRoles()->createRole('ADMIN', 'Ops', [['permission' => 'AUDIT_TRAILS', 'canRead' => true]]);
    }

    public function test_role_names_are_unique_per_type_and_tenant(): void
    {
        $roles = $this->syncedRoles();
        $roles->createRole('CORPORATE', 'Finance', tenantId: 1);
        $roles->createRole('CORPORATE', 'Finance', tenantId: 2);
        $roles->createRole('ADMIN', 'Finance');

        $this->expectException(RbacException::class);
        $roles->createRole('CORPORATE', 'Finance', tenantId: 1);
    }

    public function test_roles_for_tenant_include_shared_roles_by_default(): void
    {
        $roles = $this->syncedRoles();
        $roles->createRole('CORPORATE', 'Finance', tenantId: 1);
        $roles->createRole('CORPORATE', 'Ops', tenantId: 2);

        $this->assertEqualsCanonicalizing(['Finance', 'Corporate Admin'], $roles->rolesFor('CORPORATE', 1)->pluck('name')->all());
        $this->assertSame(['Finance'], $roles->rolesFor('CORPORATE', 1, includeShared: false)->pluck('name')->all());
        $this->assertSame(['Corporate Admin'], $roles->rolesFor('CORPORATE')->pluck('name')->all());
    }

    public function test_update_role_renames_and_replaces_grants(): void
    {
        $roles = $this->syncedRoles();
        $role = $roles->createRole('ADMIN', 'Ops', [['permission' => 'CLIENTS', 'canRead' => true]]);

        $roles->updateRole($role, 'Operations', [['permission' => 'ANALYTICS', 'canRead' => true]]);

        $this->assertSame('Operations', $role->fresh()->name);
        $this->assertSame(['ANALYTICS'], $role->fresh()->permissions->pluck('name')->all());
    }

    public function test_update_role_with_only_a_name_keeps_grants(): void
    {
        $roles = $this->syncedRoles();
        $role = $roles->createRole('ADMIN', 'Ops', [['permission' => 'CLIENTS', 'canRead' => true]]);

        $roles->updateRole($role, 'Operations');

        $this->assertSame(['CLIENTS'], $role->fresh()->permissions->pluck('name')->all());
    }

    public function test_rename_to_an_existing_name_fails(): void
    {
        $roles = $this->syncedRoles();
        $roles->createRole('ADMIN', 'Ops');
        $role = $roles->createRole('ADMIN', 'Support');

        $this->expectException(RbacException::class);
        $roles->updateRole($role, 'Ops');
    }

    public function test_system_roles_cannot_be_updated_or_deleted(): void
    {
        $roles = $this->syncedRoles();
        $system = Role::query()->where('is_system', true)->firstOrFail();

        try {
            $roles->updateRole($system, 'Renamed');
            $this->fail('Expected system role exception.');
        } catch (RbacException) {
        }

        $this->expectException(RbacException::class);
        $roles->deleteRole($system);
    }

    public function test_assigned_role_cannot_be_deleted(): void
    {
        $roles = $this->syncedRoles();
        $role = $roles->createRole('ADMIN', 'Ops');
        $this->makeUser()->setRole($role);

        $this->expectException(RbacException::class);
        $this->expectExceptionMessage('assigned');
        $roles->deleteRole($role);
    }

    public function test_unassigned_role_is_deleted_with_its_grants(): void
    {
        $roles = $this->syncedRoles();
        $role = $roles->createRole('ADMIN', 'Ops', [['permission' => 'CLIENTS', 'canRead' => true]]);

        $roles->deleteRole($role);

        $this->assertNull(Role::query()->find($role->id));
        $this->assertSame(0, DB::table('role_permissions')->where('role_id', $role->id)->count());
    }

    public function test_create_permission_grants_it_to_system_roles_and_their_users(): void
    {
        $roles = $this->syncedRoles();
        $user = $this->makeUser()->setRole(Role::query()->ofType('ADMIN')->where('is_system', true)->sole());
        $this->assertFalse($user->hasPermission('REFUNDS'));

        $permission = $roles->createPermission('ADMIN', 'Refunds', parent: 'clients');

        $this->assertSame('REFUNDS', $permission->name);
        $this->assertSame('CLIENTS', $permission->parent);
        $this->assertTrue($user->fresh()->canPerform('REFUNDS', 'delete'));
        $this->assertFalse(Role::query()->ofType('CORPORATE')->where('is_system', true)->sole()->permissions->contains('name', 'REFUNDS'));
    }

    public function test_permissions_for_type_lists_labels_and_parents(): void
    {
        $list = $this->syncedRoles()->permissionsFor('CORPORATE')->map->toRbacArray();

        $this->assertContains(['id' => $list->firstWhere('key', 'IP_WHITELISTING')['id'], 'key' => 'IP_WHITELISTING', 'name' => 'Ip Whitelisting', 'parent' => 'Settings'], $list->all());
    }
}
