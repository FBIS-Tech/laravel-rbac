<?php

namespace FbisTech\Rbac\Tests\Feature;

use FbisTech\Rbac\Enums\Action;
use FbisTech\Rbac\Exceptions\RbacException;
use FbisTech\Rbac\Models\Role;
use FbisTech\Rbac\Tests\Fixtures\DisabledFeatureFilter;
use FbisTech\Rbac\Tests\TestCase;
use Illuminate\Support\Facades\DB;

class HasRolesTest extends TestCase
{
    public function test_permissions_and_actions_come_from_the_assigned_role(): void
    {
        $role = $this->syncedRoles()->createRole('ADMIN', 'Support', [
            ['permission' => 'CLIENTS', 'canRead' => true],
            ['permission' => 'VTU_LIST', 'canRead' => true, 'canEdit' => true],
        ]);
        $user = $this->makeUser()->setRole($role);

        $this->assertTrue($user->hasPermission('CLIENTS'));
        $this->assertTrue($user->hasPermission('Vtu List'));
        $this->assertFalse($user->hasPermission('ANALYTICS'));
        $this->assertTrue($user->canPerform('VTU_LIST', 'edit'));
        $this->assertTrue($user->canPerform('VTU_LIST', Action::Read));
        $this->assertFalse($user->canPerform('CLIENTS', 'delete'));
        $this->assertFalse($user->canPerform('ANALYTICS', 'read'));
        $this->assertSame('Vtu Management', $user->getPermissions()->get('VTU_LIST')['parent']);
    }

    public function test_actions_are_combined_across_multiple_roles(): void
    {
        $roles = $this->syncedRoles();
        $reader = $roles->createRole('ADMIN', 'Reader', [['permission' => 'CLIENTS', 'canRead' => true]]);
        $deleter = $roles->createRole('ADMIN', 'Deleter', [['permission' => 'CLIENTS', 'canDelete' => true]]);

        $user = $this->makeUser()->assignRole($reader, $deleter);

        $this->assertTrue($user->canPerform('CLIENTS', 'read'));
        $this->assertTrue($user->canPerform('CLIENTS', 'delete'));
        $this->assertFalse($user->canPerform('CLIENTS', 'edit'));
    }

    public function test_set_role_replaces_previous_roles(): void
    {
        $roles = $this->syncedRoles();
        $first = $roles->createRole('ADMIN', 'First', [['permission' => 'CLIENTS', 'canRead' => true]]);
        $second = $roles->createRole('ADMIN', 'Second', [['permission' => 'ANALYTICS', 'canRead' => true]]);

        $user = $this->makeUser()->setRole($first)->setRole($second);

        $this->assertFalse($user->hasRole($first));
        $this->assertTrue($user->hasRole('Second'));
        $this->assertTrue($user->hasRole($second->id));
        $this->assertFalse($user->hasPermission('CLIENTS'));
        $this->assertTrue($user->hasPermission('ANALYTICS'));
    }

    public function test_role_type_check(): void
    {
        $user = $this->makeUser()->setRole($this->syncedRoles()->rolesFor('CORPORATE')->first());

        $this->assertTrue($user->hasRoleType('CORPORATE'));
        $this->assertTrue($user->hasRoleType('ADMIN', 'CORPORATE'));
        $this->assertFalse($user->hasRoleType('ADMIN'));
    }

    public function test_role_update_invalidates_cached_permissions_for_existing_users(): void
    {
        $roles = $this->syncedRoles();
        $role = $roles->createRole('ADMIN', 'Support', [['permission' => 'CLIENTS', 'canRead' => true]]);
        $user = $this->makeUser()->setRole($role);
        $this->assertFalse($user->canPerform('CLIENTS', 'edit'));

        $roles->updateRole($role, grants: [['permission' => 'CLIENTS', 'canRead' => true, 'canEdit' => true]]);

        $this->assertTrue($user->fresh()->canPerform('CLIENTS', 'edit'));
    }

    public function test_permissions_are_cached_between_calls(): void
    {
        $user = $this->makeUser()->setRole($this->syncedRoles()->rolesFor('ADMIN')->first());
        $user->getPermissions();

        DB::enableQueryLog();
        $user->hasPermission('CLIENTS');
        $user->canPerform('CLIENTS', 'edit');

        $this->assertCount(0, DB::getQueryLog());
    }

    public function test_permission_filter_hides_disabled_features(): void
    {
        config()->set('rbac.permission_filter', DisabledFeatureFilter::class);
        $role = $this->syncedRoles()->rolesFor('CORPORATE')->first();

        $enabled = $this->makeUser(['auto_topup' => true])->setRole($role);
        $disabled = $this->makeUser(['auto_topup' => false])->setRole($role);

        $this->assertTrue($enabled->hasPermission('AUTO_TOPUP'));
        $this->assertFalse($disabled->hasPermission('AUTO_TOPUP'));
        $this->assertTrue($disabled->hasPermission('AUDIT_TRAILS'));
    }

    public function test_assigning_unknown_or_ambiguous_role_names_fails(): void
    {
        $roles = $this->syncedRoles();
        $roles->createRole('CORPORATE', 'Finance', tenantId: 1);
        $roles->createRole('CORPORATE', 'Finance', tenantId: 2);
        $user = $this->makeUser();

        try {
            $user->setRole('Finance');
            $this->fail('Expected ambiguous role exception.');
        } catch (RbacException $e) {
            $this->assertStringContainsString('More than one role', $e->getMessage());
        }

        $this->expectException(RbacException::class);
        $user->setRole('Nope');
    }

    public function test_deleting_a_user_removes_their_role_assignments(): void
    {
        $user = $this->makeUser()->setRole($this->syncedRoles()->rolesFor('ADMIN')->first());

        $user->delete();

        $this->assertSame(0, DB::table('model_roles')->count());
        $this->assertSame(2, Role::query()->count());
    }
}
