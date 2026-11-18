<?php

namespace FbisTech\Rbac;

use FbisTech\Rbac\Enums\Action;
use FbisTech\Rbac\Exceptions\RbacException;
use FbisTech\Rbac\Models\Permission;
use FbisTech\Rbac\Models\Role;
use FbisTech\Rbac\Support\PermissionKey;
use FbisTech\Rbac\Support\PermissionRegistrar;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;

/**
 * Creates and maintains roles and permissions.
 *
 * Grants are passed as a list of items identifying a permission by "id" or
 * "permission" (key or label), with action flags in camelCase or snake_case:
 *   [['id' => 3, 'canRead' => true, 'canEdit' => false], ['permission' => 'CLIENTS', 'can_read' => true]]
 * A flag that is left out is false.
 */
class RoleManager
{
    public function __construct(private readonly PermissionRegistrar $registrar) {}

    /**
     * @param  array<int, array<string, mixed>>  $grants
     */
    public function createRole(string $type, string $name, array $grants = [], ?int $tenantId = null): Role
    {
        $this->ensureNameIsAvailable($type, $name, $tenantId);

        $pivot = $this->normalizeGrants($type, $grants);

        return DB::transaction(function () use ($type, $name, $tenantId, $pivot) {
            $role = $this->roleModel()::query()->create([
                'type' => $type,
                'name' => $name,
                'tenant_id' => $tenantId,
                'is_system' => false,
            ]);

            $role->permissions()->sync($pivot);

            return $role->load('permissions');
        });
    }

    /**
     * Pass null to leave the name or the grants unchanged.
     *
     * @param  array<int, array<string, mixed>>|null  $grants
     */
    public function updateRole(Role $role, ?string $name = null, ?array $grants = null): Role
    {
        if ($role->is_system) {
            throw RbacException::systemRole($role->name);
        }

        if ($name !== null && $name !== $role->name) {
            $this->ensureNameIsAvailable($role->type, $name, $role->tenant_id, $role->id);
        }

        $pivot = $grants === null ? null : $this->normalizeGrants($role->type, $grants);

        DB::transaction(function () use ($role, $name, $pivot) {
            if ($name !== null) {
                $role->update(['name' => $name]);
            }

            if ($pivot !== null) {
                $role->permissions()->sync($pivot);
            }
        });

        $this->registrar->flushAll();

        return $role->load('permissions');
    }

    public function deleteRole(Role $role): void
    {
        if ($role->is_system) {
            throw RbacException::systemRole($role->name);
        }

        if ($role->isAssigned()) {
            throw RbacException::roleInUse($role->name);
        }

        DB::transaction(function () use ($role) {
            $role->permissions()->detach();
            $role->delete();
        });

        $this->registrar->flushAll();
    }

    /**
     * Creates the permission if it does not exist and grants it in full to
     * the type's system roles.
     */
    public function createPermission(string $type, string $name, ?string $parent = null): Permission
    {
        $permission = DB::transaction(function () use ($type, $name, $parent) {
            $permission = $this->permissionModel()::query()->updateOrCreate(
                ['type' => $type, 'name' => PermissionKey::normalize($name)],
                ['parent' => $parent === null ? null : PermissionKey::normalize($parent)]
            );

            $this->grantToSystemRoles($type, [$permission->id]);

            return $permission;
        });

        $this->registrar->flushAll();

        return $permission;
    }

    /**
     * @return Collection<int, Permission>
     */
    public function permissionsFor(string $type): Collection
    {
        return $this->permissionModel()::query()->ofType($type)->orderBy('id')->get();
    }

    /**
     * @return Collection<int, Role>
     */
    public function rolesFor(string $type, ?int $tenantId = null, bool $includeShared = true): Collection
    {
        return $this->roleModel()::query()
            ->with('permissions')
            ->ofType($type)
            ->forTenant($tenantId, $includeShared)
            ->latest('id')
            ->get();
    }

    /**
     * Brings the database in line with config('rbac.permissions') and
     * config('rbac.system_roles'). Safe to run repeatedly.
     *
     * @return array{permissions: int, system_roles: int, pruned: int}
     */
    public function syncFromConfig(bool $prune = false): array
    {
        $stats = ['permissions' => 0, 'system_roles' => 0, 'pruned' => 0];

        DB::transaction(function () use ($prune, &$stats) {
            foreach ((array) config('rbac.permissions', []) as $type => $definitions) {
                $keys = [];

                foreach ($this->flattenDefinitions((array) $definitions) as $name => $parent) {
                    $this->permissionModel()::query()->updateOrCreate(
                        ['type' => $type, 'name' => $name],
                        ['parent' => $parent]
                    );

                    $keys[] = $name;
                    $stats['permissions']++;
                }

                if ($prune) {
                    $stats['pruned'] += $this->permissionModel()::query()
                        ->ofType($type)
                        ->whereNotIn('name', $keys)
                        ->delete();
                }
            }

            foreach ((array) config('rbac.system_roles', []) as $type => $name) {
                $this->roleModel()::query()->firstOrCreate(
                    ['type' => $type, 'is_system' => true, 'tenant_id' => null],
                    ['name' => $name]
                )->update(['name' => $name]);

                $this->grantToSystemRoles($type, $this->permissionsFor($type)->modelKeys());
                $stats['system_roles']++;
            }
        });

        $this->registrar->flushAll();

        return $stats;
    }

    /**
     * @param  array<int, int>  $permissionIds
     */
    private function grantToSystemRoles(string $type, array $permissionIds): void
    {
        $fullAccess = array_fill_keys(array_map(fn (Action $action) => $action->column(), Action::cases()), true);

        $this->roleModel()::query()->ofType($type)->where('is_system', true)->each(
            fn (Role $role) => $role->permissions()->syncWithoutDetaching(array_fill_keys($permissionIds, $fullAccess))
        );
    }

    /**
     * @param  array<int|string, string|array<int, string>>  $definitions
     * @return array<string, string|null> permission key => parent key
     */
    private function flattenDefinitions(array $definitions): array
    {
        $flat = [];

        foreach ($definitions as $key => $value) {
            if (is_array($value)) {
                $parent = PermissionKey::normalize((string) $key);
                $flat[$parent] ??= null;

                foreach ($value as $child) {
                    $flat[PermissionKey::normalize($child)] ??= $parent;
                }

                continue;
            }

            $flat[PermissionKey::normalize($value)] ??= null;
        }

        return $flat;
    }

    /**
     * @param  array<int, array<string, mixed>>  $grants
     * @return array<int, array<string, bool>> permission id => pivot flags
     */
    private function normalizeGrants(string $type, array $grants): array
    {
        $permissions = $this->permissionsFor($type);
        $byId = $permissions->keyBy('id');
        $byName = $permissions->keyBy('name');
        $pivot = [];

        foreach ($grants as $grant) {
            $reference = $grant['id'] ?? $grant['permission'] ?? null;

            $permission = match (true) {
                is_int($reference) || ctype_digit((string) $reference) => $byId->get((int) $reference),
                is_string($reference) => $byName->get(PermissionKey::normalize($reference)),
                default => null,
            };

            if ($permission === null) {
                throw RbacException::permissionNotFound($type, is_scalar($reference) ? $reference : '?');
            }

            foreach (Action::cases() as $action) {
                $pivot[$permission->id][$action->column()] = (bool) ($grant[$action->grantKey()] ?? $grant[$action->column()] ?? false);
            }
        }

        return $pivot;
    }

    private function ensureNameIsAvailable(string $type, string $name, ?int $tenantId, ?int $ignoreId = null): void
    {
        $exists = $this->roleModel()::query()
            ->ofType($type)
            ->where('name', $name)
            ->where(fn ($query) => $tenantId === null ? $query->whereNull('tenant_id') : $query->where('tenant_id', $tenantId))
            ->when($ignoreId, fn ($query) => $query->whereKeyNot($ignoreId))
            ->exists();

        if ($exists) {
            throw RbacException::roleExists($name);
        }
    }

    /**
     * @return class-string<Role>
     */
    private function roleModel(): string
    {
        return config('rbac.models.role');
    }

    /**
     * @return class-string<Permission>
     */
    private function permissionModel(): string
    {
        return config('rbac.models.permission');
    }
}
