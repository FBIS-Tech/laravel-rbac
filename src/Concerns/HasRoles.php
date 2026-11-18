<?php

namespace FbisTech\Rbac\Concerns;

use FbisTech\Rbac\Enums\Action;
use FbisTech\Rbac\Exceptions\RbacException;
use FbisTech\Rbac\Models\Role;
use FbisTech\Rbac\Support\PermissionKey;
use FbisTech\Rbac\Support\PermissionRegistrar;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Collection;

/**
 * Add to any Eloquent model (usually User) that can hold roles.
 *
 * @mixin Model
 */
trait HasRoles
{
    public static function bootHasRoles(): void
    {
        static::deleting(function ($model) {
            if (method_exists($model, 'isForceDeleting') && ! $model->isForceDeleting()) {
                return;
            }

            $model->roles()->detach();
            $model->flushPermissionCache();
        });
    }

    public function roles(): MorphToMany
    {
        return $this->morphToMany(
            config('rbac.models.role'),
            'model',
            config('rbac.table_names.model_roles'),
            'model_id',
            'role_id'
        )->withTimestamps();
    }

    /**
     * Adds roles, keeping any the model already holds.
     */
    public function assignRole(Role|int|string ...$roles): static
    {
        $this->roles()->syncWithoutDetaching($this->resolveRoleIds($roles));

        return $this->rolesChanged();
    }

    /**
     * Replaces all of the model's roles with the given ones.
     */
    public function syncRoles(Role|int|string ...$roles): static
    {
        $this->roles()->sync($this->resolveRoleIds($roles));

        return $this->rolesChanged();
    }

    /**
     * Replaces all of the model's roles with a single role.
     */
    public function setRole(Role|int|string $role): static
    {
        return $this->syncRoles($role);
    }

    public function removeRole(Role|int|string ...$roles): static
    {
        $this->roles()->detach($this->resolveRoleIds($roles));

        return $this->rolesChanged();
    }

    /**
     * True if the model holds the role, matched by model, id or name.
     */
    public function hasRole(Role|int|string $role): bool
    {
        return $this->roles->contains(function (Role $held) use ($role) {
            return match (true) {
                $role instanceof Role => $held->is($role),
                is_int($role) => $held->id === $role,
                default => $held->name === $role,
            };
        });
    }

    /**
     * True if any held role is of one of the given types, e.g. hasRoleType('ADMIN').
     */
    public function hasRoleType(string ...$types): bool
    {
        return $this->roles->contains(fn (Role $role) => in_array($role->type, $types, true));
    }

    /**
     * Effective permissions across all held roles, keyed by permission key.
     *
     * @return Collection<string, array{id: int, key: string, name: string, parent: string|null, canRead: bool, canAdd: bool, canEdit: bool, canDelete: bool}>
     */
    public function getPermissions(): Collection
    {
        return app(PermissionRegistrar::class)->grantsFor($this);
    }

    /**
     * Accepts keys or labels: "VTU_MANAGEMENT" and "Vtu Management" are equivalent.
     */
    public function hasPermission(string $permission): bool
    {
        return $this->getPermissions()->has(PermissionKey::normalize($permission));
    }

    public function hasAnyPermission(string ...$permissions): bool
    {
        foreach ($permissions as $permission) {
            if ($this->hasPermission($permission)) {
                return true;
            }
        }

        return false;
    }

    public function canPerform(string $permission, Action|string $action): bool
    {
        $grant = $this->getPermissions()->get(PermissionKey::normalize($permission));

        return $grant !== null && $grant[Action::parse($action)->grantKey()];
    }

    public function flushPermissionCache(): void
    {
        app(PermissionRegistrar::class)->flushFor($this);
    }

    private function rolesChanged(): static
    {
        $this->unsetRelation('roles');
        $this->flushPermissionCache();

        return $this;
    }

    /**
     * @param  array<int, Role|int|string>  $roles
     * @return array<int, int>
     */
    private function resolveRoleIds(array $roles): array
    {
        $roleClass = config('rbac.models.role');

        return array_map(function (Role|int|string $role) use ($roleClass) {
            if ($role instanceof Role) {
                return $role->id;
            }

            if (is_int($role)) {
                return $roleClass::query()->whereKey($role)->exists()
                    ? $role
                    : throw RbacException::roleNotFound($role);
            }

            $matches = $roleClass::query()->where('name', $role)->limit(2)->pluck('id');

            return match ($matches->count()) {
                0 => throw RbacException::roleNotFound($role),
                1 => $matches->first(),
                default => throw RbacException::ambiguousRole($role),
            };
        }, $roles);
    }
}
