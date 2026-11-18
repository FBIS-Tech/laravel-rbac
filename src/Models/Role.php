<?php

namespace FbisTech\Rbac\Models;

use FbisTech\Rbac\Support\PermissionKey;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Facades\DB;

/**
 * @property int $id
 * @property string $type
 * @property string $name
 * @property int|null $tenant_id
 * @property bool $is_system
 */
class Role extends Model
{
    protected $guarded = ['id'];

    /**
     * @var array<string, string>
     */
    protected $casts = [
        'tenant_id' => 'integer',
        'is_system' => 'boolean',
    ];

    public function getTable(): string
    {
        return config('rbac.table_names.roles', parent::getTable());
    }

    public function permissions(): BelongsToMany
    {
        return $this->belongsToMany(
            config('rbac.models.permission'),
            config('rbac.table_names.role_permissions'),
            'role_id',
            'permission_id'
        )->withPivot(['can_read', 'can_add', 'can_edit', 'can_delete']);
    }

    public function scopeOfType(Builder $query, string $type): Builder
    {
        return $query->where('type', $type);
    }

    /**
     * Roles owned by the tenant, plus shared (tenant-less) roles unless excluded.
     */
    public function scopeForTenant(Builder $query, ?int $tenantId, bool $includeShared = true): Builder
    {
        return $query->where(function (Builder $query) use ($tenantId, $includeShared) {
            $query->where('tenant_id', $tenantId);

            if ($includeShared && $tenantId !== null) {
                $query->orWhereNull('tenant_id');
            }
        });
    }

    public function isAssigned(): bool
    {
        return DB::table(config('rbac.table_names.model_roles'))->where('role_id', $this->id)->exists();
    }

    /**
     * @return array<int, array{id: int, key: string, name: string, parent: string|null, canRead: bool, canAdd: bool, canEdit: bool, canDelete: bool}>
     */
    public function grants(): array
    {
        return $this->permissions->map(fn (Permission $permission) => [
            'id' => $permission->id,
            'key' => $permission->name,
            'name' => PermissionKey::label($permission->name),
            'parent' => $permission->parent ? PermissionKey::label($permission->parent) : null,
            'canRead' => (bool) $permission->pivot->can_read,
            'canAdd' => (bool) $permission->pivot->can_add,
            'canEdit' => (bool) $permission->pivot->can_edit,
            'canDelete' => (bool) $permission->pivot->can_delete,
        ])->values()->all();
    }
}
