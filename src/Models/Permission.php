<?php

namespace FbisTech\Rbac\Models;

use FbisTech\Rbac\Support\PermissionKey;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

/**
 * @property int $id
 * @property string $type
 * @property string $name
 * @property string|null $parent
 */
class Permission extends Model
{
    protected $guarded = ['id'];

    public function getTable(): string
    {
        return config('rbac.table_names.permissions', parent::getTable());
    }

    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(
            config('rbac.models.role'),
            config('rbac.table_names.role_permissions'),
            'permission_id',
            'role_id'
        )->withPivot(['can_read', 'can_add', 'can_edit', 'can_delete']);
    }

    public function scopeOfType(Builder $query, string $type): Builder
    {
        return $query->where('type', $type);
    }

    public function label(): string
    {
        return PermissionKey::label($this->name);
    }

    /**
     * @return array{id: int, key: string, name: string, parent: string|null}
     */
    public function toRbacArray(): array
    {
        return [
            'id' => $this->id,
            'key' => $this->name,
            'name' => $this->label(),
            'parent' => $this->parent ? PermissionKey::label($this->parent) : null,
        ];
    }
}
