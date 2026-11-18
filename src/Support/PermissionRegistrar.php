<?php

namespace FbisTech\Rbac\Support;

use FbisTech\Rbac\Contracts\PermissionFilter;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

/**
 * Resolves and caches the effective permissions of a model across all its roles.
 */
class PermissionRegistrar
{
    public function __construct(
        private readonly CacheFactory $cacheFactory,
        private readonly Container $container,
    ) {}

    /**
     * Effective grants keyed by permission key. When a model holds several
     * roles, an action is allowed if any of its roles allows it.
     *
     * @return Collection<string, array{id: int, key: string, name: string, parent: string|null, canRead: bool, canAdd: bool, canEdit: bool, canDelete: bool}>
     */
    public function grantsFor(Model $model): Collection
    {
        $grants = $this->cache()->remember(
            $this->cacheKey($model),
            (int) config('rbac.cache.ttl', 3600),
            fn () => $this->loadGrants($model)
        );

        $filter = $this->filter();

        return collect($grants)
            ->filter(fn (array $grant) => $filter === null || $filter->allows($model, $grant['key']));
    }

    public function flushFor(Model $model): void
    {
        $this->cache()->forget($this->cacheKey($model));
    }

    /**
     * Invalidates every cached grant set at once by bumping a version number,
     * used whenever a role or permission changes.
     */
    public function flushAll(): void
    {
        $key = $this->prefix().':version';

        $this->cache()->forever($key, ((int) $this->cache()->get($key, 0)) + 1);
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function loadGrants(Model $model): array
    {
        $tables = config('rbac.table_names');

        $rows = DB::table($tables['role_permissions'].' as rp')
            ->join($tables['permissions'].' as p', 'p.id', '=', 'rp.permission_id')
            ->join($tables['model_roles'].' as mr', 'mr.role_id', '=', 'rp.role_id')
            ->where('mr.model_type', $model->getMorphClass())
            ->where('mr.model_id', $model->getKey())
            ->orderBy('p.id')
            ->get(['p.id', 'p.name', 'p.parent', 'rp.can_read', 'rp.can_add', 'rp.can_edit', 'rp.can_delete']);

        $grants = [];

        foreach ($rows as $row) {
            $existing = $grants[$row->name] ?? null;

            $grants[$row->name] = [
                'id' => (int) $row->id,
                'key' => $row->name,
                'name' => PermissionKey::label($row->name),
                'parent' => $row->parent ? PermissionKey::label($row->parent) : null,
                'canRead' => (bool) $row->can_read || ($existing['canRead'] ?? false),
                'canAdd' => (bool) $row->can_add || ($existing['canAdd'] ?? false),
                'canEdit' => (bool) $row->can_edit || ($existing['canEdit'] ?? false),
                'canDelete' => (bool) $row->can_delete || ($existing['canDelete'] ?? false),
            ];
        }

        return $grants;
    }

    private function filter(): ?PermissionFilter
    {
        $class = config('rbac.permission_filter');

        return $class ? $this->container->make($class) : null;
    }

    private function cacheKey(Model $model): string
    {
        $version = (int) $this->cache()->get($this->prefix().':version', 0);

        return sprintf('%s:v%d:%s:%s', $this->prefix(), $version, $model->getMorphClass(), $model->getKey());
    }

    private function prefix(): string
    {
        return (string) config('rbac.cache.prefix', 'rbac');
    }

    private function cache(): Repository
    {
        return $this->cacheFactory->store(config('rbac.cache.store'));
    }
}
