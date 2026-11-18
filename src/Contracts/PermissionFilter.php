<?php

namespace FbisTech\Rbac\Contracts;

use Illuminate\Database\Eloquent\Model;

/**
 * Hides granted permissions at runtime, e.g. features a tenant has not enabled.
 */
interface PermissionFilter
{
    /**
     * @param  string  $permission  Normalised permission key, e.g. "AUTO_TOPUP".
     */
    public function allows(Model $model, string $permission): bool;
}
