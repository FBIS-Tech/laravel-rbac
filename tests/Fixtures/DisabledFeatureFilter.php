<?php

namespace FbisTech\Rbac\Tests\Fixtures;

use FbisTech\Rbac\Contracts\PermissionFilter;
use Illuminate\Database\Eloquent\Model;

class DisabledFeatureFilter implements PermissionFilter
{
    public function allows(Model $model, string $permission): bool
    {
        return ! ($permission === 'AUTO_TOPUP' && ! $model->getAttribute('auto_topup'));
    }
}
