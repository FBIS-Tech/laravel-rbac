<?php

use FbisTech\Rbac\Models\Permission;
use FbisTech\Rbac\Models\Role;

return [

    /*
    |--------------------------------------------------------------------------
    | Permission Registry
    |--------------------------------------------------------------------------
    |
    | Permissions grouped by role type. A role type is a broad audience such
    | as ADMIN or CORPORATE; every role belongs to exactly one type and can
    | only be granted permissions of that type.
    |
    | A string entry is a top-level permission. A key => [children] entry is
    | a parent permission whose children are listed under it in UIs.
    |
    | Run `php artisan rbac:sync` after changing this list.
    |
    */

    'permissions' => [
        // 'ADMIN' => [
        //     'CLIENTS',
        //     'ANALYTICS',
        //     'VTU_MANAGEMENT' => ['VTU_LIST', 'VTU_FUNDING'],
        //     'ADMIN_MANAGEMENT',
        // ],
    ],

    /*
    |--------------------------------------------------------------------------
    | System Roles
    |--------------------------------------------------------------------------
    |
    | One full-access role created per type by `rbac:sync`, e.g.
    | 'ADMIN' => 'Super Admin'. System roles always hold every permission of
    | their type (including ones added later) and cannot be edited or deleted.
    |
    */

    'system_roles' => [
        // 'ADMIN' => 'Super Admin',
    ],

    /*
    |--------------------------------------------------------------------------
    | Permission Filter
    |--------------------------------------------------------------------------
    |
    | Optional class implementing FbisTech\Rbac\Contracts\PermissionFilter to
    | hide granted permissions at runtime, e.g. features a tenant has not
    | switched on. Null disables filtering.
    |
    */

    'permission_filter' => null,

    /*
    |--------------------------------------------------------------------------
    | Gate Integration
    |--------------------------------------------------------------------------
    |
    | When enabled, `$user->can('CLIENTS')` and `$user->can('CLIENTS.edit')`
    | (and @can in Blade) resolve through RBAC for models using HasRoles.
    |
    */

    'register_gate' => true,

    'models' => [
        'role' => Role::class,
        'permission' => Permission::class,
    ],

    'table_names' => [
        'roles' => 'roles',
        'permissions' => 'permissions',
        'role_permissions' => 'role_permissions',
        'model_roles' => 'model_roles',
    ],

    'cache' => [
        'store' => null,
        'ttl' => 3600,
        'prefix' => 'rbac',
    ],

];
