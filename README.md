# Laravel RBAC

Role-based access control for Laravel:

- **Roles** with a **type** (e.g. `ADMIN`, `CORPORATE`) and an optional **tenant**.
- **Permissions** per type, optionally grouped under a parent.
- **Per-action flags** on every grant: `read`, `add`, `edit`, `delete`.
- One full-access **system role** per type, kept in sync automatically.
- Route middleware, Gate/`@can` integration, cached lookups.

Standalone. It does not need `spatie/laravel-permission`.

## Install

Add the repository to your app's `composer.json`:

```json
"repositories": [
    { "type": "vcs", "url": "https://github.com/FBIS-Tech/laravel-rbac.git" }
]
```

```bash
composer require fbis-tech/laravel-rbac:^1.0
php artisan vendor:publish --tag=rbac-config
php artisan vendor:publish --tag=rbac-migrations
php artisan migrate
```

The migration creates `roles`, `permissions`, `role_permissions` and `model_roles`. You can rename them in `config/rbac.php` under `table_names` before migrating.

## Configure

Register your permissions and system roles in `config/rbac.php`:

```php
'permissions' => [
    'ADMIN' => [
        'CLIENTS',
        'ANALYTICS',
        'VTU_MANAGEMENT' => ['VTU_LIST', 'VTU_FUNDING'], // parent => children
        'ADMIN_MANAGEMENT',
    ],
    'CORPORATE' => [
        'AUDIT_TRAILS',
        'SETTINGS' => ['ACCOUNT_SETTINGS', 'IP_WHITELISTING'],
    ],
],

'system_roles' => [
    'ADMIN'     => 'Super Admin',
    'CORPORATE' => 'Corporate Admin',
],
```

Then sync. Run it on every deploy; it is safe to repeat:

```bash
php artisan rbac:sync           # add/update permissions, grant them to system roles
php artisan rbac:sync --prune   # also delete permissions removed from config
```

Add the trait to your user model:

```php
use FbisTech\Rbac\Concerns\HasRoles;

class User extends Authenticatable
{
    use HasRoles;
}
```

## Protect routes

| Middleware | Passes when |
| --- | --- |
| `rbac.permission:CLIENTS\|ANALYTICS` | the user has **any** of the permissions |
| `rbac.permit:ADMIN_MANAGEMENT,edit` | the user has the permission **and** the action (`read`, `add`, `edit`, `delete`) |
| `rbac.permit:ADMIN_MANAGEMENT` | the user has the permission, with any action |
| `rbac.type:ADMIN` | the user holds a role of that type |

```php
Route::middleware(['auth:sanctum', 'rbac.permission:ADMIN_MANAGEMENT'])->group(function () {
    Route::get('/roles', [RoleController::class, 'index'])->middleware('rbac.permit:ADMIN_MANAGEMENT,read');
    Route::post('/roles', [RoleController::class, 'store'])->middleware('rbac.permit:ADMIN_MANAGEMENT,add');
});
```

Guests get a 401. Users without access get a 403; JSON requests receive:

```json
{ "success": false, "message": "You do not have the permission to edit Admin Management data" }
```

To use shorter aliases, register your own in `bootstrap/app.php` or `app/Http/Kernel.php`:

```php
'permit' => \FbisTech\Rbac\Http\Middleware\RequirePermissionAction::class,
```

## Check access in code

```php
$user->hasPermission('CLIENTS');            // keys or labels: 'Vtu List' === 'VTU_LIST'
$user->hasAnyPermission('CLIENTS', 'ANALYTICS');
$user->canPerform('CLIENTS', 'edit');       // or Action::Edit
$user->hasRoleType('ADMIN');
$user->hasRole('Support');                  // by name, id or Role model

$user->getPermissions();                    // effective grants, keyed by permission key
// ['CLIENTS' => ['id' => 1, 'key' => 'CLIENTS', 'name' => 'Clients', 'parent' => null,
//                'canRead' => true, 'canAdd' => false, 'canEdit' => false, 'canDelete' => false], ...]
```

With `register_gate` enabled (the default), `$user->can('CLIENTS')`, `$user->can('CLIENTS.edit')` and `@can('CLIENTS.edit')` also work. Abilities that are not granted fall through to your other gates and policies.

A user with several roles gets an action if **any** of their roles allows it.

## Assign roles

```php
$user->setRole($role);              // replace all roles with one
$user->assignRole($roleA, $roleB);  // add, keeping existing roles
$user->syncRoles($roleA);           // replace with a set
$user->removeRole($roleA);
```

Roles can be passed as a model, an id, or a name. If more than one role has that name (for example two tenants each have "Finance"), assigning by name throws; pass the model or id instead.

## Manage roles and permissions

Inject `FbisTech\Rbac\RoleManager`:

```php
$role = $roles->createRole('CORPORATE', 'Finance', [
    ['id' => 3, 'canRead' => true, 'canEdit' => true],
    ['permission' => 'AUDIT_TRAILS', 'canRead' => true],   // by key or label
], tenantId: $client->id);

$roles->updateRole($role, name: 'Finance Team', grants: [...]);  // null leaves a field unchanged
$roles->deleteRole($role);                     // throws if users still hold it

$roles->rolesFor('CORPORATE', $client->id);    // tenant roles + shared roles (e.g. the system role)
$roles->permissionsFor('CORPORATE')->map->toRbacArray();  // id, key, name, parent for a role editor UI
$roles->createPermission('ADMIN', 'REFUNDS', parent: 'CLIENTS');  // also granted to the system role

$role->grants();                               // the role's permissions with action flags
```

Grant flags may be camelCase (`canEdit`) or snake_case (`can_edit`); a flag that is left out is `false`. Permissions from another role type are rejected.

Role names are unique per type and tenant. System roles cannot be edited or deleted. Failures throw `FbisTech\Rbac\Exceptions\RbacException`.

## Hide permissions at runtime

To hide granted permissions based on state (for example a feature a tenant has not switched on), implement `PermissionFilter` and set it in `config/rbac.php`:

```php
use FbisTech\Rbac\Contracts\PermissionFilter;

class EnabledFeaturesFilter implements PermissionFilter
{
    public function allows(Model $user, string $permission): bool
    {
        return match ($permission) {
            'AUTO_TOPUP' => (bool) $user->client?->auto_topup,
            default => true,
        };
    }
}
```

```php
'permission_filter' => App\Rbac\EnabledFeaturesFilter::class,
```

## Caching

Each user's grants are cached (`cache.ttl`, default one hour, in `cache.store`). Changing a user's roles clears that user's cache. Changing a role or permission through `RoleManager` or `rbac:sync` clears everyone's. If you edit the tables directly, call `app(\FbisTech\Rbac\Support\PermissionRegistrar::class)->flushAll()`.

## Testing

```bash
composer install
vendor/bin/phpunit
```
