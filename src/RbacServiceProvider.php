<?php

namespace FbisTech\Rbac;

use FbisTech\Rbac\Commands\SyncCommand;
use FbisTech\Rbac\Concerns\HasRoles;
use FbisTech\Rbac\Enums\Action;
use FbisTech\Rbac\Http\Middleware\RequirePermission;
use FbisTech\Rbac\Http\Middleware\RequirePermissionAction;
use FbisTech\Rbac\Http\Middleware\RequireRoleType;
use FbisTech\Rbac\Support\PermissionRegistrar;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

class RbacServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/rbac.php', 'rbac');

        $this->app->singleton(PermissionRegistrar::class);
        $this->app->singleton(RoleManager::class);
    }

    public function boot(): void
    {
        $this->registerPublishing();
        $this->registerMiddleware();
        $this->registerGate();

        if ($this->app->runningInConsole()) {
            $this->commands([SyncCommand::class]);
        }
    }

    private function registerPublishing(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->publishes([__DIR__.'/../config/rbac.php' => config_path('rbac.php')], 'rbac-config');

        if (method_exists($this, 'publishesMigrations')) {
            $this->publishesMigrations([__DIR__.'/../database/migrations' => database_path('migrations')], 'rbac-migrations');

            return;
        }

        $this->publishes([
            __DIR__.'/../database/migrations/create_rbac_tables.php' => database_path('migrations/'.date('Y_m_d_His').'_create_rbac_tables.php'),
        ], 'rbac-migrations');
    }

    private function registerMiddleware(): void
    {
        $router = $this->app->make(Router::class);

        $router->aliasMiddleware('rbac.permission', RequirePermission::class);
        $router->aliasMiddleware('rbac.permit', RequirePermissionAction::class);
        $router->aliasMiddleware('rbac.type', RequireRoleType::class);
    }

    /**
     * Answers "PERMISSION" and "PERMISSION.action" abilities with true when
     * granted; otherwise returns null so other gates and policies still run.
     */
    private function registerGate(): void
    {
        if (! config('rbac.register_gate', true)) {
            return;
        }

        $this->app->make(Gate::class)->before(function ($user, string $ability) {
            if (! in_array(HasRoles::class, class_uses_recursive($user), true)) {
                return null;
            }

            [$permission, $action] = array_pad(explode('.', $ability, 2), 2, null);

            if ($action === null) {
                return $user->hasPermission($permission) ? true : null;
            }

            $action = Action::tryParse($action);

            return $action !== null && $user->canPerform($permission, $action) ? true : null;
        });
    }
}
