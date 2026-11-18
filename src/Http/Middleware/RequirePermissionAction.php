<?php

namespace FbisTech\Rbac\Http\Middleware;

use Closure;
use FbisTech\Rbac\Enums\Action;
use FbisTech\Rbac\Exceptions\UnauthorizedException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Passes when the user holds the permission and, if given, the action on it.
 * Usage: ->middleware('rbac.permit:ADMIN_MANAGEMENT,edit')
 */
class RequirePermissionAction
{
    use ResolvesRbacUser;

    public function handle(Request $request, Closure $next, string $permission, ?string $action = null): Response
    {
        $user = $this->rbacUser($request);

        if (! $user->hasPermission($permission)) {
            throw UnauthorizedException::missingPermission();
        }

        if ($action !== null) {
            $action = Action::parse($action);

            if (! $user->canPerform($permission, $action)) {
                throw UnauthorizedException::missingAction($permission, $action);
            }
        }

        return $next($request);
    }
}
