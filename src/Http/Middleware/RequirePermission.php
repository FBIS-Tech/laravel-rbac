<?php

namespace FbisTech\Rbac\Http\Middleware;

use Closure;
use FbisTech\Rbac\Exceptions\UnauthorizedException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Passes when the user holds any of the listed permissions.
 * Usage: ->middleware('rbac.permission:CLIENTS|ACCOUNTS')
 */
class RequirePermission
{
    use ResolvesRbacUser;

    public function handle(Request $request, Closure $next, string ...$permissions): Response
    {
        if (! $this->rbacUser($request)->hasAnyPermission(...$this->splitParameters($permissions))) {
            throw UnauthorizedException::missingPermission();
        }

        return $next($request);
    }
}
