<?php

namespace FbisTech\Rbac\Http\Middleware;

use Closure;
use FbisTech\Rbac\Exceptions\UnauthorizedException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Passes when the user holds a role of any of the listed types.
 * Usage: ->middleware('rbac.type:ADMIN')
 */
class RequireRoleType
{
    use ResolvesRbacUser;

    public function handle(Request $request, Closure $next, string ...$types): Response
    {
        if (! $this->rbacUser($request)->hasRoleType(...$this->splitParameters($types))) {
            throw UnauthorizedException::missingPermission();
        }

        return $next($request);
    }
}
