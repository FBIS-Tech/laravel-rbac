<?php

namespace FbisTech\Rbac\Http\Middleware;

use FbisTech\Rbac\Concerns\HasRoles;
use FbisTech\Rbac\Exceptions\UnauthorizedException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

trait ResolvesRbacUser
{
    /**
     * @throws AuthenticationException when no one is signed in
     * @throws UnauthorizedException when the user model does not use HasRoles
     */
    private function rbacUser(Request $request): Model
    {
        $user = $request->user();

        if ($user === null) {
            throw new AuthenticationException;
        }

        if (! $user instanceof Model || ! in_array(HasRoles::class, class_uses_recursive($user), true)) {
            throw UnauthorizedException::missingPermission();
        }

        return $user;
    }

    /**
     * Middleware parameters arrive comma-split; also allow "A|B" inside one.
     *
     * @param  array<int, string>  $values
     * @return array<int, string>
     */
    private function splitParameters(array $values): array
    {
        return array_values(array_filter(array_map('trim', explode('|', implode('|', $values)))));
    }
}
