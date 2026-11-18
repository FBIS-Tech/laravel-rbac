<?php

namespace FbisTech\Rbac\Exceptions;

use FbisTech\Rbac\Enums\Action;
use FbisTech\Rbac\Support\PermissionKey;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\HttpException;

class UnauthorizedException extends HttpException
{
    public const DEFAULT_MESSAGE = 'You do not have the permission to carry out this action';

    public function __construct(string $message = self::DEFAULT_MESSAGE)
    {
        parent::__construct(403, $message);
    }

    public static function missingPermission(): self
    {
        return new self;
    }

    public static function missingAction(string $permission, Action $action): self
    {
        return new self("You do not have the permission to {$action->verb()} ".PermissionKey::label($permission).' data');
    }

    /**
     * JSON clients get {"success": false, "message": "..."}; others fall back
     * to the application's default 403 handling.
     */
    public function render(Request $request): ?JsonResponse
    {
        if (! $request->expectsJson()) {
            return null;
        }

        return new JsonResponse(['success' => false, 'message' => $this->getMessage()], 403);
    }
}
