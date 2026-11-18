<?php

namespace FbisTech\Rbac\Exceptions;

use RuntimeException;

class RbacException extends RuntimeException
{
    public static function roleNotFound(int|string $role): self
    {
        return new self("Role [{$role}] does not exist.");
    }

    public static function ambiguousRole(string $name): self
    {
        return new self("More than one role is named [{$name}]. Pass the Role model or its id instead.");
    }

    public static function roleExists(string $name): self
    {
        return new self("A role named [{$name}] already exists.");
    }

    public static function roleInUse(string $name): self
    {
        return new self("Role [{$name}] is assigned to users. Reassign them before deleting it.");
    }

    public static function systemRole(string $name): self
    {
        return new self("Role [{$name}] is a system role and cannot be changed.");
    }

    public static function permissionNotFound(string $type, int|string $permission): self
    {
        return new self("Permission [{$permission}] does not exist for role type [{$type}].");
    }
}
