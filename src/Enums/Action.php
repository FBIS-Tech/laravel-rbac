<?php

namespace FbisTech\Rbac\Enums;

use ValueError;

enum Action: string
{
    case Read = 'read';
    case Add = 'add';
    case Edit = 'edit';
    case Delete = 'delete';

    /**
     * Case-insensitive lookup, accepting an Action or its string value.
     *
     * @throws ValueError
     */
    public static function parse(self|string $action): self
    {
        return $action instanceof self ? $action : self::from(strtolower(trim($action)));
    }

    public static function tryParse(self|string $action): ?self
    {
        return $action instanceof self ? $action : self::tryFrom(strtolower(trim($action)));
    }

    /**
     * Pivot column holding this action's flag, e.g. "can_edit".
     */
    public function column(): string
    {
        return 'can_'.$this->value;
    }

    /**
     * Grant array key holding this action's flag, e.g. "canEdit".
     */
    public function grantKey(): string
    {
        return 'can'.ucfirst($this->value);
    }

    /**
     * Human verb used in error messages ("view" instead of "read").
     */
    public function verb(): string
    {
        return $this === self::Read ? 'view' : $this->value;
    }
}
