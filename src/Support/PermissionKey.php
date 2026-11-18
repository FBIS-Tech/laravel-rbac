<?php

namespace FbisTech\Rbac\Support;

final class PermissionKey
{
    /**
     * "Vtu Management", "vtu-management" and "VTU_MANAGEMENT" all become "VTU_MANAGEMENT".
     */
    public static function normalize(string $permission): string
    {
        return strtoupper((string) preg_replace('/[\s\-]+/', '_', trim($permission)));
    }

    /**
     * "VTU_MANAGEMENT" becomes "Vtu Management".
     */
    public static function label(string $permission): string
    {
        return ucwords(strtolower(str_replace('_', ' ', self::normalize($permission))));
    }
}
