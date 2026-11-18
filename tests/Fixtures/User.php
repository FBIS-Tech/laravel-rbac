<?php

namespace FbisTech\Rbac\Tests\Fixtures;

use FbisTech\Rbac\Concerns\HasRoles;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    use HasRoles;

    protected $guarded = ['id'];

    protected $table = 'users';
}
