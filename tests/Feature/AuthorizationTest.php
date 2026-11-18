<?php

namespace FbisTech\Rbac\Tests\Feature;

use FbisTech\Rbac\Tests\Fixtures\User;
use FbisTech\Rbac\Tests\TestCase;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;

class AuthorizationTest extends TestCase
{
    private User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $role = $this->syncedRoles()->createRole('ADMIN', 'Support', [
            ['permission' => 'CLIENTS', 'canRead' => true],
        ]);
        $this->user = $this->makeUser()->setRole($role);

        Route::middleware('rbac.permission:CLIENTS|ANALYTICS')->get('/any', fn () => 'ok');
        Route::middleware('rbac.permission:ANALYTICS,ADMIN_MANAGEMENT')->get('/none', fn () => 'ok');
        Route::middleware('rbac.permit:CLIENTS,read')->get('/clients', fn () => 'ok');
        Route::middleware('rbac.permit:CLIENTS,EDIT')->put('/clients', fn () => 'ok');
        Route::middleware('rbac.permit:CLIENTS')->get('/clients-any', fn () => 'ok');
        Route::middleware('rbac.type:ADMIN')->get('/admin', fn () => 'ok');
        Route::middleware('rbac.type:CORPORATE')->get('/corporate', fn () => 'ok');
    }

    public function test_permission_middleware_passes_with_any_listed_permission(): void
    {
        $this->actingAs($this->user)->getJson('/any')->assertOk();
    }

    public function test_permission_middleware_rejects_with_json_message(): void
    {
        $this->actingAs($this->user)->getJson('/none')
            ->assertForbidden()
            ->assertExactJson(['success' => false, 'message' => 'You do not have the permission to carry out this action']);
    }

    public function test_action_middleware_checks_the_action_flag(): void
    {
        $this->actingAs($this->user)->getJson('/clients')->assertOk();
        $this->actingAs($this->user)->getJson('/clients-any')->assertOk();
        $this->actingAs($this->user)->putJson('/clients')
            ->assertForbidden()
            ->assertJson(['message' => 'You do not have the permission to edit Clients data']);
    }

    public function test_role_type_middleware(): void
    {
        $this->actingAs($this->user)->getJson('/admin')->assertOk();
        $this->actingAs($this->user)->getJson('/corporate')->assertForbidden();
    }

    public function test_guests_are_unauthenticated(): void
    {
        $this->getJson('/clients')->assertUnauthorized();
    }

    public function test_gate_resolves_permission_and_action_abilities(): void
    {
        $this->assertTrue($this->user->can('CLIENTS'));
        $this->assertTrue($this->user->can('CLIENTS.read'));
        $this->assertFalse($this->user->can('CLIENTS.edit'));
        $this->assertFalse($this->user->can('ANALYTICS'));
    }

    public function test_gate_defers_to_other_definitions_when_not_granted(): void
    {
        Gate::define('update-post', fn () => true);

        $this->assertTrue($this->user->can('update-post'));
    }
}
