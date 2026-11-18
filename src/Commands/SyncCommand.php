<?php

namespace FbisTech\Rbac\Commands;

use FbisTech\Rbac\RoleManager;
use Illuminate\Console\Command;

class SyncCommand extends Command
{
    protected $signature = 'rbac:sync
                            {--prune : Delete permissions of configured types that are no longer in config}';

    protected $description = 'Sync permissions and system roles from config/rbac.php';

    public function handle(RoleManager $roles): int
    {
        $stats = $roles->syncFromConfig((bool) $this->option('prune'));

        $this->components->info(sprintf(
            'Synced %d permissions and %d system roles%s.',
            $stats['permissions'],
            $stats['system_roles'],
            $this->option('prune') ? ", pruned {$stats['pruned']}" : ''
        ));

        return self::SUCCESS;
    }
}
