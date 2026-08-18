<?php

namespace Moosylvania\RegistrationGuard\Admin;

use Moosylvania\RegistrationGuard\Model\SpamRegistrationLog;
use SilverStripe\Admin\ModelAdmin;
use SilverStripe\Security\PermissionProvider;

/**
 * CMS section listing everything RegistrationGuard has blocked.
 *
 * Filter by Source to tune one form's thresholds without disturbing the others.
 */
class SpamRegistrationAdmin extends ModelAdmin implements PermissionProvider
{
    private static $managed_models = [
        SpamRegistrationLog::class,
    ];

    private static $url_segment = 'spam-registrations';

    private static $menu_title = 'Blocked Registrations';

    private static $menu_icon_class = 'font-icon-block';

    private static $required_permission_codes = 'CMS_ACCESS_SpamRegistrationAdmin';

    public function providePermissions()
    {
        return [
            'CMS_ACCESS_SpamRegistrationAdmin' => [
                'name' => 'Access to Blocked Registrations',
                'category' => 'CMS Access',
                'help' => 'View and delete the log of submissions blocked by RegistrationGuard.',
            ],
        ];
    }
}
