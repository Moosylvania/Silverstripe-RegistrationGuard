<?php

namespace Moosylvania\RegistrationGuard\Model;

use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Permission;

/**
 * A submission RegistrationGuard blocked, kept so thresholds can be tuned against real traffic.
 *
 * Records are written by RegistrationGuard only and are read-only in the CMS - editing a record of
 * what was submitted would defeat the point of keeping it.
 */
class SpamRegistrationLog extends DataObject
{
    private static $table_name = 'Moosylvania_SpamRegistrationLog';

    private static $singular_name = 'Blocked Registration';

    private static $plural_name = 'Blocked Registrations';

    private static $default_sort = 'Created DESC';

    private static $db = [
        'Email' => 'Varchar(254)',
        'EmailCanonical' => 'Varchar(254)',
        'Nickname' => 'Varchar(255)',
        'FirstName' => 'Varchar(255)',
        'Surname' => 'Varchar(255)',
        // Varchar rather than Date: this is the raw submitted value and may not parse at all.
        'Dob' => 'Varchar(50)',
        'Zip' => 'Varchar(20)',
        'IP' => 'Varchar(45)',
        'UserAgent' => 'Text',
        'Score' => 'Int',
        'Reasons' => 'Text',
        'Source' => 'Varchar(100)',
        'SecondsOnForm' => 'Int',
    ];

    private static $indexes = [
        'EmailCanonical' => true,
        'IP' => true,
        'Source' => true,
    ];

    private static $summary_fields = [
        'Created' => 'When',
        'Source' => 'Form',
        'Score' => 'Score',
        'Email' => 'Email',
        'Nickname' => 'Nickname',
        'FirstName' => 'First',
        'Surname' => 'Last',
        'Dob' => 'Dob',
        'IP' => 'IP',
        'Reasons' => 'Reasons',
    ];

    private static $searchable_fields = [
        'Email',
        'Nickname',
        'IP',
        'Source',
        'Reasons',
    ];

    public function canView($member = null)
    {
        return Permission::checkMember($member, 'CMS_ACCESS_SpamRegistrationAdmin');
    }

    public function canDelete($member = null)
    {
        return Permission::checkMember($member, 'CMS_ACCESS_SpamRegistrationAdmin');
    }

    public function canEdit($member = null)
    {
        return false;
    }

    public function canCreate($member = null, $context = [])
    {
        return false;
    }
}
