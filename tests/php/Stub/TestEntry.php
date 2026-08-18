<?php

namespace Moosylvania\RegistrationGuard\Tests\Stub;

use SilverStripe\Dev\TestOnly;
use SilverStripe\ORM\DataObject;

class TestEntry extends DataObject implements TestOnly
{
    private static $table_name = 'Moosylvania_TestEntry';

    private static $db = [
        'Email' => 'Varchar(254)',
        'FirstName' => 'Varchar(255)',
        'Surname' => 'Varchar(255)',
    ];
}
