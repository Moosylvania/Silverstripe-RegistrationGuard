<?php

namespace Moosylvania\RegistrationGuard\Tests\Stub;

use SilverStripe\Control\Controller;
use SilverStripe\Dev\TestOnly;

/**
 * Rendering a form asks its controller for a link, and the bare Controller::curr() in a test has no
 * url_segment to build one from.
 */
class TestController extends Controller implements TestOnly
{
    // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps -- overriding a framework method
    public function Link($action = null)
    {
        return Controller::join_links('registrationguard-test', $action);
    }
}
