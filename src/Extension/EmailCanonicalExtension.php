<?php

namespace Moosylvania\RegistrationGuard\Extension;

use Moosylvania\RegistrationGuard\Service\RegistrationGuard;
use SilverStripe\Core\Extension;

/**
 * Stores the canonical form of a record's email address alongside the address itself.
 *
 * Canonicalising collapses the gmail dot and plus tricks, so one inbox stops yielding unlimited
 * unique-looking addresses. Apply to Member, a sweeps entry, or any other DataObject holding an email:
 *
 *     SilverStripe\Security\Member:
 *       extensions:
 *         - Moosylvania\RegistrationGuard\Extension\EmailCanonicalExtension
 *
 * RegistrationGuard's duplicate-canonical-email block does nothing until this is applied to the
 * source's target_class - the guard skips the check silently when the column is absent.
 */
class EmailCanonicalExtension extends Extension
{
    /**
     * Column holding the address to canonicalise.
     */
    private static $email_field = 'Email';

    private static $db = [
        'EmailCanonical' => 'Varchar(254)',
    ];

    private static $indexes = [
        'EmailCanonical' => true,
    ];

    public function onBeforeWrite()
    {
        $owner = $this->getOwner();
        $field = $owner->config()->get('email_field') ?: 'Email';

        $owner->EmailCanonical = RegistrationGuard::canonicalEmail($owner->getField($field));
    }
}
