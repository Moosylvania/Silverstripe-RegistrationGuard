<?php

namespace Moosylvania\RegistrationGuard\Extension;

use Moosylvania\RegistrationGuard\Service\RegistrationGuard;
use SilverStripe\Core\Extension;
use SilverStripe\Forms\Form;

/**
 * Injects the guard's timestamp and honeypot fields into any form listed in
 * RegistrationGuard.guarded_forms.
 *
 * Applied to Form itself; the guarded_forms config decides which forms it actually touches.
 *
 *     SilverStripe\Forms\Form:
 *       extensions:
 *         - Moosylvania\RegistrationGuard\Extension\RegistrationGuardFormExtension
 *
 * Hooking render rather than construction means the timestamp is refreshed every time the form is
 * drawn. That sidesteps the ordering trap of setting it in the constructor, where a loadDataFrom()
 * after the fact replays a spent token, and it clears any honeypot value a redirectBack() repopulate
 * would otherwise carry forward.
 */
class RegistrationGuardFormExtension extends Extension
{
    public function onBeforeRender($context)
    {
        $form = $context instanceof Form ? $context : $this->getOwner();
        $source = RegistrationGuardHandlerExtension::sourceForForm($form);

        if ($source === false) {
            return;
        }

        $fields = $form->Fields();

        foreach (RegistrationGuard::guardFields($source) as $field) {
            if ($existing = $fields->dataFieldByName($field->getName())) {
                // Already present from a previous render or hand-added: refresh, don't duplicate.
                $existing->setValue($field->dataValue());
                continue;
            }
            $fields->push($field);
        }
    }
}
