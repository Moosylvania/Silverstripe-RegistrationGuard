<?php

namespace Moosylvania\RegistrationGuard\Extension;

use Moosylvania\RegistrationGuard\Service\RegistrationGuard;
use SilverStripe\Core\Extension;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Forms\Form;

/**
 * Runs the guard on submission for any form listed in RegistrationGuard.guarded_forms, so a project
 * can protect a form without touching its action handler.
 *
 *     SilverStripe\Forms\FormRequestHandler:
 *       extensions:
 *         - Moosylvania\RegistrationGuard\Extension\RegistrationGuardHandlerExtension
 *
 *     Moosylvania\RegistrationGuard\Service\RegistrationGuard:
 *       guarded_forms:
 *         'App\Forms\RegistrationForm': {actions: [doRegister], source: members}
 *         'App\Forms\SweepsForm':       {actions: [doEnter],    source: sweeps}
 *
 * beforeCallFormHandler ignores its return value, so blocking means throwing. FormRequestHandler
 * wraps the call in a catch for ValidationException, which is the supported way to stop an action and
 * bounce the user back with messages intact.
 */
class RegistrationGuardHandlerExtension extends Extension
{
    public function beforeCallFormHandler($request, $funcName, $vars, $form, $subject)
    {
        $config = static::configForForm($form);

        if (!$config || !in_array($funcName, (array) ($config['actions'] ?? []), true)) {
            return;
        }

        $result = RegistrationGuard::create($request, $config['source'] ?? null)->check((array) $vars);

        if (!$result->shouldStop()) {
            return;
        }

        throw new ValidationException($result->toValidationResult());
    }

    /**
     * The guarded_forms entry covering a form, matching subclasses too.
     *
     * @return array|null
     */
    public static function configForForm(Form $form)
    {
        $guarded = (array) RegistrationGuard::config()->get('guarded_forms');

        foreach ($guarded as $class => $config) {
            if ($form instanceof $class) {
                return (array) $config;
            }
        }

        return null;
    }

    /**
     * @return string|null|false Source name, null when guarded without one, false when not guarded.
     */
    public static function sourceForForm(Form $form)
    {
        $config = static::configForForm($form);

        return $config === null ? false : ($config['source'] ?? null);
    }
}
