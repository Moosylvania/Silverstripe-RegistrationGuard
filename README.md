# Silverstripe Registration Guard

[![CI](https://github.com/Moosylvania/Silverstripe-RegistrationGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Moosylvania/Silverstripe-RegistrationGuard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Packagist Version](https://img.shields.io/packagist/v/moosylvania/silverstripe-registrationguard?link=https%3A%2F%2Fpackagist.org%2Fpackages%2Fmoosylvania%2Fsilverstripe-registrationguard)(https://packagist.org/packages/moosylvania/silverstripe-registrationguard)

Anti-spam for Silverstripe forms that create records — registrations, sweepstakes entries, anything a
bot would like to submit ten thousand times.

The guard runs a signed dwell-time check, its own honeypot field, a per-IP rate limit, configurable
hard blocks, and a scored "this text looks machine generated" heuristic. Everything it blocks is
written to a log with the reasons, so you can tune the thresholds against your own traffic rather than
guessing. Users get one generic error and are told nothing about which rule fired.

One install serves many forms: each form names a **source**, and a source supplies the target class,
the field names and any threshold overrides.

## Requirements

| Module | Silverstripe | PHP |
|---|---|---|
| `^2` (branch `main`) | 6 | 8.3+ |
| `^1` (branch `1`) | 5 | 8.1+ |

```bash
composer require moosylvania/silverstripe-registrationguard
```

Then run `dev/build?flush=1`.

## Quick start

Define a source for the form you want to protect:

```yaml
# app/_config/registrationguard.yml
Moosylvania\RegistrationGuard\Service\RegistrationGuard:
  sources:
    members:
      target_class: SilverStripe\Security\Member
      field_map: {email: Email, first_name: FirstName, surname: Surname, dob: Dob}
      unique_fields: ['Email']
      min_age: 21
```

Add the guard fields to the form, and run the check in the action:

```php
use Moosylvania\RegistrationGuard\Service\RegistrationGuard;

// in your Form's constructor, after the rest of your fields
$fields->merge(RegistrationGuard::guardFields('members'));

// in your action handler
public function doRegister($data, Form $form)
{
    $result = RegistrationGuard::create($this->getRequest())->check($data, 'members');

    if ($result->shouldStop()) {
        $result->applyTo($form);
        return $this->controller->redirectBack();
    }

    // ... create the member
}
```

That is the whole integration. There is also an opt-in mode that wires itself in via YAML with no PHP
changes at all — see the docs below.

To make the gmail-alias duplicate check work, apply the canonical email extension to your target class:

```yaml
SilverStripe\Security\Member:
  extensions:
    - Moosylvania\RegistrationGuard\Extension\EmailCanonicalExtension
```

## Documentation

- [Registration guard and configuration](docs/en/registration-guard.md) — sources, every check, the
  scoring model, and the full config reference
- [Log and admin](docs/en/log-and-admin.md) — what gets recorded, what each reason code means, and how
  to tune thresholds from real traffic
- [Email canonical extension](docs/en/email-canonical.md) — collapsing gmail dot and plus aliases
- [Tasks](docs/en/tasks.md) — scoring records that predate the guard, and backfilling canonical emails

## License

MIT. See [LICENSE](LICENSE).
