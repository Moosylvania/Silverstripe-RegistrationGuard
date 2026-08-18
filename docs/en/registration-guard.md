# Registration guard and configuration

`RegistrationGuard` is the service that evaluates a submission. It returns a
[`RegistrationGuardResult`](#the-result) and never touches your form or your records itself.

- [Sources](#sources)
- [Integrating](#integrating)
- [The checks](#the-checks)
- [Scoring](#scoring)
- [The result](#the-result)
- [Config reference](#config-reference)
- [Upgrading from Silverstripe 5](#upgrading-from-silverstripe-5)

## Sources

A site usually has more than one form worth guarding, and they rarely want the same rules. A member
registration writes a `Member` and must reject a duplicate nickname; a sweepstakes entry writes a
`SweepsEntry`, collects an address, and is perfectly happy for the same person to enter twice.

So the guard has no single target. Config defines **named sources**, and every call names one:

```php
RegistrationGuard::create($request)->check($data, 'members');
RegistrationGuard::create($request)->check($data, 'sweeps');
```

```yaml
Moosylvania\RegistrationGuard\Service\RegistrationGuard:
  sources:
    members:
      target_class: SilverStripe\Security\Member
      field_map: {email: Email, nickname: Nickname, first_name: FirstName, surname: Surname, zip: Zip, dob: Dob}
      unique_fields: ['Email', 'Nickname']
      reserved_nicknames: ['admin', 'support']
      min_age: 21
      zip_regex: '/^\d{5}(-\d{4})?$/'

    sweeps:
      target_class: App\Model\SweepsEntry
      field_map: {email: Email, first_name: FirstName, surname: Surname, zip: Zip, dob: Dob}
      unique_fields: []          # one person may legitimately enter more than once
      min_age: 21
      min_form_seconds: 3        # shorter form, lower dwell floor
```

Resolution is one level deep and predictable: **a value set on the source wins, otherwise the module
default applies.** Nothing else. A source only states what it changes.

The same string is written to `SpamRegistrationLog.Source`, so the log arrives already segmented by
form — you can tune one form's thresholds from its own traffic without disturbing the others.

Two things worth knowing:

- **An unknown source name is not an error.** It resolves to the defaults and still gets logged under
  that name, so `check($data, 'whatever')` always works.
- **`field_map` replaces rather than merges.** A source lists every field it collects; omitting one
  disables every check that reads it. This is what lets a source drop a field the default map has.

### Guarding a form that writes nothing

`target_class` defaults to `null`, and with no target class every database-backed check becomes a
no-op. Timing, honeypot and the text heuristics still run. That is a working configuration — use it
for a contact form or anything else that has no record to check against.

## Integrating

### Manual

The primary mode. Add the guard's fields to your form:

```php
use Moosylvania\RegistrationGuard\Service\RegistrationGuard;

$fields->merge(RegistrationGuard::guardFields('members'));
```

and run the check in your action:

```php
public function doRegister($data, Form $form)
{
    $result = RegistrationGuard::create($this->getRequest())->check($data, 'members');

    if ($result->shouldStop()) {
        $result->applyTo($form);
        return $this->controller->redirectBack();
    }

    // ... create the record
}
```

`applyTo()` puts field errors against their fields and a form-level message at the top, or — for a
blocked submission — a single generic message and nothing else. It is safe to call for either outcome.

If you rebuild the form after a `redirectBack()`, make sure the guard fields are added *after* any
`loadDataFrom($_REQUEST)`. Otherwise the retry replays the spent timestamp from the previous POST
instead of the fresh one, and the dwell-time check measures the wrong window. The auto-wired mode below
does not have this problem.

### Auto-wired

Opt in with two extensions and a config map, and the guard runs with no changes to your form classes:

```yaml
SilverStripe\Forms\Form:
  extensions:
    - Moosylvania\RegistrationGuard\Extension\RegistrationGuardFormExtension

SilverStripe\Forms\FormRequestHandler:
  extensions:
    - Moosylvania\RegistrationGuard\Extension\RegistrationGuardHandlerExtension

Moosylvania\RegistrationGuard\Service\RegistrationGuard:
  guarded_forms:
    'App\Forms\RegistrationForm': {actions: [doRegister], source: members}
    'App\Forms\SweepsForm':       {actions: [doEnter],    source: sweeps}
```

Both extensions are inert until a form appears in `guarded_forms`, and both match subclasses.

- The form extension injects the guard fields at render time, so the timestamp is refreshed on every
  draw and a honeypot value carried back by a repopulate is cleared.
- The handler extension runs the check before your action and throws a `ValidationException` if the
  submission should stop. Silverstripe catches it, attaches the messages and bounces the user back.

Field-level errors reach the form; a block produces one generic message. Your action never runs.

## The checks

In the order `check()` applies them.

### 1. Duplicate values — *field error*

Every column in `unique_fields` is compared case-insensitively against existing `target_class` records.
Skipped entirely when the submitted value is empty, or when there is no target class.

Messages come from i18n so you can write your own, including HTML:

```yaml
en:
  Moosylvania\RegistrationGuard\Service\RegistrationGuard:
    DUPLICATE: 'Sorry this {field} is already in use.'
    DUPLICATE_Email: 'That email is already registered. <a href="/Security/lostpassword">Forgot your password?</a>'
```

A message containing markup is cast as HTML automatically — there is no flag to set.

### 2. Reserved nicknames — *field error*

The nickname field must not be one of `reserved_nicknames` (compared case-insensitively). Skipped when
the source has no `nickname` in its `field_map`.

### 3. Age gate — *field error*

With `min_age` above zero, the date in the `dob` field must be at least that many years ago. `min_age`
defaults to `0`, which disables the check.

### 4. Dwell time — *block*

A hidden field carries the page-load time, HMAC-signed so a bot cannot simply post an older timestamp
to walk past the check. Submissions faster than `min_form_seconds` are blocked; a token older than
`max_form_seconds` gets the "your form expired, please reload" message instead of the generic one,
because that one really can happen to a real person who left a tab open.

The signing key comes from the `SS_REGISTRATION_SECRET` environment variable, falling back to
`SS_DATABASE_PASSWORD`. Setting a dedicated secret is worth doing; the fallback only exists so the
module works before anyone has read this paragraph.

### 5. Honeypot — *block*

The module ships its own honeypot field rather than depending on a honeypot module, and it does not
read `Captcha` — that name is used by real captcha plugins and would collide.

The field must come back **present and empty**. Both halves matter: a bot posting a hand-built field
list never sends it at all, which is caught by the presence half.

It is hidden with an inline style, so the module ships no CSS or JS for your build pipeline to handle,
and it carries `autocomplete="off"`, `tabindex="-1"` and `aria-hidden="true"`.

Two ways a honeypot silently blocks real people, both of which this design avoids — and both of which
you can reintroduce, so be careful if you customise it:

- **Browser autofill.** A field named `Website` or `Address` gets filled by password managers, and the
  user is blocked with no idea why. The default name `RgWebsite` is not an autofill token. If you hit a
  manager that fills it anyway, change `honeypot_field`.
- **Frontend validators.** The field must never carry a `required` class or attribute. Most JS
  validation walks `.required` and would then demand the honeypot be filled, blocking *every*
  submission. This applies to the timestamp field too.

Set `honeypot_field: null` to disable.

### 6. Hard content blocks — *block*

Unconditional, and all configurable:

| Config | Blocks when |
|---|---|
| `blocked_name_substrings` | any name field contains the substring (default: `http://`, `https://`, `.ru`) |
| `blocked_email_suffixes` | the address ends with the suffix (default: `.ru`) |
| `blocked_email_domains` | the address is at one of these domains (default: none) |
| `blocked_name_patterns` | any name or the email matches the regex (default: Cyrillic, Han) |
| `blocked_address_patterns` | the address matches the regex (default: none) |
| `max_name_spaces` | a name has more spaces than allowed (default: 1 in `first_name`, 2 in `surname`) |
| `zip_regex` | the zip does not match (default: `null`, disabled) |

`blocked_name_patterns` takes plain regexes rather than script names, so you can add your own without
the module owning a mapping table. Both defaults are aggressive — if you have real users writing their
names in Cyrillic or Han, override the list.

#### Blocking an address

`blocked_address_patterns` is the address equivalent, kept as its own option rather than folded into
`blocked_name_patterns` because a street address legitimately contains digits, punctuation and
abbreviations that would look like spam in a surname.

It takes any number of regexes, and the address is blocked if it matches **any** of them:

```yaml
Moosylvania\RegistrationGuard\Service\RegistrationGuard:
  sources:
    sweeps:
      field_map: {email: Email, first_name: FirstName, surname: Surname, address: Address}
      blocked_address_patterns:
        - '/^123 Nowhere Ln$/i'          # one address a bot keeps reusing
        - '/\bP\.?O\.? Box\b/i'        # no PO boxes for a physical prize
        - '/^\d+ Test\b/i'
```

The check needs `address` in the source's `field_map`; without it there is nothing to read and the
check is skipped. An empty address never matches, so a pattern like `/^$/` cannot accidentally block
every submission that leaves the field blank.

The intended workflow is reactive rather than predictive: when the [log](log-and-admin.md) shows the
same address arriving over and over, add a pattern for it. The module does not count repeat addresses
for you — if you want an address to be usable exactly once, put it in `unique_fields` instead, which
produces a field error rather than a silent block.

Addresses are never fed to the [scoring heuristics](#scoring). Street addresses are full of digits and
abbreviations, and scoring them would reject real people.

#### Spaces in names

`max_name_spaces` maps a `field_map` name to the most spaces it may contain. The defaults catch `a b c
d` while leaving `Mary Jane` and `van der Berg` alone. A field not listed is unlimited:

```yaml
max_name_spaces:
  first_name: 1
  surname: 2
  nickname: 0      # no spaces at all in a handle
```

### 7. Duplicate canonical email — *block*

The address is collapsed to the inbox it actually reaches — `j.o.e+promo@gmail.com` becomes
`joe@gmail.com` — and checked against the `canonical_field` column on the target class.

**This check does nothing until [`EmailCanonicalExtension`](email-canonical.md) is applied to the
target class.** The guard skips it silently when the column is absent, so an unconfigured install
behaves as if the check does not exist rather than erroring.

### 8. Scored signals — *block above the threshold*

See [Scoring](#scoring). Blocks at or above `block_threshold`.

### 9. Rate limit — *block*

Keyed on source, host and IP, allowing `rate_limit_hits` per `rate_limit_decay` seconds. Only evaluated
for submissions that have passed everything else, so a genuine user's one good attempt is what consumes
their allowance, not a bot's thousand bad ones. Requires an `HTTPRequest` — construct the guard with
one, or the rate limit is skipped.

## Scoring

`scoreProfile()` judges how machine-generated the submitted text looks. It is deliberately free of the
timer, honeypot and rate limit, so the same method can score a stored record — which is exactly what
[`SpamScoreTask`](tasks.md) does. It applies none of the hard content blocks.

| Signal | Points |
|---|---|
| Date of birth is one of `suspicious_dobs` | 60 |
| No vowels at all in a name of 4+ letters (`Rtwwg`) | 45 |
| A run of 5+ consonants (`Mnwhgskdl`) | 45 |
| Random-looking capitalisation (`cgwEIPbzXEAIBsIj`) | 40 |
| Vowel-starved after collapsing real digraphs | 25 |
| 14+ characters with no digits | 20 |
| Digits in a first name or surname | 25 |
| Dot-aliased address at a `dot_alias_domains` domain | 50 |
| Fragmented local part — 4+ segments, 60%+ single characters | 30 |

Per-name scores are capped at 50, and names are judged on their longest token, so `Anne-Marie` is
scored on `Marie` rather than the concatenation. Names shorter than four characters are never judged at
all — `Li`, `Ng`, `Bo` and `Tran` are real.

**The numbers are tuned so that no single signal a real person could trip reaches
`block_threshold` on its own.** Unusual but genuine surnames like `Krzysztof` and `Wojciechowski` land
at 25 and need corroborating evidence before anything is rejected; the vowel ratio is measured after
collapsing the consonant clusters real German, Slavic and Welsh names are built from, so `Schwartz` and
`Schmidt` are not punished for existing.

Raising a number or lowering `block_threshold` starts rejecting real signups, silently, and you will
find out from a support ticket rather than a test. Tune from the [log](log-and-admin.md), not by
intuition, and run the test suite afterwards — it asserts a list of real names stays under the
threshold precisely because this is the expensive way to get it wrong.

## The result

```php
$result->shouldStop();        // blocked, or has field errors
$result->isBlocked();         // spam
$result->getFieldErrors();    // [field => ['message', 'formMessage', 'html']]
$result->getScore();
$result->getReasons();        // for the log, never for the browser
$result->getBlockMessage();
$result->getSecondsOnForm();
$result->applyTo($form);      // surface it, ready for a redirectBack()
$result->toValidationResult();
```

Field errors and blocks are different things. A field error is a mistake the user can fix and is shown
against the field. A block is spam: the user gets one generic message, and the reasons go to the log.
`applyTo()` and `toValidationResult()` both enforce that separation — a blocked submission cannot leak
which rule fired, however you surface it.

Override the two generic strings through i18n:

```yaml
en:
  Moosylvania\RegistrationGuard\Service\RegistrationGuard:
    GENERIC_ERROR: 'There was an error submitting your registration, please make sure all information is correct.'
    STALE_ERROR: 'Your registration form expired, please reload the page and try again.'
    UNDER_AGE: 'Sorry you must be {age} years of age to register.'
    RESERVED_NICKNAME: 'Sorry this Nickname is not available.'
```

## Config reference

Every option can be set globally or overridden per source.

| Option | Default | Effect |
|---|---|---|
| `target_class` | `null` | DataObject to check against. `null` disables all database checks. |
| `field_map` | see below | Logical name to form field name. Replaces rather than merges per source. |
| `unique_fields` | `[]` | Columns that must not already hold the submitted value. |
| `canonical_field` | `EmailCanonical` | Canonical email column. `null`, or absent from the class, skips the check. |
| `min_form_seconds` | `5` | Dwell-time floor. |
| `max_form_seconds` | `7200` | Beyond this the form is stale and the user is asked to reload. |
| `timestamp_field` | `Rts` | Name of the signed timestamp field. `null` disables timing. |
| `honeypot_field` | `RgWebsite` | Name of the honeypot field. `null` disables the honeypot. |
| `block_threshold` | `100` | Scored total that blocks. |
| `suspicious_dobs` | 1970-01-01, 1900-01-01, 0000-00-00 | Dates worth 60 points. |
| `dot_alias_domains` | gmail.com, googlemail.com | Domains that ignore dots in the local part. |
| `reserved_nicknames` | `[]` | Nicknames nobody may take. |
| `blocked_email_domains` | `[]` | Hard block by domain. |
| `blocked_email_suffixes` | `['.ru']` | Hard block by address ending. |
| `blocked_name_substrings` | `http://`, `https://`, `.ru` | Hard block by substring in any name. |
| `blocked_name_patterns` | Cyrillic, Han | Hard block by regex over names and email. |
| `blocked_address_patterns` | `[]` | Hard block by regex over the address. Any match blocks. |
| `max_name_spaces` | `{first_name: 1, surname: 2}` | Most spaces each name field may contain. Unlisted fields are unlimited. |
| `min_age` | `0` | Minimum age in years. `0` disables. |
| `zip_regex` | `null` | Pattern the zip must match. `null` disables. |
| `rate_limit_hits` | `1` | Allowed submissions per window. |
| `rate_limit_decay` | `60` | Window length in seconds. |
| `sources` | `{}` | Per-source overrides. Not itself overridable. |
| `guarded_forms` | `{}` | Auto-wiring map. Not itself overridable. |

`field_map` keys are `email`, `nickname`, `first_name`, `surname`, `zip`, `dob` and `address`. The
default maps `email`, `first_name` and `surname` only; the rest are `null`.

## Upgrading from Silverstripe 5

Use `^1` of this module on Silverstripe 5 and `^2` on Silverstripe 6. The config and the public API are
identical between them, so upgrading the module is a constraint bump — nothing in your YAML or your
form code changes.

One Silverstripe 6 rename to watch for in your own registration forms, unrelated to this module:
`SilverStripe\Forms\RequiredFields` is now `SilverStripe\Forms\Validation\RequiredFieldsValidator`, and
`SilverStripe\ORM\ValidationResult` is now `SilverStripe\Core\Validation\ValidationResult`.
