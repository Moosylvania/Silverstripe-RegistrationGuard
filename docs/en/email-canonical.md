# Email canonical extension

`joe@gmail.com`, `j.o.e@gmail.com` and `joe+signup@gmail.com` are three different-looking addresses
that all arrive in one inbox. Gmail ignores dots in the local part, and everybody ignores everything
after a `+`. One address becomes an unlimited supply of unique-looking ones, which is exactly what a
bot needs to register repeatedly.

`EmailCanonicalExtension` stores the address each record actually reaches, so you can check against
that instead:

```
d.i.amondflo.o.r.i.ngl.lc.a.l@gmail.com  ->  diamondflooringllcal@gmail.com
Some.One+promo@GMail.com                 ->  someone@gmail.com
some.one+tag@example.com                 ->  some.one@example.com
```

Note the last one. Plus-addressing is collapsed everywhere, because it always reaches the same inbox.
Dots are only stripped at the domains in `dot_alias_domains`, because everywhere else `some.one@` and
`someone@` are genuinely different people.

## Applying it

To `Member`, or to any other `DataObject` holding an email address:

```yaml
SilverStripe\Security\Member:
  extensions:
    - Moosylvania\RegistrationGuard\Extension\EmailCanonicalExtension

App\Model\SweepsEntry:
  extensions:
    - Moosylvania\RegistrationGuard\Extension\EmailCanonicalExtension
```

Then `dev/build?flush=1`. The extension adds an indexed `EmailCanonical` column and fills it in
`onBeforeWrite`, so it stays correct without anything else calling it.

If the address lives in a column that is not called `Email`:

```yaml
App\Model\SweepsEntry:
  email_field: 'ContactEmail'
```

## It is required for the duplicate check

**RegistrationGuard's `duplicate-canonical-email` block does nothing until this extension is applied to
the source's `target_class`.** The guard looks for the column, does not find it, and skips the check
silently — an unconfigured install behaves as though the check does not exist rather than erroring, but
it also catches nothing.

If you are relying on that block, confirm the column exists after `dev/build`.

## Existing records

New and updated records get a canonical address automatically. Everything already in the table has an
empty column until you backfill it:

```bash
# Silverstripe 6
sake tasks:registrationguard-backfill-canonical --class="SilverStripe\Security\Member"

# Silverstripe 5
/dev/tasks/RegistrationGuard-BackfillCanonical?class=SilverStripe\Security\Member
```

See [tasks](tasks.md). Until it has run, the duplicate check only sees records written since the
extension went on — which means a bot that registered before you installed the module can register
again.

The right order for an existing site is: apply the extension, `dev/build`, backfill, *then* rely on the
check.
