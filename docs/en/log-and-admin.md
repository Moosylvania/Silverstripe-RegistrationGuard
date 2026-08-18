# Log and admin

Every blocked submission is recorded, so thresholds can be tuned against your traffic instead of
guesswork. Nothing that passes is logged.

## The admin section

`SpamRegistrationAdmin` appears in the CMS as **Blocked Registrations**, listing everything the guard
has rejected, newest first. Records are searchable by email, nickname, IP, source and reasons.

They are read-only: you can view and delete, but not edit or create. A record of what somebody
submitted is not much use once it can be altered.

Access is controlled by the `CMS_ACCESS_SpamRegistrationAdmin` permission, which appears under **CMS
Access** in the security admin.

## What gets recorded

| Field | Notes |
|---|---|
| `Created` | When it was blocked |
| `Source` | The source name passed to `check()` — this is how you segment the log per form |
| `Score` | Scored total; see [scoring](registration-guard.md#scoring) |
| `Reasons` | One reason code per line, in the order the checks ran |
| `Email` | As submitted |
| `EmailCanonical` | The inbox it actually reaches, aliases collapsed |
| `Nickname`, `FirstName`, `Surname`, `Zip`, `Address` | As submitted |
| `Dob` | Stored as a string, not a date — the raw value may not parse at all |
| `IP`, `UserAgent` | Only when the guard was given an `HTTPRequest` |
| `SecondsOnForm` | Dwell time, or `-1` when the timestamp was missing or forged |

`EmailCanonical`, `IP` and `Source` are indexed. `Email`, `Nickname`, `Address`, `IP`, `Source` and
`Reasons` are searchable in the admin.

## Reason codes

| Reason | Meaning |
|---|---|
| `too-fast:3s` | Submitted 3 seconds after the page loaded, under `min_form_seconds` |
| `bad-timestamp` | The signed timestamp was missing, malformed or forged |
| `stale-form` | Older than `max_form_seconds` — the one block a real person hits |
| `honeypot` | The honeypot came back filled, or was not posted at all |
| `blocked-substring-in-name:.ru` | A name contained a `blocked_name_substrings` entry |
| `blocked-email-suffix:.ru` | The address ended with a `blocked_email_suffixes` entry |
| `blocked-domain:qq.com` | The address was at a `blocked_email_domains` domain |
| `blocked-pattern:/[А-Яа-яЁё]/u` | A name or the email matched a `blocked_name_patterns` regex |
| `blocked-address-pattern:/^123 Main St$/i` | The address matched a `blocked_address_patterns` regex |
| `too-many-spaces:surname` | That field had more spaces than `max_name_spaces` allows |
| `invalid-zip` | The zip failed `zip_regex` |
| `duplicate-canonical-email` | The inbox is already registered under a different-looking address |
| `suspicious-dob:1970-01-01` | A date of birth from `suspicious_dobs` — worth 60 points |
| `gibberish-surname:45` | The surname scored 45 on the machine-generated heuristic |
| `dot-aliased-email:4dots` | Dot-aliased address at a `dot_alias_domains` domain |
| `fragmented-email-local` | Local part is mostly single-character segments |
| `rate-limited` | Too many submissions from this IP for this source |

A record can carry several. Scored reasons appear whether or not they were what pushed the total over
the threshold — they document the score, not the decision.

## Tuning from the log

Work one source at a time. Filter the list by `Source`, then override that source rather than the
global default, so a change to the sweepstakes form cannot affect registration.

**Reading the log for false positives.** Sort by `Score` ascending and look at what sits just above
`block_threshold`. Records blocked at exactly 100 by two corroborating signals are where genuine people
end up. A `gibberish-surname` on a real-looking name, or an `invalid-zip` from a country whose postcodes
your `zip_regex` does not describe, means the config is wrong rather than the submitter.

**Reading it for false negatives** is harder, because what got through is not here. Compare the log
against records created in the same window — that is what [`SpamScoreTask`](tasks.md) is for.

**Before lowering `block_threshold`**, check whether an extra hard block would do the job instead. A
specific `blocked_email_domains` entry costs nothing; a lower threshold applies to everybody.

**Repeated addresses.** Sort or search by `Address` to find one a bot is reusing, then add a pattern
for it to that source's `blocked_address_patterns`. This is why the address is logged. Nothing counts
repeats automatically — see
[blocking an address](registration-guard.md#blocking-an-address).

## Logging never breaks a submission

The write is wrapped in a try/catch. If it fails — a missing table before `dev/build`, a full disk —
the error goes to the PSR logger and the request carries on. A spam log that can take a site's
registration form down with it is worse than no log.
