# Tasks

Two build tasks, both operating on any class you point them at.

Each takes `--source` to resolve the class, field names and thresholds from the same config your form
uses, or `--class` to name a class directly. `--class` on its own falls back to the global defaults.

## Scoring existing records

`SpamScoreTask` runs the guard's heuristics against records already in your database, so junk that
predates the module can be found and dealt with.

```bash
# Silverstripe 6
sake tasks:registrationguard-score --source=members --from="-1 year" --min=80

# Silverstripe 5
/dev/tasks/RegistrationGuard-Score?source=members&from=-1+year&min=80
```

| Option | Default | Effect |
|---|---|---|
| `--source` | — | Source name to resolve class, fields and thresholds from |
| `--class` | — | DataObject class, overriding the source |
| `--from` | `-90 days` | Only records created on or after this |
| `--to` | `now` | Only records created on or before this |
| `--min` | the source's `block_threshold` | Minimum score to report |
| `--limit` | `500` | Maximum records to scan |
| `--delete` | off | Actually delete matching records that hold no content |

Each match prints its ID, score, email and reasons.

### It does not delete anything unless you say so

Without `--delete` the task reports and stops, and prints the IDs it would have removed so you can
review them. Nothing is written.

With `--delete` it removes matching records that pass the content gate below. The run announces the
mode in its header before doing anything, so a `--delete` run is obvious in the output and in your
scrollback.

Run it without the flag first. Always. Read the list, decide whether `--min` is right, and only then
run it again with the flag.

### The content gate

A record that has anything hanging off it is never deleted, whatever it scores — a member who has
posted, ordered or reviewed is a real person with an odd-looking name, not a bot. Tell the task what
counts as content:

```yaml
Moosylvania\RegistrationGuard\Task\SpamScoreTask:
  content_relations:
    SilverStripe\Security\Member:
      - Posts
      - Orders
      - Reviews
    App\Model\SweepsEntry:
      - Prizes
```

Relations are matched against subclasses too. A relation the class does not have is ignored rather than
fatal — but note that an empty or misspelled list means nothing is protected, so check the output for
`[has content, kept]` markers before trusting a delete run.

### What it does and does not check

The task applies the scored signals only — the machine-generated-text heuristics, suspicious dates of
birth and email aliasing. It does not apply the hard content blocks, and it cannot apply the dwell-time,
honeypot or rate-limit checks, because a stored record has no submission to judge.

So its scores are not directly comparable to the ones in the [log](log-and-admin.md), which include
everything. A record scoring 60 here might well have been blocked outright at signup.

## Backfilling canonical emails

`EmailCanonicalBackfillTask` fills `EmailCanonical` on records that predate
[`EmailCanonicalExtension`](email-canonical.md) being applied.

```bash
# Silverstripe 6
sake tasks:registrationguard-backfill-canonical --class="SilverStripe\Security\Member"

# Silverstripe 5
/dev/tasks/RegistrationGuard-BackfillCanonical?class=SilverStripe\Security\Member
```

| Option | Default | Effect |
|---|---|---|
| `--source` | — | Source name to resolve the class from |
| `--class` | — | DataObject class, overriding the source |
| `--limit` | `5000` | Maximum records per run |

It only touches records with an empty `EmailCanonical`, so it is safe to run repeatedly, and it tells
you when it has hit the limit and needs running again.

The column is written straight to the table rather than through `write()`. `EmailCanonical` is derived
data, and firing every `onBeforeWrite` in your application across the entire member table would be slow
and could have side effects that have nothing to do with this module.

Run it once after `dev/build`, before relying on the `duplicate-canonical-email` block.
