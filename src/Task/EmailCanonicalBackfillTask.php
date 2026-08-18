<?php

namespace Moosylvania\RegistrationGuard\Task;

use Moosylvania\RegistrationGuard\Service\RegistrationGuard;
use SilverStripe\Control\Director;
use SilverStripe\Dev\BuildTask;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\DB;

/**
 * Populate EmailCanonical on records that predate EmailCanonicalExtension being applied.
 *
 * Run once after dev/build. Until it has run, the guard's duplicate-canonical-email block only sees
 * records written since the extension went on.
 */
class EmailCanonicalBackfillTask extends BuildTask
{
    private static $segment = 'RegistrationGuard-BackfillCanonical';

    protected $title = 'RegistrationGuard: backfill EmailCanonical';

    protected $description = 'Writes EmailCanonical for existing records that do not have one yet. '
        . 'Params: source, class, limit.';

    public function run($request)
    {
        $source = $request->getVar('source');
        $class = $request->getVar('class') ?: RegistrationGuard::option('target_class', $source);

        if (!$class || !is_a($class, DataObject::class, true)) {
            $this->line('No DataObject class to backfill. Pass class, or source naming a source with a target_class.');
            return;
        }

        if (!DataObject::getSchema()->fieldSpec($class, 'EmailCanonical')) {
            $this->line("{$class} has no EmailCanonical column. Apply EmailCanonicalExtension and run dev/build first.");
            return;
        }

        $emailField = DataObject::singleton($class)->config()->get('email_field') ?: 'Email';
        $table = DataObject::getSchema()->tableForField($class, 'EmailCanonical');
        $limit = (int) ($request->getVar('limit') ?: 5000);

        $records = DataList::create($class)
            ->filterAny(['EmailCanonical' => [null, '']])
            ->limit($limit);

        $written = 0;
        $total = $records->count();

        foreach ($records as $record) {
            $canonical = RegistrationGuard::canonicalEmail($record->getField($emailField), $source);
            if (!$canonical) {
                continue;
            }
            // Straight to the table: this is a derived column, and a full write() would fire
            // onBeforeWrite across the whole application for every historical record.
            DB::prepared_query(
                sprintf('UPDATE "%s" SET "EmailCanonical" = ? WHERE "ID" = ?', $table),
                [$canonical, $record->ID]
            );
            $written++;
        }

        $this->line("Backfilled {$written} of {$total} record(s) on {$class}.");

        if ($total >= $limit) {
            $this->line('Hit the limit - run again to continue.');
        }
    }

    protected function line($message)
    {
        echo $message . (Director::is_cli() ? PHP_EOL : '<br>' . PHP_EOL);
    }
}
