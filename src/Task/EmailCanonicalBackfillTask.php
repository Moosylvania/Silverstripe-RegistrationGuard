<?php

namespace Moosylvania\RegistrationGuard\Task;

use Moosylvania\RegistrationGuard\Service\RegistrationGuard;
use SilverStripe\Dev\BuildTask;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\DB;
use SilverStripe\PolyExecution\PolyOutput;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * Populate EmailCanonical on records that predate EmailCanonicalExtension being applied.
 *
 * Run once after dev/build. Until it has run, the guard's duplicate-canonical-email block only sees
 * records written since the extension went on.
 */
class EmailCanonicalBackfillTask extends BuildTask
{
    protected string $title = 'RegistrationGuard: backfill EmailCanonical';

    protected static string $description = 'Writes EmailCanonical for existing records that do not have one yet.';

    protected static string $commandName = 'registrationguard-backfill-canonical';

    public function getOptions(): array
    {
        return [
            new InputOption('source', null, InputOption::VALUE_REQUIRED, 'RegistrationGuard source name to resolve the class from'),
            new InputOption('class', null, InputOption::VALUE_REQUIRED, 'DataObject class to backfill, overriding the source'),
            new InputOption('limit', null, InputOption::VALUE_REQUIRED, 'Maximum records to process in this run', 5000),
        ];
    }

    protected function execute(InputInterface $input, PolyOutput $output): int
    {
        $source = $input->getOption('source');
        $class = $input->getOption('class') ?: RegistrationGuard::option('target_class', $source);

        if (!$class || !is_a($class, DataObject::class, true)) {
            $output->writeln('<error>No DataObject class to backfill. Pass --class, or --source naming a source with a target_class.</error>');
            return Command::FAILURE;
        }

        if (!DataObject::getSchema()->fieldSpec($class, 'EmailCanonical')) {
            $output->writeln("<error>{$class} has no EmailCanonical column. Apply EmailCanonicalExtension and run dev/build first.</error>");
            return Command::FAILURE;
        }

        $emailField = DataObject::singleton($class)->config()->get('email_field') ?: 'Email';
        $table = DataObject::getSchema()->tableForField($class, 'EmailCanonical');
        $limit = (int) $input->getOption('limit');

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

        $output->writeln("Backfilled {$written} of {$total} record(s) on {$class}.");

        if ($total >= $limit) {
            $output->writeln('<comment>Hit the limit - run again to continue.</comment>');
        }

        return Command::SUCCESS;
    }
}
