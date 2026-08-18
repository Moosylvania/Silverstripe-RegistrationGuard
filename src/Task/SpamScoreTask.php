<?php

namespace Moosylvania\RegistrationGuard\Task;

use Moosylvania\RegistrationGuard\Service\RegistrationGuard;
use SilverStripe\Dev\BuildTask;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\DataObject;
use SilverStripe\PolyExecution\PolyOutput;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * Score existing records with exactly the heuristics that would have blocked them at signup, so junk
 * that predates the guard can be found.
 *
 * Reports only. Nothing is deleted unless --delete is passed, and even then only records that pass the
 * content_relations safety gate.
 *
 * Note this applies the scored signals alone, not the hard content blocks - a stored record has no
 * timer, honeypot or rate limit to judge.
 */
class SpamScoreTask extends BuildTask
{
    protected string $title = 'RegistrationGuard: score existing records for spam';

    protected static string $description = 'Scores existing records with the RegistrationGuard heuristics. Reports only unless --delete is passed.';

    protected static string $commandName = 'registrationguard-score';

    /**
     * Relations that mean "this record is really used, never delete it", keyed by class name.
     *
     *     content_relations:
     *       SilverStripe\Security\Member:
     *         - Posts
     *         - Orders
     */
    private static array $content_relations = [];

    public function getOptions(): array
    {
        return [
            new InputOption('source', null, InputOption::VALUE_REQUIRED, 'RegistrationGuard source name to resolve class, fields and thresholds from'),
            new InputOption('class', null, InputOption::VALUE_REQUIRED, 'DataObject class to scan, overriding the source'),
            new InputOption('from', null, InputOption::VALUE_REQUIRED, 'Only records created on or after this date', '-90 days'),
            new InputOption('to', null, InputOption::VALUE_REQUIRED, 'Only records created on or before this date', 'now'),
            new InputOption('min', null, InputOption::VALUE_REQUIRED, 'Minimum score to report; defaults to the source block_threshold'),
            new InputOption('limit', null, InputOption::VALUE_REQUIRED, 'Maximum records to scan', 500),
            new InputOption('delete', null, InputOption::VALUE_NONE, 'Actually delete matching records that hold no content'),
        ];
    }

    protected function execute(InputInterface $input, PolyOutput $output): int
    {
        $source = $input->getOption('source');
        $class = $input->getOption('class') ?: RegistrationGuard::option('target_class', $source);

        if (!$class || !is_a($class, DataObject::class, true)) {
            $output->writeln('<error>No DataObject class to scan. Pass --class, or --source naming a source with a target_class.</error>');
            return Command::FAILURE;
        }

        $min = $input->getOption('min') !== null
            ? (int) $input->getOption('min')
            : (int) RegistrationGuard::option('block_threshold', $source);
        $limit = (int) $input->getOption('limit');
        $delete = (bool) $input->getOption('delete');

        $from = date('Y-m-d H:i:s', strtotime($input->getOption('from')));
        $to = date('Y-m-d H:i:s', strtotime($input->getOption('to')));

        $output->writeln([
            "Class:     {$class}",
            'Source:    ' . ($source ?: '(defaults)'),
            "Created:   {$from} .. {$to}",
            "Min score: {$min}",
            "Limit:     {$limit}",
            'Mode:      ' . ($delete ? '<error>DELETE - records will be removed</error>' : 'report only'),
            '',
        ]);

        $guard = RegistrationGuard::create(null, $source);
        $records = DataList::create($class)
            ->filter(['Created:GreaterThanOrEqual' => $from, 'Created:LessThanOrEqual' => $to])
            ->limit($limit);

        $matched = 0;
        $deletable = [];

        foreach ($records as $record) {
            $scored = $guard->scoreProfile($this->profileFor($record, $source), $source);

            if ($scored['score'] < $min) {
                continue;
            }

            $matched++;
            $hasContent = $this->hasContent($record);
            if (!$hasContent) {
                $deletable[] = $record->ID;
            }

            $output->writeln(sprintf(
                '#%-8d %-4d %-40s %s%s',
                $record->ID,
                $scored['score'],
                (string) $record->getField('Email'),
                implode(', ', $scored['reasons']),
                $hasContent ? '  <comment>[has content, kept]</comment>' : ''
            ));
        }

        $output->writeln([
            '',
            "Scanned {$records->count()} records, {$matched} at or above {$min}, " . count($deletable) . ' with no content.',
        ]);

        if (!$deletable) {
            return Command::SUCCESS;
        }

        if (!$delete) {
            $output->writeln([
                '',
                'Nothing was deleted. Re-run with --delete to remove the ' . count($deletable) . ' record(s) listed above without content.',
                'IDs: ' . implode(',', $deletable),
            ]);
            return Command::SUCCESS;
        }

        $deleted = 0;
        foreach (DataList::create($class)->filter(['ID' => $deletable]) as $record) {
            $record->delete();
            $deleted++;
        }
        $output->writeln(['', "<error>Deleted {$deleted} record(s).</error>"]);

        return Command::SUCCESS;
    }

    /**
     * Read the scoring fields off a record using the source's field_map.
     */
    protected function profileFor(DataObject $record, $source): array
    {
        $profile = [];

        foreach (['email' => 'Email', 'nickname' => 'Nickname', 'first_name' => 'FirstName', 'surname' => 'Surname', 'dob' => 'Dob'] as $logical => $key) {
            $column = RegistrationGuard::fieldName($logical, $source);
            // getField() rather than the accessor so a date comes back raw and unformatted.
            $profile[$key] = $column ? (string) $record->getField($column) : '';
        }

        return $profile;
    }

    /**
     * Whether the record has anything hanging off it worth keeping.
     */
    protected function hasContent(DataObject $record): bool
    {
        foreach ((array) $this->config()->get('content_relations') as $class => $relations) {
            if (!$record instanceof $class) {
                continue;
            }

            foreach ((array) $relations as $relation) {
                try {
                    $value = $record->relField($relation);
                } catch (\Exception $e) {
                    // A relation that doesn't exist can't prove the record is in use.
                    continue;
                }

                if (is_iterable($value)) {
                    foreach ($value as $ignored) {
                        return true;
                    }
                    continue;
                }

                if (!empty($value)) {
                    return true;
                }
            }
        }

        return false;
    }
}
