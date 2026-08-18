<?php

namespace Moosylvania\RegistrationGuard\Task;

use Moosylvania\RegistrationGuard\Service\RegistrationGuard;
use SilverStripe\Control\Director;
use SilverStripe\Dev\BuildTask;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\DataObject;

/**
 * Score existing records with exactly the heuristics that would have blocked them at signup, so junk
 * that predates the guard can be found.
 *
 * Reports only. Nothing is deleted unless delete=1 is passed, and even then only records that pass the
 * content_relations safety gate.
 *
 * Note this applies the scored signals alone, not the hard content blocks - a stored record has no
 * timer, honeypot or rate limit to judge.
 */
class SpamScoreTask extends BuildTask
{
    private static $segment = 'RegistrationGuard-Score';

    protected $title = 'RegistrationGuard: score existing records for spam';

    protected $description = 'Scores existing records with the RegistrationGuard heuristics. '
        . 'Reports only unless delete=1 is passed. '
        . 'Params: source, class, from, to, min, limit, delete.';

    /**
     * Relations that mean "this record is really used, never delete it", keyed by class name.
     *
     *     content_relations:
     *       SilverStripe\Security\Member:
     *         - Posts
     *         - Orders
     */
    private static $content_relations = [];

    public function run($request)
    {
        $source = $request->getVar('source');
        $class = $request->getVar('class') ?: RegistrationGuard::option('target_class', $source);

        if (!$class || !is_a($class, DataObject::class, true)) {
            $this->line('No DataObject class to scan. Pass class, or source naming a source with a target_class.');
            return;
        }

        $min = $request->getVar('min') !== null
            ? (int) $request->getVar('min')
            : (int) RegistrationGuard::option('block_threshold', $source);
        $limit = (int) ($request->getVar('limit') ?: 500);
        $delete = (bool) $request->getVar('delete');

        $from = date('Y-m-d H:i:s', strtotime($request->getVar('from') ?: '-90 days'));
        $to = date('Y-m-d H:i:s', strtotime($request->getVar('to') ?: 'now'));

        $this->line("Class:     {$class}");
        $this->line('Source:    ' . ($source ?: '(defaults)'));
        $this->line("Created:   {$from} .. {$to}");
        $this->line("Min score: {$min}");
        $this->line("Limit:     {$limit}");
        $this->line('Mode:      ' . ($delete ? 'DELETE - records will be removed' : 'report only'));
        $this->line('');

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

            $this->line(sprintf(
                '#%-8d %-4d %-40s %s%s',
                $record->ID,
                $scored['score'],
                (string) $record->getField('Email'),
                implode(', ', $scored['reasons']),
                $hasContent ? '  [has content, kept]' : ''
            ));
        }

        $this->line('');
        $this->line(
            "Scanned {$records->count()} records, {$matched} at or above {$min}, "
            . count($deletable) . ' with no content.'
        );

        if (!$deletable) {
            return;
        }

        if (!$delete) {
            $this->line('');
            $this->line(
                'Nothing was deleted. Re-run with delete=1 to remove the ' . count($deletable)
                . ' record(s) listed above without content.'
            );
            $this->line('IDs: ' . implode(',', $deletable));
            return;
        }

        $deleted = 0;
        foreach (DataList::create($class)->filter(['ID' => $deletable]) as $record) {
            $record->delete();
            $deleted++;
        }
        $this->line('');
        $this->line("Deleted {$deleted} record(s).");
    }

    /**
     * Read the scoring fields off a record using the source's field_map.
     */
    protected function profileFor(DataObject $record, $source)
    {
        $profile = [];
        $logicals = [
            'email' => 'Email',
            'nickname' => 'Nickname',
            'first_name' => 'FirstName',
            'surname' => 'Surname',
            'dob' => 'Dob',
        ];

        foreach ($logicals as $logical => $key) {
            $column = RegistrationGuard::fieldName($logical, $source);
            // getField() rather than the accessor so a date comes back raw and unformatted.
            $profile[$key] = $column ? (string) $record->getField($column) : '';
        }

        return $profile;
    }

    /**
     * Whether the record has anything hanging off it worth keeping.
     */
    protected function hasContent(DataObject $record)
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

    protected function line($message)
    {
        echo $message . (Director::is_cli() ? PHP_EOL : '<br>' . PHP_EOL);
    }
}
