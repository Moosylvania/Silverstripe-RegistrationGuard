<?php

namespace Moosylvania\RegistrationGuard\Service;

use Moosylvania\RegistrationGuard\Model\SpamRegistrationLog;
use Psr\Log\LoggerInterface;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Cache\RateLimiter;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Forms\TextField;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\DataObject;

/**
 * Single home for every registration anti-spam / validation check.
 *
 * One guard serves many forms. Each form names a "source" - a key under the `sources` config - which
 * supplies the DataObject class to check against, the form field names to read, and any threshold
 * overrides. The same string is written to SpamRegistrationLog.Source, so the log stays segmented by
 * form for free.
 *
 * Two kinds of outcome:
 *  - Field errors: user-fixable problems (duplicate email, under age). Shown against the field.
 *  - Blocks: spam. Generic error message, silently logged to SpamRegistrationLog for tuning.
 *
 * The scored heuristics are tuned against real traffic. No single signal that could plausibly hit a
 * real person reaches block_threshold on its own - see docs/en/registration-guard.md before changing
 * any of the numbers.
 */
class RegistrationGuard
{
    use Configurable;
    use Injectable;

    /**
     * Minimum seconds a human must spend on the form before we accept the submission.
     */
    private static $min_form_seconds = 5;

    /**
     * Beyond this the signed timestamp is considered stale and we ask them to reload.
     */
    private static $max_form_seconds = 7200;

    /**
     * Scored signals block at or above this total.
     */
    private static $block_threshold = 100;

    /**
     * Dates of birth used by bots. Scored, never a hard block on their own - a real person can
     * legitimately have been born on any of these.
     */
    private static $suspicious_dobs = [
        '1970-01-01',
        '1900-01-01',
        '0000-00-00',
    ];

    /**
     * Domains where dots in the local part are ignored by the mail provider, letting one inbox farm
     * unlimited unique-looking addresses.
     */
    private static $dot_alias_domains = [
        'gmail.com',
        'googlemail.com',
    ];

    /**
     * Rate limit: hits allowed per decay window (seconds), keyed on source + host + IP.
     */
    private static $rate_limit_hits = 1;

    private static $rate_limit_decay = 60;

    /**
     * DataObject the submission would create. null disables every database-backed check.
     */
    private static $target_class = null;

    /**
     * Logical name => form field name. A null or missing entry skips every check reading that field.
     * A source's field_map REPLACES this wholesale rather than merging, so a source can drop a field
     * simply by omitting it.
     */
    private static $field_map = [
        'email' => 'Email',
        'nickname' => null,
        'first_name' => 'FirstName',
        'surname' => 'Surname',
        'zip' => null,
        'dob' => null,
    ];

    /**
     * target_class columns that must not already hold the submitted value (compared case-insensitively).
     */
    private static $unique_fields = [];

    private static $reserved_nicknames = [];

    private static $blocked_email_domains = [];

    private static $blocked_email_suffixes = ['.ru'];

    private static $blocked_name_substrings = ['http://', 'https://', '.ru'];

    /**
     * Preg patterns that must not match any submitted name or the email. Plain regexes rather than
     * script names so a project can add its own without the module owning a mapping table.
     */
    private static $blocked_name_patterns = ['/[А-Яа-яЁё]/u', '/\p{Han}/u'];

    /**
     * Minimum age in years. 0 disables the age gate.
     */
    private static $min_age = 0;

    /**
     * Preg pattern the zip must match. null disables the check.
     */
    private static $zip_regex = null;

    /**
     * Name of the module's own honeypot field. null disables the honeypot.
     */
    private static $honeypot_field = 'RgWebsite';

    private static $timestamp_field = 'Rts';

    /**
     * Column written by EmailCanonicalExtension. Skipped when null or absent from target_class.
     */
    private static $canonical_field = 'EmailCanonical';

    /**
     * Per-source overrides of any option above, keyed by source name.
     */
    private static $sources = [];

    /**
     * Forms the auto-wiring extensions guard, keyed by form class:
     *
     *     guarded_forms:
     *       'App\Forms\RegistrationForm': {actions: [doRegister], source: members}
     *
     * Read by both RegistrationGuardFormExtension and RegistrationGuardHandlerExtension so the
     * wiring lives in one place. Empty by default - the extensions are inert until a form is listed.
     */
    private static $guarded_forms = [];

    /**
     * @var HTTPRequest|null
     */
    protected $request;

    /**
     * @var string|null
     */
    protected $source;

    public function __construct($request = null, $source = null)
    {
        $this->request = $request;
        $this->source = $source;
    }

    public function setSource($source)
    {
        $this->source = $source;
        return $this;
    }

    public function getSource()
    {
        return $this->source;
    }

    /*
    |--------------------------------------------------------------------------
    | Config resolution
    |--------------------------------------------------------------------------
    */

    /**
     * Resolve an option for a source, falling back to the class-level default.
     *
     * An unknown source name is not an error - it simply resolves to the defaults, so check() always
     * works and the log still records the name.
     *
     * @param string $name
     * @param string|null $source
     * @return mixed
     */
    public static function option($name, $source = null)
    {
        $config = static::config();

        if ($source) {
            $sources = (array) $config->get('sources');
            if (
                isset($sources[$source]) && is_array($sources[$source])
                && array_key_exists($name, $sources[$source])
            ) {
                return $sources[$source][$name];
            }
        }

        return $config->get($name);
    }

    /**
     * Instance shorthand for option() bound to this guard's source.
     *
     * @param string $name
     * @return mixed
     */
    protected function opt($name)
    {
        return static::option($name, $this->source);
    }

    /**
     * @param string $logical One of the field_map keys
     * @param string|null $source
     * @return string|null Form field name, or null when this source doesn't collect it
     */
    public static function fieldName($logical, $source = null)
    {
        $map = (array) static::option('field_map', $source);
        return !empty($map[$logical]) ? $map[$logical] : null;
    }

    /**
     * Trimmed submitted value for a logical field, or '' when unmapped or absent.
     *
     * @return string
     */
    protected function value(array $data, $logical)
    {
        $name = $this->fieldName($logical, $this->source);
        return ($name !== null && isset($data[$name])) ? trim((string) $data[$name]) : '';
    }

    /*
    |--------------------------------------------------------------------------
    | Form fields
    |--------------------------------------------------------------------------
    */

    /**
     * The timestamp and honeypot fields, ready to merge into a form's FieldList.
     *
     * Neither field may ever carry a "required" class or attribute - frontend validators routinely
     * walk `.required` and would block every genuine submission.
     *
     * @param string|null $source
     * @return FieldList
     */
    public static function guardFields($source = null)
    {
        $fields = FieldList::create();

        if ($field = static::timestampField($source)) {
            $fields->push($field);
        }
        if ($field = static::honeypotField($source)) {
            $fields->push($field);
        }

        return $fields;
    }

    /**
     * Hidden field carrying an HMAC signed page-load time. Signing stops a bot simply posting an
     * older timestamp to walk past the dwell time check.
     *
     * @param string|null $source
     * @return HiddenField|null
     */
    public static function timestampField($source = null)
    {
        $name = static::option('timestamp_field', $source);
        if (!$name) {
            return null;
        }

        return HiddenField::create($name)->setValue(static::freshToken());
    }

    /**
     * The module's own honeypot: a text input that must come back present and empty.
     *
     * Present-and-empty rather than just empty, because the presence half is what catches a bot
     * posting a hand-built field list instead of the real form.
     *
     * Hidden with an inline style so the module ships no CSS or JS asset. autocomplete/tabindex keep
     * password managers and keyboard users out of it - a filled honeypot silently blocks a real
     * person, so the false-positive surface matters more than the field being pretty.
     *
     * @param string|null $source
     * @return TextField|null
     */
    public static function honeypotField($source = null)
    {
        $name = static::option('honeypot_field', $source);
        if (!$name) {
            return null;
        }

        return TextField::create($name, '')
            ->setValue('')
            ->setAttribute('style', 'position:absolute;left:-9999px;top:-9999px;height:0;width:0;opacity:0;')
            ->setAttribute('autocomplete', 'off')
            ->setAttribute('tabindex', '-1')
            ->setAttribute('aria-hidden', 'true');
    }

    /*
    |--------------------------------------------------------------------------
    | Form timing
    |--------------------------------------------------------------------------
    */

    /**
     * @return string "<timestamp>.<signature>"
     */
    public static function freshToken()
    {
        $ts = time();
        return $ts . '.' . static::signTimestamp($ts);
    }

    protected static function signTimestamp($ts)
    {
        $secret = Environment::getEnv('SS_REGISTRATION_SECRET');
        if (!$secret) {
            $secret = Environment::getEnv('SS_DATABASE_PASSWORD');
        }
        return hash_hmac('sha256', (string) $ts, (string) $secret);
    }

    /**
     * @param string|null $token
     * @return int|false Seconds spent on the form, or false when missing / forged.
     */
    public static function secondsOnForm($token)
    {
        if (!$token || strpos($token, '.') === false) {
            return false;
        }
        list($ts, $sig) = explode('.', $token, 2);
        if (!ctype_digit($ts) || !hash_equals(static::signTimestamp($ts), $sig)) {
            return false;
        }
        return time() - (int) $ts;
    }

    /*
    |--------------------------------------------------------------------------
    | Main entry point
    |--------------------------------------------------------------------------
    */

    /**
     * Run every check against submitted form data.
     *
     * @param array $data Raw posted data
     * @param string|null $source Source name; overrides any set on the instance
     * @return RegistrationGuardResult
     */
    public function check(array $data, $source = null)
    {
        if ($source !== null) {
            $this->source = $source;
        }

        $result = RegistrationGuardResult::create();
        $result->setSource($this->source);

        $email = $this->value($data, 'email');
        $nickname = $this->value($data, 'nickname');
        $firstName = $this->value($data, 'first_name');
        $surname = $this->value($data, 'surname');
        $zip = $this->value($data, 'zip');
        $dob = $this->value($data, 'dob');

        // ---------------------------------------------------------------- field errors

        foreach ($this->duplicateFields($data) as $field) {
            $message = _t(
                self::class . '.DUPLICATE_' . $field,
                _t(self::class . '.DUPLICATE', 'Sorry this {field} is already in use.'),
                ['field' => $field]
            );
            $result->addFieldError(
                $field,
                $message,
                $this->genericError() . ' ' . $message,
                $message !== strip_tags($message)
            );
        }

        $nicknameField = $this->fieldName('nickname', $this->source);
        if (
            $nicknameField && $nickname !== ''
            && in_array(mb_strtolower($nickname), array_map('mb_strtolower', (array) $this->opt('reserved_nicknames')), true)
        ) {
            $message = _t(self::class . '.RESERVED_NICKNAME', 'Sorry this Nickname is not available.');
            $result->addFieldError($nicknameField, $message, $this->genericError() . ' ' . $message);
        }

        $minAge = (int) $this->opt('min_age');
        $dobField = $this->fieldName('dob', $this->source);
        $bd = $dob !== '' ? strtotime($dob) : false;
        if ($minAge > 0 && $dobField && $bd && $bd > strtotime('-' . $minAge . ' years')) {
            $message = _t(
                self::class . '.UNDER_AGE',
                'Sorry you must be {age} years of age to register.',
                ['age' => $minAge]
            );
            $result->addFieldError($dobField, $message, $this->genericError() . ' ' . $message);
        }

        // ---------------------------------------------------------------- timing

        $timestampField = $this->opt('timestamp_field');
        if ($timestampField) {
            $seconds = static::secondsOnForm($data[$timestampField] ?? null);
            $result->setSecondsOnForm(is_int($seconds) ? $seconds : -1);

            if ($seconds === false) {
                $result->block('bad-timestamp');
            } elseif ($seconds < (int) $this->opt('min_form_seconds')) {
                $result->block('too-fast:' . $seconds . 's');
            } elseif ($seconds > (int) $this->opt('max_form_seconds')) {
                $result->block('stale-form', $this->staleError());
            }
        }

        // ---------------------------------------------------------------- honeypot

        $honeypotField = $this->opt('honeypot_field');
        if ($honeypotField) {
            if (!array_key_exists($honeypotField, $data) || trim((string) $data[$honeypotField]) !== '') {
                $result->block('honeypot');
            }
        }

        // ---------------------------------------------------------------- hard content blocks

        foreach ($this->hardBlockReasons($email, $nickname, $firstName, $surname, $zip) as $reason) {
            $result->block($reason);
        }

        // ---------------------------------------------------------------- duplicate canonical email

        $canonical = static::canonicalEmail($email, $this->source);
        if ($canonical && $this->canonicalInUse($canonical)) {
            $result->block('duplicate-canonical-email');
        }

        // ---------------------------------------------------------------- scored signals

        $scored = $this->scoreProfile([
            'Email' => $email,
            'Nickname' => $nickname,
            'FirstName' => $firstName,
            'Surname' => $surname,
            'Dob' => $bd ? date('Y-m-d', $bd) : $dob,
        ], $this->source);

        $result->addScore($scored['score'], $scored['reasons']);

        if ($result->getScore() >= (int) $this->opt('block_threshold')) {
            $result->setBlocked(true);
        }

        // ---------------------------------------------------------------- rate limit

        if (!$result->isBlocked() && !$result->getFieldErrors() && $this->request) {
            $limiter = $this->rateLimiter();
            if (!$limiter->canAccess()) {
                $result->block('rate-limited');
            } else {
                $limiter->hit();
            }
        }

        if ($result->isBlocked()) {
            $this->log($result, $data, $canonical);
        }

        return $result;
    }

    /**
     * @return string[] unique_fields whose submitted value is already taken
     */
    protected function duplicateFields(array $data)
    {
        $class = $this->targetClass();
        if (!$class) {
            return [];
        }

        $taken = [];
        foreach ((array) $this->opt('unique_fields') as $field) {
            $value = isset($data[$field]) ? trim((string) $data[$field]) : '';
            if ($value === '') {
                continue;
            }
            if (DataList::create($class)->filter([$field . ':nocase' => $value])->exists()) {
                $taken[] = $field;
            }
        }

        return $taken;
    }

    /**
     * Silently a no-op when the target class has no canonical column, i.e. when
     * EmailCanonicalExtension has not been applied.
     */
    protected function canonicalInUse($canonical)
    {
        $class = $this->targetClass();
        $field = $this->opt('canonical_field');

        if (!$class || !$field || !DataObject::getSchema()->fieldSpec($class, $field)) {
            return false;
        }

        return DataList::create($class)->filter([$field => $canonical])->exists();
    }

    /**
     * @return string|null
     */
    protected function targetClass()
    {
        $class = $this->opt('target_class');
        return ($class && class_exists($class) && is_a($class, DataObject::class, true)) ? $class : null;
    }

    /**
     * Checks that always block outright, regardless of anything else.
     *
     * @return array reason strings
     */
    protected function hardBlockReasons($email, $nickname, $firstName, $surname, $zip)
    {
        $reasons = [];
        $names = array_filter([$nickname, $firstName, $surname], 'strlen');
        $all = array_filter(array_merge($names, [$email]), 'strlen');

        foreach ((array) $this->opt('blocked_name_substrings') as $needle) {
            foreach ($names as $name) {
                if (stripos($name, (string) $needle) !== false) {
                    $reasons[] = 'blocked-substring-in-name:' . $needle;
                    break;
                }
            }
        }

        $lowerEmail = mb_strtolower($email);
        foreach ((array) $this->opt('blocked_email_suffixes') as $suffix) {
            if ($lowerEmail !== '' && str_ends_with($lowerEmail, mb_strtolower((string) $suffix))) {
                $reasons[] = 'blocked-email-suffix:' . $suffix;
            }
        }

        $domain = mb_strtolower(substr(strrchr($email, '@') ?: '', 1));
        if ($domain && in_array($domain, array_map('mb_strtolower', (array) $this->opt('blocked_email_domains')), true)) {
            $reasons[] = 'blocked-domain:' . $domain;
        }

        foreach ((array) $this->opt('blocked_name_patterns') as $pattern) {
            foreach ($all as $value) {
                if (preg_match($pattern, $value)) {
                    $reasons[] = 'blocked-pattern:' . $pattern;
                    break;
                }
            }
        }

        if (substr_count($firstName, ' ') > 1 || substr_count($surname, ' ') > 2) {
            $reasons[] = 'too-many-spaces-in-name';
        }

        $zipRegex = $this->opt('zip_regex');
        if ($zipRegex && $this->fieldName('zip', $this->source) && !preg_match($zipRegex, $zip)) {
            $reasons[] = 'invalid-zip';
        }

        return $reasons;
    }

    /*
    |--------------------------------------------------------------------------
    | Scoring - shared with SpamScoreTask
    |--------------------------------------------------------------------------
    */

    /**
     * Score a profile on the "looks machine generated" signals only. No timer, honeypot or rate
     * limiting, so this can be run against a stored record as well as a form submission.
     *
     * Note this deliberately applies none of hardBlockReasons() - a stored record scored here gets
     * only the heuristic subset.
     *
     * @param array $profile Email, Nickname, FirstName, Surname, Dob (Y-m-d)
     * @param string|null $source
     * @return array ['score' => int, 'reasons' => string[]]
     */
    public function scoreProfile(array $profile, $source = null)
    {
        if ($source === null) {
            $source = $this->source;
        }

        $score = 0;
        $reasons = [];

        $email = trim((string) ($profile['Email'] ?? ''));
        $nickname = trim((string) ($profile['Nickname'] ?? ''));
        $firstName = trim((string) ($profile['FirstName'] ?? ''));
        $surname = trim((string) ($profile['Surname'] ?? ''));
        $dob = trim((string) ($profile['Dob'] ?? ''));

        if ($dob && in_array($dob, (array) static::option('suspicious_dobs', $source), true)) {
            $score += 60;
            $reasons[] = 'suspicious-dob:' . $dob;
        }

        foreach (['FirstName' => $firstName, 'Surname' => $surname, 'Nickname' => $nickname] as $field => $value) {
            $gibberish = static::gibberishScore($value, $field !== 'Nickname');
            if ($gibberish > 0) {
                $score += $gibberish;
                $reasons[] = 'gibberish-' . strtolower($field) . ':' . $gibberish;
            }
        }

        $local = strstr($email, '@', true);
        $domain = mb_strtolower(substr(strrchr($email, '@') ?: '', 1));
        $aliasDomains = (array) static::option('dot_alias_domains', $source);

        if ($local !== false && $local !== '' && in_array($domain, $aliasDomains, true)) {
            $dots = substr_count($local, '.');
            $ratio = strlen($local) > 0 ? $dots / strlen($local) : 0;
            if ($dots >= 3 || $ratio > 0.25) {
                $score += 50;
                $reasons[] = 'dot-aliased-email:' . $dots . 'dots';
            }
        }

        if ($local !== false && $local !== '') {
            // Local parts like d.i.amondflo.o.r.i.ngl.lc.a.l where most segments are a single char.
            $segments = preg_split('/[._-]+/', $local, -1, PREG_SPLIT_NO_EMPTY);
            if (count($segments) >= 4) {
                $singles = 0;
                foreach ($segments as $segment) {
                    if (strlen($segment) === 1) {
                        $singles++;
                    }
                }
                if ($singles / count($segments) >= 0.6) {
                    $score += 30;
                    $reasons[] = 'fragmented-email-local';
                }
            }
        }

        return ['score' => $score, 'reasons' => $reasons];
    }

    /**
     * How machine generated a name looks, 0 (fine) to 50 (certainly junk).
     *
     * Deliberately tuned so no single rule that could hit a real name scores enough to block on its
     * own - unusual but genuine surnames (Krzysztof, Wojciechowski) land at 25, well under the
     * threshold, and need corroborating signals before anything is rejected.
     *
     * @param string $name
     * @param bool $isRealName true for FirstName/Surname, false for Nickname (digits are fine there)
     * @return int
     */
    public static function gibberishScore($name, $isRealName = true)
    {
        $normalised = preg_replace('/[\s\'.\-]/u', '', (string) $name);

        if (mb_strlen($normalised) < 4) {
            // Genuine short names - Li, Ng, Bo, Tran - can never be judged.
            return 0;
        }

        // Score the longest token so "Anne-Marie" is judged on "Marie", not the concatenation.
        $tokens = preg_split('/[\s\'.\-]+/u', trim((string) $name), -1, PREG_SPLIT_NO_EMPTY);
        $token = '';
        foreach ((array) $tokens as $candidate) {
            if (mb_strlen($candidate) > mb_strlen($token)) {
                $token = $candidate;
            }
        }

        if (mb_strlen($token) < 4) {
            return 0;
        }

        $score = 0;
        $lower = mb_strtolower($token);
        $length = mb_strlen($lower);
        $letters = preg_replace('/[^a-z]/', '', $lower);
        $vowels = preg_match_all('/[aeiouy]/', $letters);

        if (strlen($letters) >= 4 && $vowels === 0) {
            // Rtwwg
            $score += 45;
        }

        if (static::longestConsonantRun($letters) >= 5) {
            // Mnwhgskdl
            $score += 45;
        }

        if (static::looksRandomlyCased($token)) {
            // cgwEIPbzXEAIBsIj
            $score += 40;
        }

        // Vowel ratio is measured after collapsing the consonant digraphs real names are built from
        // (Schwartz, Schmidt, Krzysztof), which would otherwise look vowel-starved. Random strings
        // don't use those clusters, so they survive the normalisation and still score.
        $stripped = static::stripDigraphs($letters);
        if (
            strlen($stripped) >= 7 && $vowels > 0
            && (preg_match_all('/[aeiouy]/', $stripped) / strlen($stripped)) < 0.25
        ) {
            // Weak signal only - never enough to block on its own.
            $score += 25;
        }

        if ($length >= 14 && !preg_match('/\d/', $token)) {
            $score += 20;
        }

        if ($isRealName && preg_match('/\d/', $token)) {
            $score += 25;
        }

        return min($score, 50);
    }

    /**
     * Collapse doubled letters and the consonant clusters that occur in real English, German,
     * Slavic and Welsh surnames, so those names aren't judged as vowel-starved.
     */
    protected static function stripDigraphs($letters)
    {
        $letters = preg_replace('/(.)\1+/', '$1', $letters);
        return str_replace(
            ['sch', 'sz', 'cz', 'rz', 'tz', 'ck', 'ph', 'th', 'sh', 'ch', 'ng', 'wr', 'kn', 'gh', 'wh', 'qu'],
            '',
            $letters
        );
    }

    protected static function longestConsonantRun($letters)
    {
        $longest = 0;
        $current = 0;
        foreach (str_split($letters ?: '') as $char) {
            if (strpos('aeiouy', $char) === false) {
                $current++;
                $longest = max($longest, $current);
            } else {
                $current = 0;
            }
        }
        return $longest;
    }

    /**
     * Frequent lower -> UPPER transitions are what random string generators produce - but they are
     * also just camelCase, which plenty of real nicknames use (xXCigarKingXx, SmokeyJoe).
     *
     * The tell is where the breaks fall: a real camelCase handle breaks at word boundaries, so every
     * chunk is pronounceable. A generated string leaves vowel-less rubble behind ("cgw" in
     * cgwEIPbzXEAIBsIj), so we require both the transitions and at least one such chunk.
     */
    protected static function looksRandomlyCased($value)
    {
        $segments = preg_split('/(?<=[a-z])(?=[A-Z])/', $value);

        if (count($segments) < 4) {
            // Fewer than 3 transitions.
            return false;
        }

        foreach ($segments as $segment) {
            $letters = preg_replace('/[^a-z]/', '', strtolower($segment));
            if (strlen($letters) >= 3 && !preg_match('/[aeiouy]/', $letters)) {
                return true;
            }
        }

        return false;
    }

    /*
    |--------------------------------------------------------------------------
    | Email canonicalisation
    |--------------------------------------------------------------------------
    */

    /**
     * Collapse an address to the inbox it actually reaches, so the gmail dot / plus tricks stop
     * yielding unlimited unique looking addresses.
     *
     * d.i.amondflo.o.r.i.ngl.lc.a.l@gmail.com -> diamondflooringllcal@gmail.com
     *
     * @param string $email
     * @param string|null $source
     * @return string
     */
    public static function canonicalEmail($email, $source = null)
    {
        $email = mb_strtolower(trim((string) $email));
        if (!$email || strpos($email, '@') === false) {
            return $email;
        }

        list($local, $domain) = explode('@', $email, 2);

        if (strpos($local, '+') !== false) {
            $local = strstr($local, '+', true);
        }

        if (in_array($domain, (array) static::option('dot_alias_domains', $source), true)) {
            $local = str_replace('.', '', $local);
        }

        return $local . '@' . $domain;
    }

    /*
    |--------------------------------------------------------------------------
    | Messages
    |--------------------------------------------------------------------------
    */

    public function genericError()
    {
        return _t(
            self::class . '.GENERIC_ERROR',
            'There was an error submitting your registration, please make sure all information is correct.'
        );
    }

    public function staleError()
    {
        return _t(
            self::class . '.STALE_ERROR',
            'Your registration form expired, please reload the page and try again.'
        );
    }

    /*
    |--------------------------------------------------------------------------
    | Rate limiting
    |--------------------------------------------------------------------------
    */

    public function rateLimiter()
    {
        return RateLimiter::create(
            $this->rateLimitKey(),
            (int) $this->opt('rate_limit_hits'),
            (int) $this->opt('rate_limit_decay')
        );
    }

    /**
     * Keyed on the source too, so a sweeps entry and a registration don't share one bucket.
     */
    protected function rateLimitKey()
    {
        $key = 'registrationguard-';
        $key .= ($this->source ?: 'default') . '-';
        $key .= $this->request->getHost() . '-';
        $key .= $this->request->getIP();
        return md5($key);
    }

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    */

    /**
     * Record a blocked attempt so thresholds can be tuned against real traffic. Never allowed to
     * interfere with the request.
     */
    protected function log(RegistrationGuardResult $result, array $data, $canonical)
    {
        try {
            $log = SpamRegistrationLog::create();
            $log->Email = $this->value($data, 'email');
            $log->EmailCanonical = $canonical;
            $log->Nickname = $this->value($data, 'nickname');
            $log->FirstName = $this->value($data, 'first_name');
            $log->Surname = $this->value($data, 'surname');
            $log->Dob = $this->value($data, 'dob');
            $log->Zip = $this->value($data, 'zip');
            $log->Score = $result->getScore();
            $log->Reasons = implode("\n", $result->getReasons());
            $log->Source = (string) $this->source;
            $log->SecondsOnForm = $result->getSecondsOnForm();
            if ($this->request) {
                $log->IP = $this->request->getIP();
                $log->UserAgent = substr((string) $this->request->getHeader('User-Agent'), 0, 1000);
            }
            $log->write();
        } catch (\Exception $e) {
            Injector::inst()->get(LoggerInterface::class)->error(
                'Unable to write SpamRegistrationLog: ' . $e->getMessage(),
                ['exception' => $e]
            );
        }
    }
}
