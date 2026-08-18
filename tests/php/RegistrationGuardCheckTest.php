<?php

namespace Moosylvania\RegistrationGuard\Tests;

use Moosylvania\RegistrationGuard\Model\SpamRegistrationLog;
use Moosylvania\RegistrationGuard\Service\RegistrationGuard;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\Form;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\TextField;

/**
 * End to end runs of check(), the paths that only break once the framework is actually booted.
 */
class RegistrationGuardCheckTest extends SapphireTest
{
    protected $usesDatabase = true;

    protected function setUp(): void
    {
        parent::setUp();
        Environment::setEnv('SS_REGISTRATION_SECRET', 'test-secret');
        Config::modify()->set(RegistrationGuard::class, 'sources', [
            'test' => [
                'field_map' => [
                    'email' => 'Email',
                    'first_name' => 'FirstName',
                    'surname' => 'Surname',
                    'zip' => 'Zip',
                    'dob' => 'Dob',
                ],
                'min_age' => 21,
                'zip_regex' => '/^\d{5}(-\d{4})?$/',
            ],
        ]);
    }

    protected function validData(array $overrides = [])
    {
        return array_merge([
            'Email' => 'joe.madden@example.com',
            'FirstName' => 'Joe',
            'Surname' => 'Madden',
            'Zip' => '55401',
            'Dob' => '1980-05-02',
            'Rts' => $this->agedToken(30),
            'RgWebsite' => '',
        ], $overrides);
    }

    /**
     * A token that looks like the page was loaded $seconds ago.
     */
    protected function agedToken($seconds)
    {
        $method = new \ReflectionMethod(RegistrationGuard::class, 'signTimestamp');
        $method->setAccessible(true);
        $ts = time() - $seconds;
        return $ts . '.' . $method->invoke(null, $ts);
    }

    public function testCleanSubmissionPasses()
    {
        $result = RegistrationGuard::create()->check($this->validData(), 'test');

        $this->assertFalse($result->shouldStop(), implode(', ', $result->getReasons()));
        $this->assertEmpty($result->getFieldErrors());
        $this->assertEquals(0, $result->getScore());
    }

    public function testSubmittedTooFastIsBlocked()
    {
        $result = RegistrationGuard::create()->check($this->validData(['Rts' => $this->agedToken(1)]), 'test');

        $this->assertTrue($result->isBlocked());
        $this->assertContains('too-fast:1s', $result->getReasons());
    }

    public function testForgedAndStaleTimestampsAreBlocked()
    {
        $forged = RegistrationGuard::create()->check($this->validData(['Rts' => '1700000000.deadbeef']), 'test');
        $this->assertContains('bad-timestamp', $forged->getReasons());

        $stale = RegistrationGuard::create()->check($this->validData(['Rts' => $this->agedToken(99999)]), 'test');
        $this->assertContains('stale-form', $stale->getReasons());
        $this->assertStringContainsString('expired', $stale->getBlockMessage());
    }

    public function testFilledHoneypotIsBlocked()
    {
        $result = RegistrationGuard::create()->check($this->validData(['RgWebsite' => 'http://spam.example']), 'test');

        $this->assertTrue($result->isBlocked());
        $this->assertContains('honeypot', $result->getReasons());
    }

    /**
     * A bot posting a hand-built field list never sends the honeypot at all - absence must block just
     * as hard as a filled one.
     */
    public function testMissingHoneypotIsBlocked()
    {
        $data = $this->validData();
        unset($data['RgWebsite']);

        $result = RegistrationGuard::create()->check($data, 'test');

        $this->assertTrue($result->isBlocked());
        $this->assertContains('honeypot', $result->getReasons());
    }

    public function testUnderAgeIsAFieldErrorNotABlock()
    {
        $result = RegistrationGuard::create()->check(
            $this->validData(['Dob' => date('Y-m-d', strtotime('-18 years'))]),
            'test'
        );

        $this->assertFalse($result->isBlocked(), 'Being young is a mistake to fix, not spam');
        $this->assertTrue($result->shouldStop());
        $this->assertArrayHasKey('Dob', $result->getFieldErrors());
        $this->assertStringContainsString('21', $result->getFieldErrors()['Dob']['message']);
    }

    public function testHardContentBlocks()
    {
        $cases = [
            'blocked-substring-in-name:.ru' => ['Surname' => 'best.ru'],
            'blocked-email-suffix:.ru' => ['Email' => 'someone@mail.ru'],
            'too-many-spaces-in-name' => ['FirstName' => 'a b c d'],
            'invalid-zip' => ['Zip' => 'NW1 4RY'],
        ];

        foreach ($cases as $reason => $override) {
            $result = RegistrationGuard::create()->check($this->validData($override), 'test');
            $this->assertContains($reason, $result->getReasons(), "Expected {$reason}");
        }

        $cyrillic = RegistrationGuard::create()->check($this->validData(['Surname' => 'Иванов']), 'test');
        $this->assertTrue($cyrillic->isBlocked());
    }

    public function testBlockedSubmissionsAreLogged()
    {
        $request = new HTTPRequest('POST', '/register');
        $request->addHeader('User-Agent', 'TestBot/1.0');

        RegistrationGuard::create($request)->check($this->validData(['RgWebsite' => 'x']), 'test');

        $log = SpamRegistrationLog::get()->last();
        $this->assertNotNull($log, 'A blocked submission must leave a log row');
        $this->assertEquals('test', $log->Source);
        $this->assertEquals('joe.madden@example.com', $log->Email);
        $this->assertStringContainsString('honeypot', $log->Reasons);
    }

    public function testPassingSubmissionsAreNotLogged()
    {
        RegistrationGuard::create()->check($this->validData(), 'test');

        $this->assertEquals(0, SpamRegistrationLog::get()->count());
    }

    /**
     * With no target_class the guard must not touch the database at all, so it can protect forms that
     * write no record.
     */
    public function testWorksWithoutATargetClass()
    {
        $result = RegistrationGuard::create()->check($this->validData(), 'nosuchsource');

        $this->assertFalse($result->shouldStop(), implode(', ', $result->getReasons()));
    }

    public function testApplyToPutsFieldErrorsOnTheForm()
    {
        $form = $this->buildForm();
        $result = RegistrationGuard::create()->check(
            $this->validData(['Dob' => date('Y-m-d', strtotime('-18 years'))]),
            'test'
        );

        $result->applyTo($form);
        $messages = $form->getSessionValidationResult()->getMessages();

        $this->assertNotEmpty($messages);
        $this->assertEquals('Dob', $messages[0]['fieldName']);
    }

    /**
     * A blocked submission must reveal nothing about which rule fired.
     */
    public function testApplyToLeaksNothingForBlockedSubmissions()
    {
        $result = RegistrationGuard::create()->check($this->validData(['RgWebsite' => 'x']), 'test');
        $messages = $result->toValidationResult()->getMessages();

        $this->assertCount(1, $messages, 'A block gets exactly one generic message');
        $this->assertEmpty($messages[0]['fieldName'], 'Nothing is attributed to a field');
        $this->assertStringContainsString('error submitting', $messages[0]['message']);

        foreach ($result->getReasons() as $reason) {
            $this->assertStringNotContainsString($reason, $messages[0]['message'], 'Reasons stay in the log');
        }
    }

    protected function buildForm()
    {
        return Form::create(
            Controller::curr(),
            'TestForm',
            FieldList::create(TextField::create('Email'), TextField::create('Dob')),
            FieldList::create(FormAction::create('doTest'))
        );
    }
}
