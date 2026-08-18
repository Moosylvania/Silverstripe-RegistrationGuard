<?php

namespace Moosylvania\RegistrationGuard\Tests;

use Moosylvania\RegistrationGuard\Extension\EmailCanonicalExtension;
use Moosylvania\RegistrationGuard\Extension\RegistrationGuardFormExtension;
use Moosylvania\RegistrationGuard\Extension\RegistrationGuardHandlerExtension;
use Moosylvania\RegistrationGuard\Service\RegistrationGuard;
use Moosylvania\RegistrationGuard\Task\EmailCanonicalBackfillTask;
use Moosylvania\RegistrationGuard\Task\SpamScoreTask;
use Moosylvania\RegistrationGuard\Tests\Stub\GuardedTestForm;
use Moosylvania\RegistrationGuard\Tests\Stub\TestController;
use Moosylvania\RegistrationGuard\Tests\Stub\TestEntry;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Config\Config;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\Form;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\TextField;

class RegistrationGuardExtensionTest extends SapphireTest
{
    protected $usesDatabase = true;

    protected static $extra_dataobjects = [
        TestEntry::class,
    ];

    protected static $required_extensions = [
        TestEntry::class => [EmailCanonicalExtension::class],
        Form::class => [RegistrationGuardFormExtension::class],
    ];

    /*
    |--------------------------------------------------------------------------
    | EmailCanonicalExtension
    |--------------------------------------------------------------------------
    */

    public function testCanonicalIsWrittenOnSave()
    {
        $entry = TestEntry::create();
        $entry->Email = 'Some.One+promo@GMail.com';
        $entry->write();

        $this->assertEquals('someone@gmail.com', $entry->EmailCanonical);
    }

    public function testCanonicalCollapsesAliasesToOneInbox()
    {
        $a = TestEntry::create(['Email' => 'j.o.e@gmail.com']);
        $a->write();
        $b = TestEntry::create(['Email' => 'joe+winner@gmail.com']);
        $b->write();

        $this->assertEquals($a->EmailCanonical, $b->EmailCanonical, 'Both reach the same inbox');
    }

    public function testGuardBlocksADuplicateCanonicalAddress()
    {
        TestEntry::create(['Email' => 'j.o.e@gmail.com'])->write();

        Config::modify()->set(RegistrationGuard::class, 'sources', [
            'entries' => ['target_class' => TestEntry::class],
        ]);

        $result = RegistrationGuard::create()->check([
            'Email' => 'joe+again@gmail.com',
            'RgWebsite' => '',
            'Rts' => RegistrationGuard::freshToken(),
        ], 'entries');

        $this->assertContains('duplicate-canonical-email', $result->getReasons());
    }

    public function testUniqueFieldsProduceAFieldError()
    {
        TestEntry::create(['Email' => 'taken@example.com'])->write();

        Config::modify()->set(RegistrationGuard::class, 'sources', [
            'entries' => ['target_class' => TestEntry::class, 'unique_fields' => ['Email']],
        ]);

        $result = RegistrationGuard::create()->check([
            'Email' => 'TAKEN@example.com',
            'RgWebsite' => '',
            'Rts' => RegistrationGuard::freshToken(),
        ], 'entries');

        $this->assertArrayHasKey('Email', $result->getFieldErrors(), 'Matched case-insensitively');
    }

    /*
    |--------------------------------------------------------------------------
    | Auto-wiring
    |--------------------------------------------------------------------------
    */

    protected function guardForm()
    {
        Config::modify()->merge(RegistrationGuard::class, 'guarded_forms', [
            GuardedTestForm::class => ['actions' => ['doTest'], 'source' => 'wired'],
        ]);

        return GuardedTestForm::create(
            TestController::create(),
            'GuardedTestForm',
            FieldList::create(TextField::create('Email')),
            FieldList::create(FormAction::create('doTest'))
        );
    }

    public function testFormExtensionInjectsGuardFieldsOnRender()
    {
        $form = $this->guardForm();
        $this->assertNull($form->Fields()->dataFieldByName('RgWebsite'));

        $form->forTemplate();

        $this->assertNotNull($form->Fields()->dataFieldByName('Rts'));
        $this->assertNotNull($form->Fields()->dataFieldByName('RgWebsite'));
    }

    public function testFormExtensionRefreshesRatherThanDuplicating()
    {
        $form = $this->guardForm();
        $form->forTemplate();
        $first = $form->Fields()->dataFieldByName('Rts')->dataValue();
        $countAfterFirstRender = $form->Fields()->count();

        $form->Fields()->dataFieldByName('RgWebsite')->setValue('left over from a redirectBack');
        $form->forTemplate();

        $this->assertNotEmpty($first);
        $this->assertEquals($countAfterFirstRender, $form->Fields()->count(), 'Re-rendering must not stack up fields');
        $this->assertEquals('', $form->Fields()->dataFieldByName('RgWebsite')->dataValue());
    }

    public function testFormExtensionIgnoresUnguardedForms()
    {
        Config::modify()->set(RegistrationGuard::class, 'guarded_forms', []);
        $form = $this->guardForm();
        Config::modify()->set(RegistrationGuard::class, 'guarded_forms', []);

        $form->forTemplate();

        $this->assertNull($form->Fields()->dataFieldByName('RgWebsite'));
    }

    public function testHandlerExtensionThrowsOnASpamSubmission()
    {
        $form = $this->guardForm();
        $handler = $form->getRequestHandler();
        $extension = new RegistrationGuardHandlerExtension();
        $extension->setOwner($handler);

        $this->expectException(ValidationException::class);

        $extension->beforeCallFormHandler(
            Controller::curr()->getRequest(),
            'doTest',
            ['Email' => 'joe@example.com', 'RgWebsite' => 'i am a bot'],
            $form,
            $form
        );
    }

    public function testHandlerExtensionIgnoresOtherActions()
    {
        $form = $this->guardForm();
        $extension = new RegistrationGuardHandlerExtension();
        $extension->setOwner($form->getRequestHandler());

        $extension->beforeCallFormHandler(
            Controller::curr()->getRequest(),
            'someOtherAction',
            ['RgWebsite' => 'i am a bot'],
            $form,
            $form
        );

        $this->expectNotToPerformAssertions();
    }

    /*
    |--------------------------------------------------------------------------
    | Tasks
    |--------------------------------------------------------------------------
    */

    public function testTasksAreRegisteredAndDescribeThemselves()
    {
        foreach ([SpamScoreTask::class, EmailCanonicalBackfillTask::class] as $class) {
            $task = $class::create();

            $this->assertNotEmpty($task->getTitle());
            $this->assertNotEmpty(Config::inst()->get($class, 'segment'));
            $this->assertStringContainsString('source', $task->getDescription());
            $this->assertStringContainsString('class', $task->getDescription());
        }

        $this->assertStringContainsString(
            'delete',
            SpamScoreTask::create()->getDescription(),
            'Deleting must be an explicit opt-in flag'
        );
    }
}
