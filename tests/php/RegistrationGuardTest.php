<?php

namespace Moosylvania\RegistrationGuard\Tests;

use Moosylvania\RegistrationGuard\Service\RegistrationGuard;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Dev\SapphireTest;

/**
 * Covers the request-free logic the whole module rests on. No database: these are the pure functions,
 * and they are where a regression is silent and expensive.
 */
class RegistrationGuardTest extends SapphireTest
{
    protected $usesDatabase = false;

    protected function setUp(): void
    {
        parent::setUp();
        Environment::setEnv('SS_REGISTRATION_SECRET', 'test-secret');
    }

    public function testCanonicalEmailCollapsesGmailTricks()
    {
        $this->assertEquals(
            'diamondflooringllcal@gmail.com',
            RegistrationGuard::canonicalEmail('d.i.amondflo.o.r.i.ngl.lc.a.l@gmail.com')
        );
        $this->assertEquals('someone@gmail.com', RegistrationGuard::canonicalEmail('some.one+spam@gmail.com'));
        $this->assertEquals('someone@googlemail.com', RegistrationGuard::canonicalEmail('Some.One@GoogleMail.com'));
    }

    public function testCanonicalEmailLeavesOtherDomainsAlone()
    {
        // Dots are significant everywhere except the alias domains - stripping them here would
        // collide two genuinely different inboxes.
        $this->assertEquals('some.one@example.com', RegistrationGuard::canonicalEmail('Some.One@example.com'));
        // Plus addressing is collapsed everywhere, which is safe: it always reaches the same inbox.
        $this->assertEquals('some.one@example.com', RegistrationGuard::canonicalEmail('some.one+tag@example.com'));
        $this->assertEquals('', RegistrationGuard::canonicalEmail(''));
        $this->assertEquals('notanemail', RegistrationGuard::canonicalEmail('notanemail'));
    }

    public function testSecondsOnFormAcceptsOnlySignedTokens()
    {
        $token = RegistrationGuard::freshToken();
        $this->assertIsInt(RegistrationGuard::secondsOnForm($token));
        $this->assertLessThan(3, RegistrationGuard::secondsOnForm($token));

        list($ts) = explode('.', $token, 2);

        $this->assertFalse(RegistrationGuard::secondsOnForm(null), 'Missing token');
        $this->assertFalse(RegistrationGuard::secondsOnForm(''), 'Empty token');
        $this->assertFalse(RegistrationGuard::secondsOnForm($ts), 'Unsigned timestamp');
        $this->assertFalse(RegistrationGuard::secondsOnForm($ts . '.deadbeef'), 'Forged signature');
        // The whole point of signing: an older timestamp must not be postable.
        $this->assertFalse(RegistrationGuard::secondsOnForm(($ts - 600) . '.' . explode('.', $token, 2)[1]));
    }

    /**
     * @dataProvider provideJunkNames
     */
    public function testGibberishScoreCatchesGeneratedNames($name)
    {
        $this->assertGreaterThanOrEqual(
            40,
            RegistrationGuard::gibberishScore($name),
            "'{$name}' should score as machine generated"
        );
    }

    public static function provideJunkNames()
    {
        return [['Rtwwg'], ['Mnwhgskdl'], ['cgwEIPbzXEAIBsIj'], ['Bzzkrtlmn']];
    }

    /**
     * Real names must never reach block_threshold on the name signal alone. This is the regression
     * that matters: a tightened heuristic that starts rejecting genuine surnames costs real signups.
     *
     * @dataProvider provideRealNames
     */
    public function testGibberishScoreSpareRealNames($name)
    {
        $threshold = (int) Config::inst()->get(RegistrationGuard::class, 'block_threshold');

        $this->assertLessThan(
            $threshold,
            RegistrationGuard::gibberishScore($name),
            "'{$name}' is a real name and must not block on its own"
        );
    }

    public static function provideRealNames()
    {
        return [
            ['Li'], ['Ng'], ['Bo'], ['Tran'], ['Smith'], ['Anne-Marie'], ['Schwartz'], ['Schmidt'],
            ['Krzysztof'], ['Wojciechowski'], ["O'Sullivan"], ['van der Berg'], ['Nguyen'],
        ];
    }

    public function testNicknamesMayContainDigitsButRealNamesMayNot()
    {
        $this->assertEquals(0, RegistrationGuard::gibberishScore('Smoke99', false), 'Nickname');
        $this->assertGreaterThan(0, RegistrationGuard::gibberishScore('Smoke99', true), 'Real name');
    }

    public function testScoreProfileFlagsAliasedAndFragmentedEmails()
    {
        $guard = RegistrationGuard::create();

        $aliased = $guard->scoreProfile(['Email' => 'a.b.c.d.e.f@gmail.com']);
        $this->assertGreaterThan(0, $aliased['score']);

        $clean = $guard->scoreProfile(['Email' => 'joe.madden@example.com', 'FirstName' => 'Joe', 'Surname' => 'Madden']);
        $this->assertEquals(0, $clean['score'], 'A perfectly ordinary profile must score nothing');
        $this->assertEmpty($clean['reasons']);
    }

    public function testSourceOptionsOverrideDefaults()
    {
        Config::modify()->set(RegistrationGuard::class, 'sources', [
            'sweeps' => ['min_form_seconds' => 3],
        ]);

        $this->assertEquals(3, RegistrationGuard::option('min_form_seconds', 'sweeps'));
        // Unset in the source, so it falls through to the default.
        $this->assertEquals(7200, RegistrationGuard::option('max_form_seconds', 'sweeps'));
        // An unknown source is not an error, it is just defaults.
        $this->assertEquals(5, RegistrationGuard::option('min_form_seconds', 'nosuchsource'));
    }

    /**
     * A "required" class or attribute on either guard field makes frontend validators demand the
     * honeypot be filled, which blocks every genuine submission. Silent and total.
     */
    public function testGuardFieldsAreNeverMarkedRequired()
    {
        foreach (RegistrationGuard::guardFields() as $field) {
            $html = (string) $field->FieldHolder();

            $this->assertStringNotContainsString('required', $html, $field->getName() . ' must not look required');
        }
    }

    public function testHoneypotFieldIsHiddenAndEmpty()
    {
        $field = RegistrationGuard::honeypotField();

        $this->assertEquals('RgWebsite', $field->getName());
        $this->assertEquals('', $field->dataValue());
        $this->assertStringContainsString('-9999px', (string) $field->getAttribute('style'));
        $this->assertEquals('off', $field->getAttribute('autocomplete'));
        $this->assertEquals('-1', $field->getAttribute('tabindex'));
    }
}
