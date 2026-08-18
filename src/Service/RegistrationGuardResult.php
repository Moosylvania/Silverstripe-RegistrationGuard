<?php

namespace Moosylvania\RegistrationGuard\Service;

use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Validation\ValidationResult;
use SilverStripe\Forms\Form;

/**
 * Outcome of a RegistrationGuard::check().
 *
 * Field errors are user-fixable and shown against the field. Blocks are spam and only ever produce a
 * single generic message, so nothing is given away about which rule fired - the reasons go to the log,
 * never to the browser.
 */
class RegistrationGuardResult
{
    use Injectable;

    /**
     * @var bool
     */
    protected $blocked = false;

    /**
     * @var int
     */
    protected $score = 0;

    /**
     * @var string[]
     */
    protected $reasons = [];

    /**
     * @var array [field => ['message' => string, 'formMessage' => string, 'html' => bool]]
     */
    protected $fieldErrors = [];

    /**
     * @var string|null
     */
    protected $blockMessage;

    /**
     * @var int
     */
    protected $secondsOnForm = -1;

    /**
     * @var string|null
     */
    protected $source;

    /**
     * @param string $reason Logged, never shown
     * @param string|null $message Overrides the generic block message
     */
    public function block($reason, $message = null)
    {
        $this->blocked = true;
        $this->reasons[] = $reason;
        if ($message !== null) {
            $this->blockMessage = $message;
        }
        return $this;
    }

    public function addScore($score, array $reasons = [])
    {
        $this->score += (int) $score;
        foreach ($reasons as $reason) {
            $this->reasons[] = $reason;
        }
        return $this;
    }

    /**
     * @param string $field Form field name
     * @param string $message Shown against the field
     * @param string $formMessage Shown at the top of the form
     * @param bool $html Whether both messages contain markup
     */
    public function addFieldError($field, $message, $formMessage, $html = false)
    {
        $this->fieldErrors[$field] = [
            'message' => $message,
            'formMessage' => $formMessage,
            'html' => (bool) $html,
        ];
        return $this;
    }

    public function setBlocked($blocked)
    {
        $this->blocked = (bool) $blocked;
        return $this;
    }

    public function isBlocked()
    {
        return $this->blocked;
    }

    public function getScore()
    {
        return $this->score;
    }

    public function getReasons()
    {
        return $this->reasons;
    }

    public function getFieldErrors()
    {
        return $this->fieldErrors;
    }

    public function getBlockMessage()
    {
        if ($this->blockMessage !== null) {
            return $this->blockMessage;
        }
        return RegistrationGuard::singleton()->genericError();
    }

    public function setSecondsOnForm($seconds)
    {
        $this->secondsOnForm = (int) $seconds;
        return $this;
    }

    public function getSecondsOnForm()
    {
        return $this->secondsOnForm;
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

    /**
     * Whether the submission must not proceed.
     */
    public function shouldStop()
    {
        return $this->blocked || !empty($this->fieldErrors);
    }

    /*
    |--------------------------------------------------------------------------
    | Surfacing
    |--------------------------------------------------------------------------
    */

    /**
     * Field errors, or a single generic message when blocked. Never both - a blocked submission must
     * not reveal which rule fired.
     *
     * @return ValidationResult
     */
    public function toValidationResult()
    {
        $validation = ValidationResult::create();

        if ($this->fieldErrors) {
            foreach ($this->fieldErrors as $field => $error) {
                $validation->addFieldError(
                    $field,
                    $error['message'],
                    ValidationResult::TYPE_ERROR,
                    // Empty string, not null: Silverstripe 6 types $code as string.
                    '',
                    $error['html'] ? ValidationResult::CAST_HTML : ValidationResult::CAST_TEXT
                );
            }
            return $validation;
        }

        $validation->addError($this->getBlockMessage(), ValidationResult::TYPE_ERROR);
        return $validation;
    }

    /**
     * Surface this result on a form, ready for a redirectBack().
     *
     *     $result = RegistrationGuard::create($this->getRequest())->check($data, 'members');
     *     if ($result->shouldStop()) {
     *         $result->applyTo($form);
     *         return $this->controller->redirectBack();
     *     }
     */
    public function applyTo(Form $form)
    {
        if ($this->fieldErrors) {
            foreach ($this->fieldErrors as $error) {
                $form->sessionMessage(
                    $error['formMessage'],
                    ValidationResult::TYPE_ERROR,
                    $error['html'] ? ValidationResult::CAST_HTML : ValidationResult::CAST_TEXT
                );
            }
            $form->setSessionValidationResult($this->toValidationResult(), true);
            return $this;
        }

        $form->sessionMessage($this->getBlockMessage(), ValidationResult::TYPE_ERROR);
        return $this;
    }
}
