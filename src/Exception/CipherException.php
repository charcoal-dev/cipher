<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Exception;

/**
 * Class CipherException
 * @package Charcoal\Cipher\Exception
 */
class CipherException extends \Exception
{
    /**
     * @param \Charcoal\Cipher\Exception\CipherError $error
     * @param string $message
     * @param array $data
     * @param \Throwable|null $previous
     */
    public function __construct(
        public readonly CipherError $error,
        string                      $message = "",
        public readonly array       $data = [],
        ?\Throwable                 $previous = null)
    {
        parent::__construct($message, $this->error->value, $previous);
    }
}

