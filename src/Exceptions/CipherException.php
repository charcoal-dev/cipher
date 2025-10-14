<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Exceptions;

/**
 * Represents an exception that is specific to cipher operations.
 *
 * This exception is used to encapsulate an error related to cryptographic operations,
 * providing additional context such as a specific error type and optional data for
 * debugging or further handling.
 *
 * @property-read CipherError $error The specific cipher error associated with this exception.
 * @property-read array $data Additional data providing context about the error.
 */
class CipherException extends \Exception
{
    public function __construct(
        public readonly CipherError $error,
        string                      $message = "",
        public readonly array       $data = [],
        ?\Throwable                 $previous = null
    )
    {
        parent::__construct($message, $this->error->value, $previous);
    }
}

