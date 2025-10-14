<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Internal;

/**
 * @internal
 */
final readonly class EncryptionResult
{
    public function __construct(
        public string  $ciphertext,
        public ?string $tag
    )
    {
    }
}