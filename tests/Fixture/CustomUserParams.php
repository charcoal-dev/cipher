<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Tests\Fixture;

readonly class CustomUserParams
{
    public function __construct(
        public string $a1,
        public string $b2
    )
    {
    }
}