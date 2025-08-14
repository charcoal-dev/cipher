<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Tests\Fixture;

class CustomUserEntity
{
    public function __construct(
        public readonly int     $id,
        public readonly string  $username,
        public CustomUserParams $params,
    )
    {
    }
}