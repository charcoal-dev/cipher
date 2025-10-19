<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Support;

use Charcoal\Cipher\Cipher;
use Charcoal\Contracts\Security\Secrets\SecretKeyInterface;

/**
 * Simple VO for cipher algo + security key reference.
 * @api
 */
final readonly class CipherKeyRef
{
    public function __construct(
        public Cipher                    $algo,
        public string|SecretKeyInterface $kid
    )
    {
    }
}