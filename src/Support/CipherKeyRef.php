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

    public function __serialize(): array
    {
        return [
            "algo" => $this->algo,
            "kid" => $this->kid->ref()
        ];
    }

    public function __unserialize(array $data): void
    {
        $this->algo = $data["algo"];
        $this->kid = $data["kid"];
    }
}