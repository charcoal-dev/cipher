<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Support;

use Charcoal\Cipher\Cipher;
use Charcoal\Contracts\Security\Secrets\SecretKeyInterface;
use Charcoal\Security\Secrets\Support\SecretKeyRef;

/**
 * Simple VO for cipher algo + security key reference.
 * @api
 */
final readonly class CipherKeyRef
{
    public function __construct(
        public Cipher                          $algo,
        public SecretKeyRef|SecretKeyInterface $kid
    )
    {
    }

    /**
     * Returns new instance of self with $kid prop altered.
     * @api
     */
    public function withSecretKey(SecretKeyRef|SecretKeyInterface $kid): self
    {
        return new self($this->algo, $kid);
    }

    /**
     * @return array
     */
    public function __serialize(): array
    {
        return [
            "algo" => $this->algo,
            "kid" => $this->kid instanceof SecretKeyInterface ?
                new SecretKeyRef($this->kid->id(), $this->kid->version(), $this->kid->namespace, false) : $this->kid
        ];
    }

    /**
     * @param array $data
     * @return void
     */
    public function __unserialize(array $data): void
    {
        $this->algo = $data["algo"];
        $this->kid = $data["kid"];
    }
}