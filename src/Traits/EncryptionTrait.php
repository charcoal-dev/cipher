<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Traits;

use Charcoal\Cipher\Internal\EncryptionEnvelope;
use Charcoal\Cipher\Providers\OpenSSL;
use Charcoal\Contracts\Security\Cipher\CipherAlgorithmInterface;
use Charcoal\Contracts\Security\Cipher\CipherProviderInterface;
use Charcoal\Contracts\Security\Encrypted\EncryptedStringInterface;
use Charcoal\Contracts\Security\Secrets\SecretKeyInterface;

/**
 * Trait with encryption methods for CipherAlgorithmInterface.
 * @mixin CipherAlgorithmInterface
 */
trait EncryptionTrait
{
    /**
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function encrypt(
        #[\SensitiveParameter]
        SecretKeyInterface       $key,
        string|object            $entity,
        ?string                  $ref = null,
        int                      $version = 0,
        ?CipherProviderInterface $provider = null,
    ): EncryptedStringInterface
    {
        $provider = $provider ?? OpenSSL::getInstance();
        $envelope = new EncryptionEnvelope($this, $entity, $ref, $version);
        return $provider->encrypt($key, $envelope);
    }
}