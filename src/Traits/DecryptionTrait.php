<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Traits;

use Charcoal\Cipher\Exceptions\CipherError;
use Charcoal\Cipher\Exceptions\CipherException;
use Charcoal\Cipher\Providers\OpenSSL;
use Charcoal\Contracts\Security\Cipher\CipherAlgorithmInterface;
use Charcoal\Contracts\Security\Cipher\CipherProviderInterface;
use Charcoal\Contracts\Security\Encrypted\EncryptedObjectInterface;
use Charcoal\Contracts\Security\Encrypted\EncryptedStringInterface;
use Charcoal\Contracts\Security\Secrets\SecretKeyInterface;

/**
 * Trait with decryption methods for CipherAlgorithmInterface.
 * @mixin CipherAlgorithmInterface
 */
trait DecryptionTrait
{
    /**
     * @throws CipherException
     */
    public function decrypt(
        #[\SensitiveParameter]
        SecretKeyInterface       $key,
        EncryptedStringInterface $encrypted,
        ?string                  $aad = null,
        ?CipherProviderInterface $provider = null,
        ?array                   $unserializeAllowedFqcn = []
    ): string|object
    {
        if ($encrypted->algo()->algo() !== $this->algo()) {
            throw new CipherException(CipherError::ALGO_MISMATCH, "Cipher algorithm mismatch");
        }

        if ($encrypted->kid() && $encrypted->kid() !== $key->ref()) {
            throw new CipherException(CipherError::KEY_MISMATCH, "Cipher key mismatch");
        }

        $provider = $provider ?? OpenSSL::getInstance();
        $payload = $provider->decrypt($key, $encrypted, $aad);
        if ($encrypted instanceof EncryptedObjectInterface || $unserializeAllowedFqcn) {
            return unserialize($payload, $unserializeAllowedFqcn ?
                ["allowed_classes" => $unserializeAllowedFqcn] : []);
        }

        return $payload;
    }
}