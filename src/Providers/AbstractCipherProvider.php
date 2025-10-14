<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Providers;

use Charcoal\Cipher\Exceptions\CipherError;
use Charcoal\Cipher\Exceptions\CipherException;
use Charcoal\Contracts\Security\Cipher\CipherAlgorithmInterface;
use Charcoal\Contracts\Security\Cipher\CipherProviderInterface;
use Charcoal\Contracts\Security\Secrets\SecretKeyInterface;

/**
 * Abstract class representing a cipher provider.
 * Defines the base behavior for ensuring compatibility between cipher algorithms and secret keys.
 */
abstract class AbstractCipherProvider implements CipherProviderInterface
{
    /**
     * Returns true if the provider supports the given cipher algorithm.
     */
    abstract protected function isSupportedAlgo(CipherAlgorithmInterface $algo): bool;

    /**
     * @throws CipherException
     */
    final protected function ensureSupportedAlgo(CipherAlgorithmInterface $algo): static
    {
        if (!$this->isSupportedAlgo($algo)) {
            throw new CipherException(CipherError::ALGO_UNSUPPORTED,
                "Unsupported cipher algorithm: " . $algo->algo());
        }

        return $this;
    }

    /**
     * @throws CipherException
     */
    final protected function ensureKeyCompatibility(CipherAlgorithmInterface $algo, SecretKeyInterface $key): static
    {
        if ($algo->keySize() !== $key->length()) {
            throw new CipherException(CipherError::ALGO_KEY_INCOMPATIBLE,
                sprintf("Cipher algorithm %s requires a key of length %d, got %d",
                    strtoupper($algo->algo()),
                    $algo->keySize(),
                    $key->length()
                )
            );
        }

        return $this;
    }
}