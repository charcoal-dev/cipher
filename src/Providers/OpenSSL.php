<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Providers;

use Charcoal\Base\Objects\Traits\InstanceOnStaticScopeTrait;
use Charcoal\Base\Support\ErrorHelper;
use Charcoal\Cipher\Cipher;
use Charcoal\Cipher\Exceptions\CipherError;
use Charcoal\Cipher\Exceptions\CipherException;
use Charcoal\Cipher\Internal\EncryptionResult;
use Charcoal\Contracts\Security\Cipher\CipherAlgorithmInterface;
use Charcoal\Contracts\Security\Cipher\CipherEnvelopeInterface;
use Charcoal\Contracts\Security\Encrypted\EncryptedStringInterface;
use Charcoal\Contracts\Security\Secrets\SecretKeyInterface;

/**
 * Provides an implementation of the CipherProviderInterface using OpenSSL for cryptographic operations.
 */
final class OpenSSL extends AbstractCipherProvider
{
    use InstanceOnStaticScopeTrait;

    /**
     * @return self
     */
    public static function getInstance(): self
    {
        if (!isset(self::$instance)) {
            self::initialize();
        }

        return self::$instance;
    }

    /**
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function encrypt(
        #[\SensitiveParameter]
        SecretKeyInterface      $key,
        CipherEnvelopeInterface $envelope,
        ?string                 $aad = null
    ): EncryptedStringInterface
    {
        if (!$envelope->payload()) {
            throw new \InvalidArgumentException("Cipher envelope payload cannot be empty");
        }

        $algo = $envelope->algo();
        $this->ensureSupportedAlgo($algo)
            ->ensureKeyCompatibility($algo, $key);

        /** @var EncryptionResult $encrypted */
        $encrypted = $key->useSecretEntropy(
            function (string $key) use ($algo, $envelope, $aad) {
                return $this->encryptFromOpenSSL(
                    $algo->algo(),
                    $key,
                    $envelope->payload(),
                    $envelope->iv(),
                    min($algo->tagLength() ?? 0, 16),
                    $aad
                );
            },
        );

        return $envelope->toEncrypted($encrypted->ciphertext, $encrypted->tag, $key->ref());
    }

    /**
     * @throws CipherException
     */
    public function decrypt(
        #[\SensitiveParameter]
        SecretKeyInterface       $key,
        EncryptedStringInterface $encrypted,
        ?string                  $aad = null
    ): string
    {
        if (!$encrypted->ciphertext()) {
            throw new \InvalidArgumentException("Cipher envelope ciphertext cannot be empty");
        }

        $algo = $encrypted->algo();
        $this->ensureSupportedAlgo($algo)
            ->ensureKeyCompatibility($algo, $key);

        if (!$encrypted->tag() && $algo->tagLength() > 0) {
            throw new CipherException(CipherError::TAG_REQUIRED);
        }

        return $key->useSecretEntropy(
            function (string $key) use ($algo, $encrypted, $aad) {
                return $this->decryptFromOpenSSL(
                    $algo->algo(),
                    $key,
                    $encrypted->ciphertext(),
                    $encrypted->iv(),
                    $encrypted->tag(),
                    $aad
                );
            },
        );
    }

    /**
     * Determines whether a given cipher algorithm is supported.
     */
    protected function isSupportedAlgo(CipherAlgorithmInterface $algo): bool
    {
        return match ($algo) {
            Cipher::AES_128_GCM,
            Cipher::AES_192_GCM,
            Cipher::AES_256_GCM,
            Cipher::ChaCha20_Poly1305 => true,
            default => false,
        };
    }

    /**
     * Encrypts the given payload using openssl_encrypt().
     * @throws CipherException
     */
    protected function encryptFromOpenSSL(
        string  $algo,
        #[\SensitiveParameter]
        string  $key,
        string  $payload,
        string  $iv,
        int     $tagLength,
        ?string $aad
    ): EncryptionResult
    {
        $tag = null;
        error_clear_last();
        $ct = @openssl_encrypt($payload, $algo, $key, OPENSSL_RAW_DATA, $iv, $tag, $aad ?: "", $tagLength ?: 16);
        if (!$ct) {
            throw new CipherException(CipherError::ENCRYPTION_OP_FAIL,
                "OpenSSL encryption failed: " . openssl_error_string(),
                previous: ErrorHelper::lastErrorToRuntimeException());
        }

        return new EncryptionResult($ct, $tag ?: null);
    }

    /**
     * Decrypts the given ciphertext, iv & tag using openssl_decrypt().
     * @throws CipherException
     */
    protected function decryptFromOpenSSL(
        string  $algo,
        #[\SensitiveParameter]
        string  $key,
        string  $ciphertext,
        string  $iv,
        ?string $tag,
        ?string $aad,
    ): string
    {
        error_clear_last();
        $payload = @openssl_decrypt($ciphertext, $algo, $key, OPENSSL_RAW_DATA, $iv, $tag, $aad ?: "");
        if (!$payload) {
            throw new CipherException(CipherError::DECRYPTION_OP_FAIL,
                "OpenSSL decryption failed: " . openssl_error_string(),
                previous: ErrorHelper::lastErrorToRuntimeException());
        }

        return $payload;
    }
}