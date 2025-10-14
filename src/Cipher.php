<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher;

use Charcoal\Cipher\Traits\DecryptionTrait;
use Charcoal\Cipher\Traits\EncryptionTrait;
use Charcoal\Contracts\Security\Cipher\CipherAlgorithmInterface;

/**
 * Enum for symmetric AEAD (Authenticated Encryption with Associated Data) ciphers.
 */
enum Cipher: string implements CipherAlgorithmInterface
{
    case AES_256_GCM = "aes-256-gcm";
    case AES_192_GCM = "aes-192-gcm";
    case AES_128_GCM = "aes-128-gcm";
    case ChaCha20_Poly1305 = "chacha20-poly1305";

    use EncryptionTrait;
    use DecryptionTrait;

    /**
     * Returns the actual algorithm name for the cipher.
     */
    public function algo(): string
    {
        return $this->value;
    }

    /**
     * Returns the key size in bytes for the specified cipher algorithm.
     */
    public function keySize(): int
    {
        return match ($this) {
            self::AES_192_GCM => 24,
            self::AES_128_GCM => 16,
            self::AES_256_GCM,
            self::ChaCha20_Poly1305 => 32,
        };
    }

    /**
     * Returns the length of IV (initialization-vector) nonce for the specified cipher algo.
     */
    public function ivLength(): int
    {
        return 12;
    }


    /**
     * Returns the length of tag for the specified cipher algo where supported; Otherwise NULL.
     */
    public function tagLength(): ?int
    {
        return 16;
    }
}