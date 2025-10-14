<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Internal;

use Charcoal\Cipher\Encrypted\EncryptedObject;
use Charcoal\Cipher\Encrypted\EncryptedString;
use Charcoal\Contracts\Security\Cipher\CipherAlgorithmInterface;
use Charcoal\Contracts\Security\Cipher\CipherEnvelopeInterface;
use Random\RandomException;

/**
 * @internal
 */
final readonly class EncryptionEnvelope implements CipherEnvelopeInterface
{
    public string $subject;
    public string $ivBytes;
    public ?string $ref;
    public ?int $version;
    public ?string $objectFqcn;

    /**
     * Private constructor for creating an instance of the EncryptionEnvelope.
     */
    public function __construct(
        public CipherAlgorithmInterface $algo,
        string|object                   $subject,
        ?string                         $ref = null,
        int                             $version = 0,
    )
    {
        // Resolve entity/subject from type
        if (is_object($subject)) {
            $this->objectFqcn = get_class($subject);
            $this->subject = serialize($subject);
        } else {
            $this->objectFqcn = null;
            $this->subject = $subject;
        }

        // Set reference id and version for encryption entity
        $this->ref = $ref;
        $this->version = max(0, $version);

        // Generate IV Bytes
        try {
            $this->ivBytes = random_bytes($algo->ivLength());
        } catch (RandomException $e) {
            throw new \RuntimeException("Failed to generate IV for cipher algorithm", previous: $e);
        }
    }

    /**
     * Returns an instance of EncryptedString with the provided cipher text, tag bytes, and key reference.
     */
    public function toEncrypted(
        string  $cipherText,
        ?string $tagBytes = null,
        ?string $keyRef = null,
    ): EncryptedString
    {
        return $this->objectFqcn ?
            new EncryptedString(
                $this->algo,
                $cipherText,
                $this->ivBytes,
                $tagBytes,
                $this->ref,
                $this->version,
                $keyRef) :
            new EncryptedObject(
                $this->algo,
                $cipherText,
                $this->ivBytes,
                $tagBytes,
                $this->ref,
                $this->version,
                $keyRef,
                $this->objectFqcn
            );
    }

    /**
     * Returns the algorithm used for encryption.
     */
    public function algo(): CipherAlgorithmInterface
    {
        return $this->algo;
    }

    /**
     * Returns the payload of the encryption envelope.
     */
    public function payload(): string
    {
        return $this->subject;
    }

    /**
     * Returns the initialization vector bytes.
     */
    public function iv(): string
    {
        return $this->ivBytes;
    }
}