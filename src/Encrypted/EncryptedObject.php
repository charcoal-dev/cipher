<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Encrypted;

use Charcoal\Contracts\Security\Cipher\CipherAlgorithmInterface;
use Charcoal\Contracts\Security\Encrypted\EncryptedObjectInterface;

/**
 * Represents an encrypted object encapsulating its associated encryption details and metadata.
 * Extends the EncryptedString class and implements the EncryptedObjectInterface interface.
 * Provides additional functionality specific to objects, including retrieval of the fully qualified class name (FQCN).
 */
readonly class EncryptedObject extends EncryptedString implements EncryptedObjectInterface
{
    public function __construct(
        CipherAlgorithmInterface $algo,
        string                   $ciphertext,
        string                   $iv,
        ?string                  $tag,
        ?string                  $ref = null,
        ?int                     $version = null,
        ?string                  $keyRef = null,
        private ?string          $fqcn = null,
    )
    {
        parent::__construct($algo, $ciphertext, $iv, $tag, $ref, $version, $keyRef);
    }

    /**
     * Returns the fully qualified class name (FQCN) of the encrypted object.
     */
    public function fqcn(): string
    {
        return $this->fqcn;
    }
}