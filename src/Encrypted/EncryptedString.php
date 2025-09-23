<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Encrypted;

use Charcoal\Contracts\Encoding\EncodingSchemeStaticInterface;
use Charcoal\Contracts\Security\Cipher\CipherAlgorithmInterface;
use Charcoal\Contracts\Security\Encrypted\EncryptedStringInterface;
use Charcoal\Contracts\Security\Secrets\SecretKeyInterface;

/**
 * Represents an encrypted string, containing the ciphertext, initialization vector,
 * authentication tag (if applicable), and metadata related to the encryption.
 * Implements the EncryptedStringInterface and provides methods to access its properties
 * and encode the data to different formats.
 */
readonly class EncryptedString implements EncryptedStringInterface
{
    private ?string $keyRef;

    public function __construct(
        private CipherAlgorithmInterface $algo,
        private string                   $ciphertext,
        private string                   $iv,
        private ?string                  $tag,
        null|SecretKeyInterface|string   $keyRef,
    )
    {
        $this->keyRef = match (true) {
            $keyRef instanceof SecretKeyInterface => $keyRef->ref(),
            is_string($keyRef) => $keyRef,
            default => null,
        };
    }

    /**
     * Returns the algorithm used for encryption.
     */
    public function algo(): CipherAlgorithmInterface
    {
        return $this->algo;
    }

    /**
     * Returns the key reference.
     */
    public function kid(): string
    {
        return $this->keyRef;
    }

    /**
     * Returns the initialization vector.
     */
    public function iv(): string
    {
        return $this->iv;
    }

    /**
     * Returns the authentication tag (if supported by the algorithm, or NULL)
     */
    public function tag(): ?string
    {
        return $this->tag;
    }

    /**
     * Returns the ciphertext.
     */
    public function ciphertext(): string
    {
        return $this->ciphertext;
    }

    /**
     * Returns the encoded string.
     */
    public function encodeDto(
        EncodingSchemeStaticInterface $encoding,
        string                        $algo = "algo",
        string                        $cipherText = "ciphertext",
        string                        $iv = "iv",
        ?string                       $tag = "tag",
        ?string                       $keyRef = null
    ): array
    {
        $dto = [];
        $dto[$algo] = $this->algo->algo();
        $dto[$cipherText] = $encoding->encode($this->ciphertext);
        $dto[$iv] = $encoding->encode($this->iv);
        $dto[$tag] = is_null($this->tag) ? null : $encoding->encode($this->tag);
        $dto[$keyRef] = $this->keyRef;
        return $dto;
    }

    /**
     * Returns the encoded string.
     */
    public function encodeString(
        EncodingSchemeStaticInterface $encoding,
        string                        $tpl = "{algo}{iv}{tag}{cipherText}{keyRef}"
    ): string
    {
        $dto = $this->encodeDto($encoding, "algo", "cipherText", "iv", "tag", "keyRef");
        return strtr($tpl, [
            "{algo}"       => $dto["algo"] ?? "",
            "{cipherText}" => $dto["cipherText"] ?? "",
            "{iv}"         => $dto["iv"] ?? "",
            "{tag}"        => $dto["tag"] ?? "",
            "{keyRef}"     => $dto["keyRef"] ?? "",
        ]);
    }
}