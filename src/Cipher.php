<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher;

use Charcoal\Buffers\AbstractByteArray;
use Charcoal\Buffers\Buffer;
use Charcoal\Buffers\Frames\Bytes16;
use Charcoal\Buffers\Frames\Bytes20;
use Charcoal\Buffers\Frames\Bytes32;
use Charcoal\Cipher\Exceptions\CipherError;
use Charcoal\Cipher\Exceptions\CipherException;

/**
 * Class Cipher
 * @package Charcoal\Cipher
 */
class Cipher
{
    private string $entropy;
    public readonly int $bitLen;

    /**
     * @param Bytes16|Bytes32 $key
     * @param CipherMode $mode
     */
    public function __construct(
        Bytes16|Bytes32   $key,
        public CipherMode $mode = CipherMode::CBC,
    )
    {
        $this->entropy = $key->raw();
        $this->bitLen = strlen($this->entropy) * 8;
    }

    /**
     * @return string[]
     */
    final public function __debugInfo(): array
    {
        return [$this->bitLen . "-bit Cipher Key"];
    }

    /**
     * @param array $in
     * @return object
     */
    final public static function __set_state(array $in): object
    {
        throw new \BadMethodCallException(get_called_class() . ' instance cannot be exported');
    }

    /**
     * @return string
     */
    public function getPrivateKeyBytes(): string
    {
        return $this->entropy;
    }

    /**
     * @throws CipherException
     */
    public function deriveChildKey(string|AbstractByteArray $salt, int $iterations): static
    {
        $algo = match ($this->bitLen) {
            256 => "sha256",
            128 => "sha1"
        };

        /** @var Bytes16|Bytes32 $child */
        $child = $this->pbkdf2($algo, $salt instanceof AbstractByteArray ? $salt->raw() : $salt, $iterations);
        return new static($child);
    }

    /**
     * @throws CipherException
     */
    public function deriveMaskedKey(string $maskingKey): static
    {
        $maskBytes = [];
        $maskBytesCount = 0;
        for ($i = 0; $i < strlen($maskingKey); $i++) {
            $maskBytes[] = ord($maskingKey[$i]);
            $maskBytesCount++;
        }

        if ($maskBytesCount < 4) {
            throw new CipherException(CipherError::BAD_MASKING_KEY);
        }

        $masked = "";
        for ($i = 0; $i < strlen($this->entropy); $i++) {
            $masked .= chr(ord($this->entropy[$i]) ^ $maskBytes[$i % $maskBytesCount]);
        }

        $frame = match ($this->bitLen) {
            256 => Bytes32::class,
            128 => Bytes16::class
        };

        return new static(new $frame(substr($masked, -1 * $frame::SIZE)));
    }

    /**
     * @throws CipherException
     */
    public function encrypt(
        mixed       $value,
        ?CipherMode $mode = null,
        bool        $zeroPadding = false,
        bool        $plainString = false
    ): EncryptedEntity
    {
        $options = $zeroPadding ? OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING : OPENSSL_RAW_DATA;
        $iv = Bytes16::fromRandomBytes();
        $mode = $mode ?? $this->mode;
        $value = $plainString ? $value : serialize($value instanceof SerializedContainer ?
            $value : new SerializedContainer($value));
        $encrypted = openssl_encrypt(
            $value,
            $mode->getCipherAlgo($this->bitLen),
            $this->entropy,
            $options,
            $iv->raw(),
            $tag,
            tag_length: 16
        );

        if (!$encrypted) {
            throw new CipherException(CipherError::ENCRYPTION_OP_FAIL);
        }

        return new EncryptedEntity((new Buffer($encrypted))->readOnly(), $iv,
            isset($tag) ? new Bytes16($tag) : null);
    }

    /**
     * @throws CipherException
     */
    public function encryptSerialize(
        mixed       $value,
        ?CipherMode $mode = null,
        bool        $zeroPadding = false,
        bool        $plainString = false
    ): Buffer
    {
        return $this->encrypt($value, $mode, $zeroPadding, $plainString)
            ->serialize();
    }

    /**
     * @throws CipherException
     */
    public function decrypt(
        AbstractByteArray $encrypted,
        Bytes16           $iv,
        ?Bytes16          $tag = null,
        ?CipherMode       $mode = null,
        bool              $zeroPadding = false,
        bool              $plainString = false,
        ?array            $allowedClasses = null,
    ): mixed
    {
        $options = $zeroPadding ? OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING : OPENSSL_RAW_DATA;
        $mode = $mode ?? $this->mode;
        if (!$tag && $mode->requiresTag()) {
            throw new CipherException(CipherError::TAG_REQUIRED);
        }

        $decrypted = openssl_decrypt(
            $encrypted->raw(),
            $mode->getCipherAlgo($this->bitLen),
            $this->entropy,
            $options,
            $iv->raw(),
            $tag?->raw(),
        );
        if (!$decrypted) {
            throw new CipherException(CipherError::DECRYPTION_OP_FAIL);
        }

        if ($plainString) {
            return $decrypted;
        }

        $object = unserialize($decrypted, ["allowed_classes" => [SerializedContainer::class]]);
        if (!$object instanceof SerializedContainer) {
            throw new CipherException(CipherError::RESTORE_SERIALIZED_CONTAINER);
        }

        return $object->getValue($allowedClasses);
    }

    /**
     * @throws CipherException
     */
    public function decryptSerialized(
        AbstractByteArray|EncryptedEntity $buffer,
        ?CipherMode                       $mode = null,
        bool                              $zeroPadding = false,
        bool                              $plainString = false,
        ?array                            $allowedClasses = null
    ): mixed
    {
        $mode = $mode ?? $this->mode;
        if (!$buffer instanceof EncryptedEntity) {
            $buffer = EncryptedEntity::Unserialize($buffer, $mode->requiresTag());
        }

        return $this->decrypt($buffer->bytes, $buffer->iv, $buffer->tag,
            $mode, $zeroPadding, $plainString, $allowedClasses);
    }

    /**
     * @throws CipherException
     */
    public function hmac(string $algo, string|AbstractByteArray $data): AbstractByteArray
    {
        try {
            return $this->digestResultFrame(
                $algo,
                hash_hmac($algo, $data instanceof AbstractByteArray ?
                    $data->raw() : $data, $this->entropy, true)
            );
        } catch (\Exception) {
            throw new CipherException(CipherError::HMAC_COMPUTE_FAIL);
        }
    }

    /**
     * @throws CipherException
     */
    public function pbkdf2(string $algo, string|AbstractByteArray $data, int $iterations): AbstractByteArray
    {
        try {
            return $this->digestResultFrame(
                $algo,
                hash_pbkdf2(
                    $algo,
                    $data instanceof AbstractByteArray ? $data->raw() : $data,
                    $this->entropy,
                    $iterations,
                    0,
                    true
                )
            );
        } catch (\Exception) {
            throw new CipherException(CipherError::PBKDF2_COMPUTE_FAIL);
        }
    }

    /**
     * @param string $algo
     * @param string $raw
     * @return AbstractByteArray
     */
    private function digestResultFrame(string $algo, string $raw): AbstractByteArray
    {
        $class = match (strtolower($algo)) {
            "md5" => Bytes16::class,
            "sha1", "ripemd160" => Bytes20::class,
            "sha256" => Bytes32::class,
            default => Buffer::class,
        };

        return new $class($raw);
    }
}