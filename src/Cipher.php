<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher;

use Charcoal\Buffers\Buffer;
use Charcoal\Buffers\BufferImmutable;
use Charcoal\Buffers\Types\Bytes16;
use Charcoal\Buffers\Types\Bytes20;
use Charcoal\Buffers\Types\Bytes32;
use Charcoal\Cipher\Exceptions\CipherError;
use Charcoal\Cipher\Exceptions\CipherException;
use Charcoal\Contracts\Buffers\ReadableBufferInterface;

/**
 * Class Cipher
 * @package Charcoal\Cipher
 */
class Cipher implements CipherInterface
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
        $this->entropy = $key->bytes();
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
        $iv = Bytes16::fromPrng();
        $mode = $mode ?? $this->mode;
        $value = $plainString ? $value : serialize($value instanceof SerializedContainer ?
            $value : new SerializedContainer($value));
        $encrypted = openssl_encrypt(
            $value,
            $mode->getCipherAlgo($this->bitLen),
            $this->entropy,
            $options,
            $iv->bytes(),
            $tag,
            tag_length: 16
        );

        if (!$encrypted) {
            throw new CipherException(CipherError::ENCRYPTION_OP_FAIL);
        }

        return new EncryptedEntity(new Buffer($encrypted), $iv,
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
    ): BufferImmutable
    {
        return $this->encrypt($value, $mode, $zeroPadding, $plainString)
            ->serialize();
    }

    /**
     * @throws CipherException
     */
    public function decrypt(
        ReadableBufferInterface $encrypted,
        Bytes16                 $iv,
        ?Bytes16                $tag = null,
        ?CipherMode             $mode = null,
        bool                    $zeroPadding = false,
        bool                    $plainString = false,
        ?array                  $allowedClasses = null,
    ): mixed
    {
        $options = $zeroPadding ? OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING : OPENSSL_RAW_DATA;
        $mode = $mode ?? $this->mode;
        if (!$tag && $mode->requiresTag()) {
            throw new CipherException(CipherError::TAG_REQUIRED);
        }

        $decrypted = openssl_decrypt(
            $encrypted->bytes(),
            $mode->getCipherAlgo($this->bitLen),
            $this->entropy,
            $options,
            $iv->bytes(),
            $tag?->bytes(),
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
        ReadableBufferInterface|EncryptedEntity $buffer,
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
     * @param string $algo
     * @param string $raw
     * @return ReadableBufferInterface
     */
    private function digestResultFrame(string $algo, string $raw): ReadableBufferInterface
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