<?php
/*
 * This file is a part of "charcoal-dev/cipher" package.
 * https://github.com/charcoal-dev/cipher
 *
 * Copyright (c) Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/charcoal-dev/cipher/blob/master/LICENSE
 */

declare(strict_types=1);

namespace Charcoal\Cipher;

use Charcoal\Buffers\Buffer;
use Charcoal\Buffers\Frames\Bytes16;
use Charcoal\Buffers\Frames\Bytes32;
use Charcoal\Cipher\Exception\CipherError;
use Charcoal\Cipher\Exception\CipherException;

/**
 * Class Cipher
 * @package Charcoal\Cipher
 */
class Cipher
{
    private string $keyBytes;
    private readonly int $keyBitLen;

    /**
     * @param \Charcoal\Buffers\Frames\Bytes16|\Charcoal\Buffers\Frames\Bytes32 $key
     * @param \Charcoal\Cipher\CipherMethod $defaultMode
     */
    public function __construct(
        Bytes16|Bytes32     $key,
        public CipherMethod $defaultMode = CipherMethod::CBC,
    )
    {
        $this->keyBitLen = $key->len() * 8;
        $this->keyBytes = $key->raw();
    }

    /**
     * @return string[]
     */
    final public function __debugInfo(): array
    {
        return [$this->keyBitLen . "-bit Cipher Key"];
    }

    /**
     * @param array $in
     * @return object
     */
    final public function __set_state(array $in): object
    {
        throw new \BadMethodCallException(get_called_class() . ' instance cannot be exported');
    }

    /**
     * @param mixed $value
     * @param \Charcoal\Cipher\CipherMethod|null $mode
     * @param bool|null $zeroPadding
     * @return \Charcoal\Cipher\Encrypted
     * @throws \Charcoal\Cipher\Exception\CipherException
     */
    public function encrypt(mixed $value, ?CipherMethod $mode = null, bool $zeroPadding = false): Encrypted
    {
        $options = $zeroPadding ? OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING : OPENSSL_RAW_DATA;
        $iv = Bytes16::fromRandomBytes();
        $mode = $mode ?? $this->defaultMode;
        $encrypted = openssl_encrypt(
            serialize(new SerializedContainer($value)),
            $mode->openSSLCipherAlgo($this->keyBitLen),
            $this->keyBytes,
            $options,
            $iv->raw(),
            $tag,
            tag_length: 16
        );

        if (!$encrypted) {
            throw new CipherException(CipherError::ENCRYPTION_OP_FAIL);
        }

        return new Encrypted((new Buffer($encrypted))->readOnly(), $iv, isset($tag) ? new Bytes16($tag) : null);
    }

    /**
     * @param mixed $value
     * @param \Charcoal\Cipher\CipherMethod|null $mode
     * @param bool $zeroPadding
     * @return \Charcoal\Buffers\Buffer
     * @throws \Charcoal\Cipher\Exception\CipherException
     */
    public function encryptSerialize(mixed $value, ?CipherMethod $mode = null, bool $zeroPadding = false): Buffer
    {
        return $this->encrypt($value, $mode, $zeroPadding)->serialize();
    }

    /**
     * @param \Charcoal\Buffers\Buffer $encrypted
     * @param \Charcoal\Buffers\Frames\Bytes16 $iv
     * @param \Charcoal\Buffers\Frames\Bytes16|null $tag
     * @param \Charcoal\Cipher\CipherMethod|null $mode
     * @param bool $zeroPadding
     * @param array|null $allowedClasses
     * @return mixed
     * @throws \Charcoal\Cipher\Exception\CipherException
     */
    public function decrypt(
        Buffer        $encrypted,
        Bytes16       $iv,
        ?Bytes16      $tag = null,
        ?CipherMethod $mode = null,
        bool          $zeroPadding = false,
        ?array        $allowedClasses = null,
    ): mixed
    {
        $options = $zeroPadding ? OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING : OPENSSL_RAW_DATA;
        $mode = $mode ?? $this->defaultMode;
        if (!$tag && $mode->requiresTag()) {
            throw new CipherException(CipherError::TAG_REQUIRED);
        }

        $decrypted = openssl_decrypt(
            $encrypted->raw(),
            $mode->openSSLCipherAlgo($this->keyBitLen),
            $this->keyBytes,
            $options,
            $iv->raw(),
            $tag?->raw(),
        );
        if (!$decrypted) {
            throw new CipherException(CipherError::DECRYPTION_OP_FAIL);
        }

        $object = unserialize($decrypted, ["allowed_classes" => [SerializedContainer::class]]);
        if (!$object instanceof SerializedContainer) {
            throw new CipherException(CipherError::RESTORE_SERIALIZED_CONTAINER);
        }

        return $object->getValue($allowedClasses);
    }

    /**
     * @param \Charcoal\Buffers\Buffer|\Charcoal\Cipher\Encrypted $buffer
     * @param \Charcoal\Cipher\CipherMethod|null $mode
     * @param bool $zeroPadding
     * @param array|null $allowedClasses
     * @return mixed
     * @throws \Charcoal\Cipher\Exception\CipherException
     */
    public function decryptSerialized(
        Buffer|Encrypted $buffer,
        ?CipherMethod    $mode = null,
        bool             $zeroPadding = false,
        ?array           $allowedClasses = null): mixed
    {
        $mode = $mode ?? $this->defaultMode;
        if (!$buffer instanceof Encrypted) {
            $buffer = Encrypted::Unserialize($buffer, $mode->requiresTag());
        }

        return $this->decrypt($buffer->bytes, $buffer->iv, $buffer->tag, $mode, $zeroPadding, $allowedClasses);
    }
}