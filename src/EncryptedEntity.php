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
use Charcoal\Cipher\Exception\CipherError;
use Charcoal\Cipher\Exception\CipherException;

/**
 * Class Encrypted
 * @package Charcoal\Cipher
 */
readonly class EncryptedEntity
{
    /**
     * @param AbstractByteArray $buffer [IV][Ciphertext][Authentication Tag]
     * @param bool $hasTag
     * @return static
     * @throws CipherException
     */
    public static function Unserialize(AbstractByteArray $buffer, bool $hasTag): static
    {
        try {
            $buffer = $buffer->read();
            $iv = new Bytes16($buffer->first(16));
            $encrypted = new Buffer($buffer->next($hasTag ? $buffer->bytesLeft() - 16 : $buffer->bytesLeft()));
            if ($hasTag) {
                $tag = new Bytes16($buffer->next(16));
            }
        } catch (\UnderflowException $e) {
            throw new CipherException(CipherError::INCOMPLETE_SERIALIZED_BUFFER, previous: $e);
        }

        return new static($encrypted, $iv, $tag ?? null);
    }

    /**
     * @param Buffer $bytes
     * @param Bytes16 $iv
     * @param Bytes16|null $tag
     */
    public function __construct(
        public Buffer   $bytes,
        public Bytes16  $iv,
        public ?Bytes16 $tag = null,
    )
    {
    }

    /**
     * [IV][Ciphertext][Authentication Tag]
     * @return \Charcoal\Buffers\Buffer
     */
    public function serialize(): Buffer
    {
        return $this->bytes->copy()->prepend($this->iv)->append($this->tag)->readOnly();
    }
}

