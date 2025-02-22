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

use Charcoal\Buffers\AbstractByteArray;
use Charcoal\Buffers\Buffer;
use Charcoal\Buffers\Frames\Bytes16;
use Charcoal\Cipher\Exception\CipherError;
use Charcoal\Cipher\Exception\CipherException;

/**
 * Class Encrypted
 * @package Charcoal\Cipher
 */
class Encrypted
{
    /**
     * Expecting serialized buffer in following order:
     *  [IV][Ciphertext][Authentication Tag]
     * @param \Charcoal\Buffers\Buffer $buffer
     * @param bool $hasTag
     * @return static
     * @throws \Charcoal\Cipher\Exception\CipherException
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
     * @param \Charcoal\Buffers\Buffer $bytes
     * @param \Charcoal\Buffers\Frames\Bytes16 $iv
     * @param \Charcoal\Buffers\Frames\Bytes16|null $tag
     */
    public function __construct(
        public readonly Buffer   $bytes,
        public readonly Bytes16  $iv,
        public readonly ?Bytes16 $tag = null,
    )
    {
    }

    /**
     * Since there is any strict standard in existence, we are going to follow common practice of serializing
     * encrypted entity in following order:
     * [IV][Ciphertext][Authentication Tag]
     * @return \Charcoal\Buffers\Buffer
     */
    public function serialize(): Buffer
    {
        return $this->bytes->copy()->prepend($this->iv)->append($this->tag)->readOnly();
    }
}

