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

/**
 * Class Encrypted
 * @package Charcoal\Cipher
 */
class Encrypted
{
    /**
     * @param string $cipher
     * @param \Charcoal\Buffers\Buffer $bytes
     * @param \Charcoal\Buffers\Frames\Bytes16 $iv
     * @param bool $zeroPadding
     * @param \Charcoal\Buffers\Frames\Bytes16|null $tag
     */
    public function __construct(
        public readonly string   $cipher,
        public readonly Buffer   $bytes,
        public readonly Bytes16  $iv,
        public readonly bool     $zeroPadding,
        public readonly ?Bytes16 $tag = null,
    )
    {
    }
}

