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

/**
 * Class CipherMethod
 * @package Charcoal\Cipher
 */
enum CipherMethod
{
    case CBC;
    case GCM;

    /**
     * @param int $keySize
     * @return string
     */
    public function openSSLCipherAlgo(int $keySize): string
    {
        return match ($this) {
            self::CBC => "aes-" . $keySize . "-cbc",
            self::GCM => "aes-" . $keySize . "-gcm",
        };
    }

    /**
     * @return bool
     */
    public function requiresTag(): bool
    {
        return match ($this) {
            self::CBC => false,
            self::GCM => true,
        };
    }
}
