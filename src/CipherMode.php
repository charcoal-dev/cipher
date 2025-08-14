<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher;

/**
 * Class CipherMode
 * @package Charcoal\Cipher
 */
enum CipherMode
{
    case CBC;
    case GCM;

    /**
     * @param int $keySize
     * @return string
     */
    public function getCipherAlgo(int $keySize): string
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
