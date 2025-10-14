<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Exceptions;

/**
 * Class CipherError
 * @package Charcoal\Cipher\Exception
 */
enum CipherError: int
{
    case ALGO_KEY_INCOMPATIBLE = 100;
    case ALGO_UNSUPPORTED = 110;
    case ENCRYPTION_OP_FAIL = 200;
    case DECRYPTION_OP_FAIL = 300;
    case TAG_REQUIRED = 301;
}
