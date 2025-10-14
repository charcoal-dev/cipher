<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Exceptions;

/**
 * Enum CipherError
 * Represents error codes related to cryptographic operations.
 */
enum CipherError: int
{
    case ALGO_KEY_INCOMPATIBLE = 101;
    case ALGO_UNSUPPORTED = 102;

    /** @for=Encryption */
    case ENCRYPTION_OP_FAIL = 200;

    /** @for=Decryption */
    case DECRYPTION_OP_FAIL = 300;
    case ALGO_MISMATCH = 301;
    case KEY_MISMATCH = 302;
    case TAG_REQUIRED = 303;
}
