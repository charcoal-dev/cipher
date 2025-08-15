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
    case INVALID_VALUE_TYPE = 0x64;
    case ENCRYPTION_OP_FAIL = 0xc8;
    case TAG_REQUIRED = 0x12c;
    case DECRYPTION_OP_FAIL = 0x190;
    case RESTORE_SERIALIZED_CONTAINER = 0x1f4;
    case RETRIEVE_STORED_VALUE_TYPE = 0x258;
    case INCOMPLETE_SERIALIZED_BUFFER = 0x2bc;
    case HMAC_COMPUTE_FAIL = 0x320;
    case PBKDF2_COMPUTE_FAIL = 0x384;
    case BAD_MASKING_KEY = 0x3e8;
}
