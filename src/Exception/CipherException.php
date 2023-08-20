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

namespace Charcoal\Cipher\Exception;

/**
 * Class CipherException
 * @package Charcoal\Cipher\Exception
 */
class CipherException extends \Exception
{
    /**
     * @param \Charcoal\Cipher\Exception\CipherError $error
     * @param string $message
     * @param array $data
     * @param \Throwable|null $previous
     */
    public function __construct(
        public readonly CipherError $error,
        string                      $message = "",
        public readonly array       $data = [],
        ?\Throwable                 $previous = null)
    {
        parent::__construct($message, $this->error->value, $previous);
    }
}

