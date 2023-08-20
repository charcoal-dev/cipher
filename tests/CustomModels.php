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

class CustomUserModel
{
    public function __construct(
        public readonly int     $id,
        public readonly string  $username,
        public CustomUserParams $params,
    )
    {
    }
}

class CustomUserParams
{
    public function __construct(
        public readonly string $a1,
        public readonly string $b2
    )
    {

    }
}
