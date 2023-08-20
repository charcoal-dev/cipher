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

/**
 * Class CipherMethodTest
 */
class CipherMethodTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @return void
     */
    public function testOpenSSLAlgo(): void
    {
        $this->assertEquals("aes-256-cbc", \Charcoal\Cipher\CipherMethod::CBC->openSSLCipherAlgo(256));
        $this->assertEquals("aes-128-cbc", \Charcoal\Cipher\CipherMethod::CBC->openSSLCipherAlgo(128));
        $this->assertEquals("aes-256-gcm", \Charcoal\Cipher\CipherMethod::GCM->openSSLCipherAlgo(256));
        $this->assertEquals("aes-128-gcm", \Charcoal\Cipher\CipherMethod::GCM->openSSLCipherAlgo(128));
    }

    /**
     * @return void
     */
    public function testTagRequired(): void
    {
        $this->assertTrue(\Charcoal\Cipher\CipherMethod::GCM->requiresTag());
        $this->assertFalse(\Charcoal\Cipher\CipherMethod::CBC->requiresTag());
    }
}
