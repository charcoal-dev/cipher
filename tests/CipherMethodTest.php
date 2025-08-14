<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Tests;

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
        $this->assertEquals("aes-256-cbc", \Charcoal\Cipher\CipherMode::CBC->getCipherAlgo(256));
        $this->assertEquals("aes-128-cbc", \Charcoal\Cipher\CipherMode::CBC->getCipherAlgo(128));
        $this->assertEquals("aes-256-gcm", \Charcoal\Cipher\CipherMode::GCM->getCipherAlgo(256));
        $this->assertEquals("aes-128-gcm", \Charcoal\Cipher\CipherMode::GCM->getCipherAlgo(128));
    }

    /**
     * @return void
     */
    public function testTagRequired(): void
    {
        $this->assertTrue(\Charcoal\Cipher\CipherMode::GCM->requiresTag());
        $this->assertFalse(\Charcoal\Cipher\CipherMode::CBC->requiresTag());
    }
}
