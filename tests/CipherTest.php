<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Tests;

use Charcoal\Cipher\Cipher;
use Charcoal\Cipher\Encrypted\EncryptedString;
use Charcoal\Cipher\Tests\Fixtures\LfsSecrets;
use Charcoal\Security\Secrets\Filesystem\SecretsDirectory;
use PHPUnit\Framework\TestCase;

/**
 * Class CipherTest
 */
class CipherTest extends TestCase
{
    /**
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function testEncryptionPlainStrings(): void
    {
        $stringOne = "This is a test string!";
        $stringTwo = "\0This is another test string!\t\n";

        $secrets = new SecretsDirectory(LfsSecrets::Tests);
        $key = $secrets->load("test_secret", 1);

        $encryptedOne = Cipher::AES_256_GCM->encrypt($key, $stringOne);
        $this->assertInstanceOf(EncryptedString::class, $encryptedOne);
        $this->assertEquals(12, strlen($encryptedOne->iv()));
        $this->assertEquals(16, strlen($encryptedOne->tag() ?? ""));
        $this->assertEquals(strlen($encryptedOne->ciphertext()), strlen($stringOne));
        $decryptedOne = Cipher::AES_256_GCM->decrypt($key, $encryptedOne);
        $this->assertEquals($stringOne, $decryptedOne);

        $encryptedTwo = Cipher::AES_256_GCM->encrypt($key, $stringTwo);
        $this->assertInstanceOf(EncryptedString::class, $encryptedTwo);
        $this->assertEquals(12, strlen($encryptedTwo->iv()));
        $this->assertEquals(16, strlen($encryptedTwo->tag() ?? ""));
        $this->assertEquals(strlen($encryptedTwo->ciphertext()), strlen($stringTwo));
        $decryptedTwo = Cipher::AES_256_GCM->decrypt($key, $encryptedTwo);
        $this->assertEquals($stringTwo, $decryptedTwo);
    }

    /**
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function testDecryptionOnly()
    {
        $secrets = new SecretsDirectory(LfsSecrets::Tests);
        $key = $secrets->load("test_secret", 1);

        $envelope = new EncryptedString(
            Cipher::ChaCha20_Poly1305,
            hex2bin("6c6600f7a3d8b9c2830378c80ef685d9147b83732076deda9076d9a0fce8b7189a52af00dfb9a7c5a1ae8748"),
            hex2bin("82550ebb6b456dce35933335"),
            hex2bin("2910e0979341c3b56f3680119f3c6819")
        );

        $decrypted = Cipher::ChaCha20_Poly1305->decrypt($key, $envelope);
        $this->assertEquals("Vector-Δ: I bend but do not break; test me.", $decrypted);
    }
}
