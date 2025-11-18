<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Tests;

use Charcoal\Cipher\Cipher;
use Charcoal\Cipher\Encrypted\EncryptedObject;
use Charcoal\Cipher\Encrypted\EncryptedString;
use Charcoal\Cipher\Tests\Fixtures\CustomUserEntity;
use Charcoal\Cipher\Tests\Fixtures\CustomUserParams;
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
        $stringThree = "\0One more with Additional Authenticated Data!\r\n";

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

        $encryptedThree = Cipher::AES_256_GCM->encrypt($key, $stringThree, aad: "some_aad3");
        $this->assertInstanceOf(EncryptedString::class, $encryptedThree);
        $this->assertEquals(12, strlen($encryptedThree->iv()));
        $this->assertEquals(16, strlen($encryptedThree->tag() ?? ""));
        $this->assertEquals(strlen($encryptedThree->ciphertext()), strlen($stringThree));
        $decryptedThree = Cipher::AES_256_GCM->decrypt($key, $encryptedThree, aad: "some_aad3");
        $this->assertEquals($stringThree, $decryptedThree);
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

    /**
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function testUserEntityObjectEncryption_Aes256()
    {
        $secrets = new SecretsDirectory(LfsSecrets::Tests);
        $key = $secrets->load("test_secret", 1);

        $user = new CustomUserEntity(1, "charcoal", new CustomUserParams("prosperity", "happiness"));
        $encrypted = Cipher::AES_256_GCM->encrypt($key, $user);
        $this->assertInstanceOf(EncryptedString::class, $encrypted);
        $decrypted = Cipher::AES_256_GCM->decrypt($key, $encrypted);
        $this->assertInstanceOf(CustomUserEntity::class, $decrypted);
        $this->assertNotEquals(spl_object_id($user), spl_object_id($decrypted));
        $this->assertEquals(1, $decrypted->id);
        $this->assertEquals("charcoal", $decrypted->username);
        $this->assertEquals("prosperity", $decrypted->params->a1);
        $this->assertEquals("happiness", $decrypted->params->b2);
    }

    /**
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function testUserEntityObjectEncryption_Chacha20Poly1305()
    {
        $secrets = new SecretsDirectory(LfsSecrets::Tests);
        $key = $secrets->load("test_secret", 1);

        $user = new CustomUserEntity(7, "furqansiddiqui", new CustomUserParams("resilient", "driven"));
        $encrypted = Cipher::ChaCha20_Poly1305->encrypt($key, $user);
        $this->assertInstanceOf(EncryptedString::class, $encrypted);
        $decrypted = Cipher::ChaCha20_Poly1305->decrypt($key, $encrypted, unserializeAllowedFqcn: [
            CustomUserEntity::class,
            CustomUserParams::class,
        ]);
        $this->assertInstanceOf(CustomUserEntity::class, $decrypted);
        $this->assertNotEquals(spl_object_id($user), spl_object_id($decrypted));
        $this->assertEquals(7, $decrypted->id);
        $this->assertEquals("furqansiddiqui", $decrypted->username);
        $this->assertEquals("resilient", $decrypted->params->a1);
        $this->assertEquals("driven", $decrypted->params->b2);
    }

    /**
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function testDecryptionOnly_Object()
    {
        $secrets = new SecretsDirectory(LfsSecrets::Tests);
        $key = $secrets->load("test_secret", 1);

        $envelope = new EncryptedObject(
            Cipher::ChaCha20_Poly1305,
            hex2bin("7211a527b2359efed5d872847ad0d277b9cd22cb1430fcf3ea9ec03900d38a0bd24bd73d276a3b911cab900" .
                "c18a97d70b302e4fda2bb94691f5bda4bc377a4776da58f2bb3b2e788917b2d0e718c2ce36be9c7db550fddcc28" .
                "a181702beebe7417129edf4668dd69b8c0f46c8cd399a3dddeaed1aedac04d1e2ac2486a0fe0427f3179f8690c4" .
                "ca10010b8781dcbd91b57de54d7a5e72e79734630d23e3e0a79daa1404fc94a1191134f2b70909db7eb02045bdd" .
                "97c62ac3030f3644975e85d1f8211b97f3915c4ff2672ebdc0a4a989c9b80a2b40279da18e54863680081e401ea" .
                "50b48ee5f"),
            hex2bin("6f582b550e3efac579827fd3"),
            hex2bin("739404bd62fda2032c1ec133d2e388cc"),
            fqcn: CustomUserEntity::class
        );

        $decrypted = Cipher::ChaCha20_Poly1305->decrypt($key, $envelope);
        $this->assertInstanceOf(CustomUserEntity::class, $decrypted);
        $this->assertEquals(93891, $decrypted->id);
        $this->assertEquals("liavackb.betq", $decrypted->username);
        $this->assertEquals("poajjfsa", $decrypted->params->a1);
        $this->assertEquals("thxbmi", $decrypted->params->b2);
    }
}
