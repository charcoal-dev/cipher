<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Tests;

use Charcoal\Buffers\Frames\Bytes16;
use Charcoal\Buffers\Frames\Bytes32;
use Charcoal\Buffers\Frames\Bytes32P;
use Charcoal\Cipher\Cipher;
use Charcoal\Cipher\CipherMode;
use Charcoal\Cipher\EncryptedEntity;
use Charcoal\Cipher\Tests\Fixture\CustomUserEntity;
use Charcoal\Cipher\Tests\Fixture\CustomUserParams;

/**
 * Class CipherTest
 */
class CipherTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @return void
     */
    public function testKeysLength(): void
    {
        $cipher1 = new Cipher(new Bytes32(hash("sha256", "charcoal", true)));
        $cipher2 = new Cipher(new Bytes16(hash("md5", "charcoal", true)));

        $this->assertEquals(256, $cipher1->bitLen);
        $this->assertEquals(128, $cipher2->bitLen);
    }

    /**
     * @return void
     */
    public function testCipherWithPaddedKeys(): void
    {
        $paddedKey = new Bytes32P("charcoal");
        $this->assertEquals("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0charcoal", $paddedKey->raw());
        $cipher = new Cipher($paddedKey);
        $this->assertEquals(256, $cipher->bitLen);
    }

    /**
     * @return void
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function testSelfCircularEncryption1(): void
    {
        $cipher = new Cipher(
            Bytes32P::fromBase16("63686172636f616c"),
            CipherMode::GCM
        );

        $item = ["alpha", "beta" => 2];
        $jsonImage = json_encode($item);

        // CBC test
        $encrypted = $cipher->encrypt($item, CipherMode::CBC);
        $this->assertNull($encrypted->tag);
        $decrypted = $cipher->decrypt($encrypted->bytes, $encrypted->iv, $encrypted->tag, CipherMode::CBC);
        $this->assertEquals($jsonImage, json_encode($decrypted));

        // GCM test
        $encrypted2 = $cipher->encrypt($item, CipherMode::GCM);
        $this->assertInstanceOf(Bytes16::class, $encrypted2->tag);
        $decrypted2 = $cipher->decrypt($encrypted2->bytes, $encrypted2->iv, $encrypted2->tag);
        $this->assertEquals($jsonImage, json_encode($decrypted2));
    }

    /**
     * @return void
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function testGcmPlainString(): void
    {
        $cipher = new Cipher(
            Bytes32P::fromBase16("63686172636f616c"),
            CipherMode::GCM
        );

        $subject = "1234567890abcdef0987654321";
        $plainEncrypt = $cipher->encrypt($subject, plainString: true);
        $this->assertEquals(26, $plainEncrypt->bytes->len());
        $this->assertInstanceOf(Bytes16::class, $plainEncrypt->tag);
        $this->assertInstanceOf(Bytes16::class, $plainEncrypt->iv);

        $this->assertEquals($subject, $cipher->decryptSerialized($plainEncrypt, plainString: true));
    }

    /**
     * @return void
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function testSerialization1(): void
    {
        $cipher = new Cipher(
            Bytes32P::fromBase16("63686172636f616c")
        );

        $encrypted = $cipher->encryptSerialize("test-value", CipherMode::GCM);
        $decode1 = EncryptedEntity::Unserialize($encrypted, false);
        $this->assertInstanceOf(Bytes16::class, $decode1->iv);
        $this->assertNull($decode1->tag);
        unset($decode1);

        $decode2 = EncryptedEntity::Unserialize($encrypted, true);
        $this->assertInstanceOf(Bytes16::class, $decode2->iv);
        $this->assertInstanceOf(Bytes16::class, $decode2->tag);
        unset($decode2);
    }

    /**
     * @return void
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function testSerializeAndAllowedClassesCBC(): void
    {
        $this->testSerializeAndAllowedClasses(CipherMode::CBC);
    }

    /**
     * @return void
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function testSerializeAndAllowedClassesGCM(): void
    {
        $this->testSerializeAndAllowedClasses(CipherMode::GCM);
    }

    /**
     * @param CipherMode $mode
     * @return void
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    private function testSerializeAndAllowedClasses(CipherMode $mode): void
    {
        $cipher = new Cipher(
            new Bytes32(hash("sha256", "charcoal", true)),
            $mode
        );

        $user = new CustomUserEntity(551, "charcoal\0", new CustomUserParams("UAE", "LLC"));
        $encrypted = $cipher->encryptSerialize($user);
        unset($user);

        $model1 = $cipher->decryptSerialized($encrypted, allowedClasses: null);
        $this->assertInstanceOf(CustomUserEntity::class, $model1);
        unset($model1);

        $model2 = $cipher->decryptSerialized($encrypted, allowedClasses: []);
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $model2);
        unset($model2);

        $model3 = $cipher->decryptSerialized($encrypted, allowedClasses: [CustomUserEntity::class, CustomUserParams::class]);
        $this->assertInstanceOf(CustomUserEntity::class, $model3);
        $this->assertInstanceOf(CustomUserParams::class, $model3->params);
        $this->assertEquals("charcoal\0", $model3->username);
        unset($model3);

        $model4 = $cipher->decryptSerialized($encrypted, allowedClasses: [CustomUserParams::class]);
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $model4);
        unset($model4);

        // Expecting exception because PHP expects allowedClasses to declare all (top to bottom)
        $this->expectException(\TypeError::class);
        $model5 = $cipher->decryptSerialized($encrypted, allowedClasses: [CustomUserEntity::class]);
        unset($model5);
    }

    /**
     * @return void
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function testChildKeyDerivation(): void
    {
        $cipher = new Cipher(new Bytes32(hash("sha256", "charcoal", true)));
        $childKey1 = $cipher->deriveChildKey("some_deterministic_salt", 1500);
        $childKey2 = $cipher->deriveChildKey("some_deterministic_salt", 1501);
        $childKey3 = $cipher->deriveChildKey("some_deterministic", 1);

        $this->assertNotEquals($childKey1->getPrivateKeyBytes(), $childKey2->getPrivateKeyBytes());
        $this->assertNotEquals($childKey2->getPrivateKeyBytes(), $childKey3->getPrivateKeyBytes());
        $this->assertEquals($cipher->deriveChildKey("some_deterministic_salt", 1500)->getPrivateKeyBytes(),
            $childKey1->getPrivateKeyBytes());
    }

    /**
     * @return void
     * @throws \Charcoal\Cipher\Exceptions\CipherException
     */
    public function testMaskedKeyDerivation(): void
    {
        $cipher = new Cipher(new Bytes32(hash("sha256", "charcoal", true)));
        $masked1 = $cipher->deriveMaskedKey("some-test-salt");
        $masked2 = $cipher->deriveMaskedKey("another");
        $this->assertNotEquals($cipher->getPrivateKeyBytes(), $masked1->getPrivateKeyBytes());
        $this->assertNotEquals($masked1->getPrivateKeyBytes(), $masked2->getPrivateKeyBytes());
        $this->assertEquals($cipher->getPrivateKeyBytes(), $masked1->deriveMaskedKey("some-test-salt")->getPrivateKeyBytes());
    }
}
