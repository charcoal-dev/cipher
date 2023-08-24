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

require_once "CustomModels.php";

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
        $cipher1 = new \Charcoal\Cipher\Cipher(new \Charcoal\Buffers\Frames\Bytes32(hash("sha256", "charcoal", true)));
        $cipher2 = new \Charcoal\Cipher\Cipher(new \Charcoal\Buffers\Frames\Bytes16(hash("md5", "charcoal", true)));

        $this->assertEquals(256, $cipher1->keyBitLen);
        $this->assertEquals(128, $cipher2->keyBitLen);
    }

    /**
     * @return void
     */
    public function testCipherWithPaddedKeys(): void
    {
        $paddedKey = new \Charcoal\Buffers\Frames\Bytes32P("charcoal");
        $this->assertEquals("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0charcoal", $paddedKey->raw());
        $cipher = new \Charcoal\Cipher\Cipher($paddedKey);
        $this->assertEquals(256, $cipher->keyBitLen);
    }

    /**
     * @return void
     * @throws \Charcoal\Cipher\Exception\CipherException
     */
    public function testSelfCircularEncryption1(): void
    {
        $cipher = new \Charcoal\Cipher\Cipher(
            \Charcoal\Buffers\Frames\Bytes32P::fromBase16("63686172636f616c"),
            \Charcoal\Cipher\CipherMethod::GCM
        );

        $item = ["alpha", "beta" => 2];
        $jsonImage = json_encode($item);

        // CBC test
        $encrypted = $cipher->encrypt($item, \Charcoal\Cipher\CipherMethod::CBC);
        $this->assertNull($encrypted->tag);
        $decrypted = $cipher->decrypt($encrypted->bytes, $encrypted->iv, $encrypted->tag, \Charcoal\Cipher\CipherMethod::CBC);
        $this->assertEquals($jsonImage, json_encode($decrypted));

        // GCM test
        $encrypted2 = $cipher->encrypt($item, \Charcoal\Cipher\CipherMethod::GCM);
        $this->assertInstanceOf(\Charcoal\Buffers\Frames\Bytes16::class, $encrypted2->tag);
        $decrypted2 = $cipher->decrypt($encrypted2->bytes, $encrypted2->iv, $encrypted2->tag);
        $this->assertEquals($jsonImage, json_encode($decrypted2));
    }

    /**
     * @return void
     * @throws \Charcoal\Cipher\Exception\CipherException
     */
    public function testSerialization1(): void
    {
        $cipher = new \Charcoal\Cipher\Cipher(
            \Charcoal\Buffers\Frames\Bytes32P::fromBase16("63686172636f616c")
        );

        $encrypted = $cipher->encryptSerialize("test-value", \Charcoal\Cipher\CipherMethod::GCM);
        $decode1 = \Charcoal\Cipher\Encrypted::Unserialize($encrypted, false);
        $this->assertInstanceOf(\Charcoal\Buffers\Frames\Bytes16::class, $decode1->iv);
        $this->assertNull($decode1->tag);
        unset($decode1);

        $decode2 = \Charcoal\Cipher\Encrypted::Unserialize($encrypted, true);
        $this->assertInstanceOf(\Charcoal\Buffers\Frames\Bytes16::class, $decode2->iv);
        $this->assertInstanceOf(\Charcoal\Buffers\Frames\Bytes16::class, $decode2->tag);
        unset($decode2);
    }

    /**
     * @return void
     * @throws \Charcoal\Cipher\Exception\CipherException
     */
    public function testSerializeAndAllowedClassesCBC(): void
    {
        $this->testSerializeAndAllowedClasses(\Charcoal\Cipher\CipherMethod::CBC);
    }

    /**
     * @return void
     * @throws \Charcoal\Cipher\Exception\CipherException
     */
    public function testSerializeAndAllowedClassesGCM(): void
    {
        $this->testSerializeAndAllowedClasses(\Charcoal\Cipher\CipherMethod::GCM);
    }

    /**
     * @param \Charcoal\Cipher\CipherMethod $mode
     * @return void
     * @throws \Charcoal\Cipher\Exception\CipherException
     */
    private function testSerializeAndAllowedClasses(\Charcoal\Cipher\CipherMethod $mode): void
    {
        $cipher = new \Charcoal\Cipher\Cipher(
            new \Charcoal\Buffers\Frames\Bytes32(hash("sha256", "charcoal", true)),
            $mode
        );

        $user = new CustomUserModel(551, "charcoal\0", new CustomUserParams("UAE", "LLC"));
        $encrypted = $cipher->encryptSerialize($user);
        unset($user);

        $model1 = $cipher->decryptSerialized($encrypted, allowedClasses: null);
        $this->assertInstanceOf(CustomUserModel::class, $model1);
        unset($model1);

        $model2 = $cipher->decryptSerialized($encrypted, allowedClasses: []);
        $this->assertInstanceOf(__PHP_Incomplete_Class::class, $model2);
        unset($model2);

        $model3 = $cipher->decryptSerialized($encrypted, allowedClasses: [CustomUserModel::class, CustomUserParams::class]);
        $this->assertInstanceOf(CustomUserModel::class, $model3);
        $this->assertInstanceOf(CustomUserParams::class, $model3->params);
        $this->assertEquals("charcoal\0", $model3->username);
        unset($model3);

        $model4 = $cipher->decryptSerialized($encrypted, allowedClasses: [CustomUserParams::class]);
        $this->assertInstanceOf(__PHP_Incomplete_Class::class, $model4);
        unset($model4);

        // Expecting exception because PHP expects allowedClasses to declare all (top to bottom)
        $this->expectException(TypeError::class);
        $model5 = $cipher->decryptSerialized($encrypted, allowedClasses: [CustomUserModel::class]);
        unset($model5);
    }

    /**
     * @return void
     * @throws \Charcoal\Cipher\Exception\CipherException
     */
    public function testChildKeyDerivation(): void
    {
        $cipher = new \Charcoal\Cipher\Cipher(new \Charcoal\Buffers\Frames\Bytes32(hash("sha256", "charcoal", true)));
        $childKey1 = $cipher->deriveChildKey("some_deterministic_salt", 1500);
        $childKey2 = $cipher->deriveChildKey("some_deterministic_salt", 1501);
        $childKey3 = $cipher->deriveChildKey("some_deterministic", 1);

        $this->assertNotEquals($childKey1->getPrivateKeyBytes(), $childKey2->getPrivateKeyBytes());
        $this->assertNotEquals($childKey2->getPrivateKeyBytes(), $childKey3->getPrivateKeyBytes());
        $this->assertEquals($cipher->deriveChildKey("some_deterministic_salt", 1500)->getPrivateKeyBytes(), $childKey1->getPrivateKeyBytes());
    }

    /**
     * @return void
     * @throws \Charcoal\Cipher\Exception\CipherException
     */
    public function testMaskedKeyDerivation(): void
    {
        $cipher = new \Charcoal\Cipher\Cipher(new \Charcoal\Buffers\Frames\Bytes32(hash("sha256", "charcoal", true)));
        $masked1 = $cipher->deriveMaskedKey("some-test-salt");
        $masked2 = $cipher->deriveMaskedKey("another");
        $this->assertNotEquals($cipher->getPrivateKeyBytes(), $masked1->getPrivateKeyBytes());
        $this->assertNotEquals($masked1->getPrivateKeyBytes(), $masked2->getPrivateKeyBytes());
        $this->assertEquals($cipher->getPrivateKeyBytes(), $masked1->deriveMaskedKey("some-test-salt")->getPrivateKeyBytes());
    }
}
