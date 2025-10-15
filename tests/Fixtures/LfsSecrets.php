<?php
/**
 * Part of the "charcoal-dev/cipher" package.
 * @link https://github.com/charcoal-dev/cipher
 */

declare(strict_types=1);

namespace Charcoal\Cipher\Tests\Fixtures;

use Charcoal\Security\Secrets\Contracts\SecretsProviderEnumInterface;
use Charcoal\Security\Secrets\Enums\KeySize;

enum LfsSecrets: string implements SecretsProviderEnumInterface
{
    case Tests = "Secrets";

    public function getId(): string
    {
        return $this->name;
    }

    public function resolvePath(): string
    {
        return __DIR__
            . DIRECTORY_SEPARATOR . $this->value;
    }

    public function getKeySize(): KeySize
    {
        return KeySize::Bytes32;
    }
}