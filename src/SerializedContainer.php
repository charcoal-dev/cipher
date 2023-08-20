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

namespace Charcoal\Cipher;

use Charcoal\Cipher\Exception\CipherError;
use Charcoal\Cipher\Exception\CipherException;

/**
 * Class SerializedContainer
 * @package Charcoal\Cipher
 */
class SerializedContainer
{
    public readonly string $type;
    private string $data;

    /**
     * @param mixed $data
     * @throws \Charcoal\Cipher\Exception\CipherException
     */
    public function __construct(mixed $data)
    {
        $this->type = gettype($data);
        $this->data = match ($this->type) {
            "integer", "double", "string" => $data,
            "array", "object" => serialize($data),
            default => throw new CipherException(
                CipherError::INVALID_VALUE_TYPE,
                sprintf('Cannot encrypt value of type "%s"', $this->type),
                [$this->type]
            ),
        };
    }

    /**
     * @return array
     */
    public function __serialize(): array
    {
        return [
            "type" => $this->type,
            "data" => $this->data
        ];
    }

    /**
     * @param array $data
     */
    public function __unserialize(array $data): void
    {
        $this->type = $data["type"];
        $this->data = $data["data"];
    }

    /**
     * @param array|null $allowedClasses
     * @return mixed
     * @throws \Charcoal\Cipher\Exception\CipherException
     */
    public function getValue(?array $allowedClasses = null): mixed
    {
        switch ($this->type) {
            case "integer":
            case "double":
            case "string":
                return $this->data;
            case "array":
            case "object":
                $obj = unserialize($this->data, ["allowed_classes" => $allowedClasses ?? true]);
                if ($obj === false || gettype($obj) !== $this->type) {
                    throw new CipherException(CipherError::RETRIEVE_STORED_VALUE_TYPE, data: [$this->type, gettype($obj)]);
                }
                return $obj;
        }

        throw new \UnexpectedValueException(sprintf('%s encountered value of type "%s"', __METHOD__, $this->type));
    }
}
