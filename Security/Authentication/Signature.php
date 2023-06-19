<?php

namespace Ibrows\HmacBundle\Security\Authentication;

class Signature
{

    protected string $id;
    protected string $signature;
    protected int $timestamp;

    public function __construct(string $id, string $signature, int $timestamp)
    {
        $this->id = $id;
        $this->signature = $signature;
        $this->timestamp = $timestamp;
    }


    public function getId(): string
    {
        return $this->id;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }


    public function getTimestamp(): int
    {
        return $this->timestamp;
    }


    public function matches($signature): bool
    {
        return $this->signature === (string) $signature;
    }

    /**
     * @throws \InvalidArgumentException
     * @return int -1 = to old, 1 = to far, 0 = ok
     */
    public function compareTimestamp(int|string $expiry): int
    {
        // There is no expiry.
        if (!$expiry) {
            return 0;
        }

        // Is the request too old?
        $lowerLimit = $this->getExpiry($expiry, $this->timestamp);
        if (time() > $lowerLimit) {
            return -1;
        }

        // Is the request too far in the future?
        $upperLimit = $this->getExpiry($expiry, time());
        if ($this->timestamp > $upperLimit) {
            return 1;
        }

        // Timestamp is within the expected range.
        return 0;
    }


    public function __toString()
    {
        return $this->signature;
    }

    /**
     * @throws \InvalidArgumentException
     */
    protected function getExpiry(int|string $expiry, int $relativeTimestamp): int
    {
        if (!is_int($expiry)) {
            $expiry = strtotime($expiry, $relativeTimestamp);
            if (!$expiry) {
                throw new \InvalidArgumentException('Expiry not valid');
            }
        }

        return $expiry;
    }
}
