<?php

namespace Ibrows\HmacBundle\Tests;

use Ibrows\HmacBundle\Security\Authentication\Signature;
use PHPUnit\Framework\TestCase;

class SignatureTest extends TestCase
{

    public function getSignature(int $timestamp = null): Signature
    {
        $timestamp = $timestamp ?: time();
        return new Signature('1', 'test-signature', $timestamp);
    }

    public function testGetId(): void
    {
        $signature = $this->getSignature();
        static::assertEquals('1', $signature->getId());
    }

    public function testGetSignature(): void
    {
        $signature = $this->getSignature();
        static::assertEquals('test-signature', $signature->getSignature());
    }

    public function testToString(): void
    {
        $signature = $this->getSignature();
        static::assertEquals('test-signature', (string) $signature);
    }

    public function testGetTimestamp(): void
    {
        $signature = $this->getSignature(385344004);
        static::assertEquals(385344004, $signature->getTimestamp());
    }

    public function testSignatureMatches(): void
    {
        $signature = $this->getSignature(385344004);
        static::assertTrue($signature->matches('test-signature'));
    }

    public function testSignatureDoesNotMatch(): void
    {
        $signature = $this->getSignature(385344004);
        static::assertFalse($signature->matches('no-match'));
    }

    public function testInvalidExpiry(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $signature = $this->getSignature();
        $signature->compareTimestamp('a-bad-expiry');
    }

    public function testNoExpiry(): void
    {
        $signature = $this->getSignature(385344004);
        static::assertEquals(0, $signature->compareTimestamp(0));
    }

    public function testExpiredRequest(): void
    {
        // Threshold of 10 minutes, request 11 minutes old.
        $signature = $this->getSignature(strtotime('-11 minutes'));
        static::assertEquals(-1, $signature->compareTimestamp('10 minutes'));
    }

    public function testFutureRequest(): void
    {
        // Threshold of 10 minutes, request 11 minutes in the future.
        $signature = $this->getSignature(strtotime('+11 minutes'));
        static::assertEquals(1, $signature->compareTimestamp('10 minutes'));
    }

    public function testRequestWithinThreshold(): void
    {
        // Threshold of 10 minutes, request is current.
        $signature = $this->getSignature();
        static::assertEquals(0, $signature->compareTimestamp('10 minutes'));
    }
}
