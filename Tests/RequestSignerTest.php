<?php

namespace Ibrows\HmacBundle\Tests;

use Ibrows\HmacBundle\Security\Authentication\RequestSigner;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\HeaderBag;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

class RequestSignerTest extends TestCase
{


    public function testSetProvider(): void
    {
        $signer = new RequestSigner('TestProvider');
        static::assertEquals('TestProvider', $signer->getProvider());
    }


    public function testAddCustomHeader(): void
    {
        $headers = [
            'Custom1' => 'Value1',
            'CustomX' => 'ValueX',
            'Content-Type' => 'text/plain',
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
        ];

        $signer = new RequestSigner('TestProvider');
        $signer->addCustomHeader('Custom1');

        $request = new Request();
        $request->headers = new HeaderBag($headers);

        $messageParts = explode("\n", $signer->getMessage($request));

        $expected = [
            'GET',
            md5(''),
            'text/plain',
            'Fri, 19 Mar 1982 00:00:04 GMT',
            'custom1: Value1',
            '',
        ];

        static::assertEquals($expected, $messageParts);
    }

    public function testMissingContentType(): void
    {
        $this->expectException(CustomUserMessageAuthenticationException::class);
        $request = new Request();
        $signer = new RequestSigner('TestProvider');
        $signer->getContentType($request);
    }

    public function testMissingAuthorizationHeader(): void
    {
        $this->expectException(CustomUserMessageAuthenticationException::class);
        $signer = new RequestSigner('TestProvider');
        $signer->getSignature(new Request());
    }

    public function testInvalidAuthorizationHeader(): void
    {
        $this->expectException(CustomUserMessageAuthenticationException::class);
        $request = new Request();
        $request->headers->set('Authorization', 'invalid-header');

        $signer = new RequestSigner('TestProvider');
        $signer->getSignature($request);
    }

    public function testInvalidProvider(): void
    {
        $this->expectException(CustomUserMessageAuthenticationException::class);
        $request = new Request();
        $request->headers->set('Authorization', 'BadProvider 1:abcd');

        $signer = new RequestSigner('TestProvider');
        $signer->getSignature($request);
    }

    public function testMissingTimestampHeader(): void
    {
        $this->expectException(CustomUserMessageAuthenticationException::class);
        $request = new Request();
        $request->headers->set('Authorization', 'TestProvider 1:abcd');

        $signer = new RequestSigner('TestProvider');
        $signer->getSignature($request);
    }

    public function testInvalidSignature(): void
    {
        $this->expectException(CustomUserMessageAuthenticationException::class);
        $request = new Request();
        $request->headers->set('Authorization', 'Test 1:abcd');
        $request->headers->set('Date', 'bad-timestamp');

        $signer = new RequestSigner('Test');
        $signer->getSignature($request);
    }

    public static function provideSignature()
    {
        yield [
            [
                'Content-Type' => 'text/plain',
                'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
                'Authorization' => 'Test 1:abcd',
            ],
            'id' => '1',
            'sig' => 'abcd',
        ];
        yield [
            [
                'Content-Type' => 'text/plain',
                'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
                'Authorization' => 'Test //1:abcd',
            ],
            'id' => '//1',
            'sig' => 'abcd',
        ];
        yield [
            [
                'Content-Type' => 'text/plain',
                'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
                'Authorization' => 'Test 1::abcd',
            ],
            'id' => '1',
            'sig' => 'abcd',
            'invalid' => true,
        ];
        yield [
            [
                'Content-Type' => 'text/plain',
                'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
                'Authorization' => 'Test1:abcd',
            ],
            'id' => '1',
            'sig' => 'abcd',
            'invalid' => true,
        ];
    }

    /**
     * @dataProvider provideSignature
     */
    public function testSignature(array $headers, string $id, string $sig, bool $invalid = false): void
    {

        $request = new Request();
        $request->headers = new HeaderBag($headers);

        $signer = new RequestSigner('Test');
        if ($invalid) {
            $this->expectException(CustomUserMessageAuthenticationException::class);
        }
        $signature = $signer->getSignature($request);

        static::assertEquals($id, $signature->getId());
        static::assertEquals($sig, $signature->getSignature());
        static::assertEquals(strtotime($headers['Date']), $signature->getTimestamp());
    }

    public function testSignRequest(): void
    {
        $signer = new RequestSigner('Test');
        $signer->addCustomHeader('Custom1');

        $request = new Request();
        $request->headers = new HeaderBag([
            'Content-Type' => 'text/plain',
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Custom1' => 'Value1',
        ]);

        static::assertEquals('nv8dzi42F+Rh470oNSSbCpWYUds=', $signer->signRequest($request, 'secret-key'));
    }

    public function testgetAuthorization(): void
    {
        $signer = new RequestSigner('Test');
        $signer->addCustomHeader('Custom1');

        $request = new Request();
        $request->headers = new HeaderBag([
            'Content-Type' => 'text/plain',
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Custom1' => 'Value1',
        ]);

        $expected = 'Test 1:'.'nv8dzi42F+Rh470oNSSbCpWYUds=';
        static::assertEquals($expected, $signer->getAuthorization($request, '1', 'secret-key'));
    }
}
