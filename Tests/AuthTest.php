<?php

namespace Ibrows\HmacBundle\Tests;

use Ibrows\HmacBundle\Tests\app\AppKernel;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

class AuthTest extends WebTestCase
{
    protected static KernelBrowser $client;

    public function testAuth(): void
    {

        $url = '/api/company';
        $signature = 'abc';
        $provider = 'ibrows';
        $user = 'test';
        $serverHeader = ['HTTP_Authorization' => "$provider $user:$signature", 'HTTP_Content-Type' => 'json'];

        self::$client->request('GET', $url);
        $response = self::$client->getResponse();
        static::assertEquals(401, $response->getStatusCode());
        static::assertStringContainsString("401 Unauthorized", $response->getContent());

        self::$client->request('GET', $url, [], [], $serverHeader);
        $response = self::$client->getResponse();
        static::assertEquals(401, $response->getStatusCode());
        static::assertStringContainsString("Date header required", $response->getContent());

        $now = new \DateTime();
        $serverHeader['HTTP_Date'] = $now->format('c');
        self::$client->request('GET', $url, [], [], $serverHeader);
        $response = self::$client->getResponse();
        static::assertEquals(401, $response->getStatusCode());
        static::assertStringContainsString("Signature not valid", $response->getContent());

        $message = "GET\n".md5('')."\njson\n".$serverHeader['HTTP_Date']."\n\n/api/company";

        $secretKey = 'test';
        $digest = hash_hmac('sha1', $message, $secretKey, true);
        $signature = base64_encode($digest);

        $serverHeader['HTTP_Authorization'] = "$provider $user:$signature";
        self::$client->request('GET', $url, [], [], $serverHeader);
        $response = self::$client->getResponse();
        static::assertEquals(302, $response->getStatusCode());


    }


    protected function setUp(): void
    {
        parent::setUp();
        self::$client = self::createClient();
    }

    protected static function createKernel(array $options = []): KernelInterface
    {
        require_once __DIR__.'/app/AppKernel.php';

        return new AppKernel(
            'config/config.yml',
            'test',
            true
        );
    }

    protected function tearDown(): void
    {

    }
}
