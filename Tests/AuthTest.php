<?php

namespace Ibrows\HmacBundle\Tests;

use Doctrine\ORM\Query;
use Ibrows\HmacBundle\Tests\app\AppKernel;
use Symfony\Bundle\FrameworkBundle\Client;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Validator\Constraints\DateTime;

class AuthTest extends WebTestCase

{

    /**
     * @var Client
     */
    protected static $client = null;


    public function testAuth()
    {

        $url ='/api/company';
        $signature = 'abc';
        $provider = 'ibrows';
        $user = 'test';
        $serverHeader = array('HTTP_Authorization'=>"$provider $user:$signature", 'HTTP_Content-Type'=>'json');

        self::$client->request('GET', $url);
        $response = self::$client->getResponse();
        $this->assertEquals(401,$response->getStatusCode());
        $this->assertContains("Authorization header required",$response->getContent());

        self::$client->request('GET', $url, array(),array(),$serverHeader);
        $response = self::$client->getResponse();
        $this->assertEquals(401,$response->getStatusCode());
        $this->assertContains("Date header required",$response->getContent());

        $now = new \DateTime();
        $serverHeader['HTTP_Date'] = $now->format('c');
        self::$client->request('GET', $url, array(),array(),$serverHeader);
        $response = self::$client->getResponse();
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertContains("Signature not valid",$response->getContent());

        $message = "GET\n".md5('')."\njson\n".$serverHeader['HTTP_Date']. "\n\n/api/company" ;

        $secretKey = 'test';
        $digest = hash_hmac('sha1', $message, $secretKey, true);
        $signature =base64_encode($digest);

        $serverHeader['HTTP_Authorization'] = "$provider $user:$signature";
        self::$client->request('GET', $url, array(),array(),$serverHeader);
        $response = self::$client->getResponse();
        $this->assertEquals(302, $response->getStatusCode());



    }



    protected function setUp()
    {
        parent::setUp();
        self::$client = self::createClient();
    }

    protected static function createKernel(array $options = array())
    {
        require_once __DIR__ .'/app/AppKernel.php';
        return new AppKernel(
            'config/config.yml',
            'test',
            true
        );
    }

    protected function tearDown()
    {

    }
}
