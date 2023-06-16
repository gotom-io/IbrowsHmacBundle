<?php

namespace Ibrows\HmacBundle\Security\Authentication;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

class RequestSigner
{
    protected string $provider = 'Test';
    protected array $customHeaders = [];


    public function __construct(string $provider)
    {
        $this->provider = $provider;
    }


    public function getSignature(Request $request): Signature
    {
        $headers = $request->headers;
        if (!$headers->has('Authorization')) {
            throw new CustomUserMessageAuthenticationException('Authorization header required');
        }

        // Check the provider.
        $header = $headers->get('Authorization');
        if (!str_contains($header, $this->provider.' ')) {
            throw new CustomUserMessageAuthenticationException('Invalid provider in authorization header');
        }

        // Split ID and sgnature by an unescaped colon.
        $offset = strlen($this->provider) + 1;
        $credentials = substr($header, $offset);
        $matches = preg_split('@\\\\.(*SKIP)(*FAIL)|:@s', $credentials);
        if (!isset($matches[1])) {
            throw new CustomUserMessageAuthenticationException('Unable to parse ID and signature from authorization header');
        }

        // Ensure the signature is a base64 encoded string.
        if (!preg_match('@^[a-zA-Z0-9+/]+={0,2}$@', $matches[1])) {
            throw new CustomUserMessageAuthenticationException('Invalid signature in authorization header');
        }
        $timestamp = $this->getTimestamp($request);

        return new Signature(
            stripslashes($matches[0]),
            $matches[1],
            $timestamp,
        );
    }

    public function getDate(Request $request): string
    {
        $time = $request->headers->get('Date');
        if (!$time) {
            throw new CustomUserMessageAuthenticationException('Date header required');
        }

        return $time;
    }

    public function getTimestamp(Request $request): int
    {
        $time = $this->getDate($request);
        $timestamp = strtotime($time);
        if (!$timestamp) {
            throw new CustomUserMessageAuthenticationException('Timestamp not valid');
        }

        return $timestamp;
    }

    public function signRequest(Request $request, $secretKey): string
    {
        $message = $this->getMessage($request);
        $digest = hash_hmac('sha1', $message, $secretKey, true);

        return base64_encode($digest);
    }

    public function getMessage(Request $request): string
    {
        $headers = [];
        foreach ($this->customHeaders as $header) {
            if ($request->headers->get($header)) {
                $headers[$header] = $request->headers->get(($header));
            }
        }

        $canonicalizedHeaders = [];
        foreach ($headers as $header => $value) {
            $canonicalizedHeaders[] = strtolower($header).': '.$value;
        }

        sort($canonicalizedHeaders);
        $customHeaders = implode("\n", $canonicalizedHeaders);

        $parts = [
            strtoupper($request->getMethod()),
            md5((string) $request->getContent()),
            $this->getContentType($request),
            $this->getDate($request),
            $customHeaders,
            $request->getRequestUri(),
        ];

        return implode("\n", $parts);
    }

    public function getContentType(Request $request): string
    {
        if (!$request->headers->has('Content-Type')) {
            throw new CustomUserMessageAuthenticationException('Content type header required');
        }

        return strtolower($request->headers->get('Content-Type'));
    }

    public function getAuthorization(Request $request, $id, $secretKey): string
    {
        $signature = $this->signRequest($request, $secretKey);

        return $this->provider.' '.str_replace(':', '\\:', $id).':'.$signature;
    }


    public function setProvider($provider): void
    {
        $this->provider = $provider;
    }

    public function getProvider(): string
    {
        return $this->provider;
    }

    public function addCustomHeader(string $header): void
    {
        $this->customHeaders[] = $header;
    }

    public function setCustomHeaders(array $customHeaders): void
    {
        $this->customHeaders = $customHeaders;
    }

    public function getCustomHeaders(): array
    {
        return $this->customHeaders;
    }

}
