IbrowsHmacBundle
=============================

[![Build Status](https://travis-ci.org/ibrows/IbrowsHmacBundle.svg?branch=master)](https://travis-ci.org/ibrows/IbrowsHmacBundle)

Ibrows HMAC Bundle  adds a SecurityListenerFactor which provide a hmac authentication for configured firewall
This is a recommend way to sign and verify RESTful Web API requests



Install & setup the bundle
--------------------------

1. Add IbrowsHmacBundle in your composer.json:

	```js
	{
	    "require": {
	        "ibrows/hmac-bundle": "~1.0",
	    }
	}
	```

2. Now tell composer to download the bundle by running the command:

    ``` bash
    $ php composer.phar update ibrows/hmac-bundle
    ```

3. Add the bundle to your `AppKernel` class

    ``` php
    // app/AppKernerl.php
    public function registerBundles()
    {
        $bundles = array(
            // ...
            new \Ibrows\HmacBundle\IbrowsHmacBundle(),
            // ...
        );
        // ...
    }
    ```
    
4. Sample Configuration of your security.yml

    ``` yml
    security:
        firewalls:
            api:
                pattern:  ^/api
                stateless: true
                anonymous: ~
                provider: api_provider
                ibrows_hmac:
                    authentication_provider_key: me
        access_control:
            - { path: ^/api/, roles: ROLE_API }
        password_hashers:
            Symfony\Component\Security\Core\User\User: plaintext
        providers:
            api_provider:
                memory:
                    users:
                        test:
                            password: test
                            roles:  ['ROLE_API']
    ```

