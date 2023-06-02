security.yml usage example

api_provider:
            memory:
                users:
                    test:
                        password: test
                        roles:  ['ROLE_API']


encoders:
        Symfony\Component\Security\Core\User\User: plaintext

    firewalls:
        api:
            pattern:  ^/api
            stateless: true
            provider: api_provider
            ibrows_hmac:
                authentication_provider_key: ibrows

    access_control:
        - { path: ^/api, role: ROLE_API }
