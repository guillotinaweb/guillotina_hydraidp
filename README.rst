guillotina_hydraidp
===================

This addon aims to provide an identity provider through guillotina
for hydra.

It also implements the login and consent flow for hydra.


Endpoints:

 - GET /@users
 - POST /@users {'id', 'username', 'password', 'phone', 'email', 'data'}
 - DELETE /@users/{userid}
 - GET /@users/{userid}
 - GET /@hydra-login
 - POST /@hydra-login
 - GET /@hydra-consent
 - POST /@hydra-consent


Trying it out
-------------

Tests require a hydra instance to be running with the following configuration:

    - OAUTH2_ISSUER_URL=http://localhost:4444
    - OAUTH2_CONSENT_URL=http://localhost:8080/@hydra-consent
    - OAUTH2_LOGIN_URL=http://localhost:8080/@hydra-login
    - DATABASE_URL=postgres://hydra:secret@postgresd:5432/hydra?sslmode=disable
    - SYSTEM_SECRET=youReallyNeedToChangeThis
    - OAUTH2_SHARE_ERROR_DEBUG=1
    - OIDC_SUBJECT_TYPES_SUPPORTED=public,pairwise
    - OIDC_SUBJECT_TYPE_PAIRWISE_SALT=youReallyNeedToChangeThis


Then you need to configure guillotina::

    auth_providers:
      hydra:
        configuration:
          client_id: auth-code-client
          client_secret: secret
          base_url: http://localhost:4444/
          authorize_url: http://localhost:4444/oauth2/auth
          access_token_url: http://localhost:4444/oauth2/token
        state: true
        scope: openid offline
    hydra_db:
      dsn: postgres://hydra:secret@localhost:5432/hydra
      pool_size: 20
    # hydra admin url should be internal, protected!
    hydra_admin_url: http://localhost:4445/


To add an oauth client to hydra::

    curl -XPUT http://localhost:4445/clients/auth-code-client -d '{
        "client_id": "auth-code-client",
        "client_name": "",
        "redirect_uris": [
            "http://localhost:8080/@callback/hydra"
        ],
        "grant_types": [
            "authorization_code",
            "refresh_token"
        ],
        "response_types": [
            "code",
            "id_token"
        ],
        "scope": "openid offline",
        "owner": "",
        "policy_uri": "",
        "allowed_cors_origins": [],
        "tos_uri": "",
        "client_uri": "",
        "logo_uri": "",
        "contacts": [],
        "client_secret_expires_at": 0,
        "subject_type": "public",
        "jwks": {
            "keys": null
        },
        "token_endpoint_auth_method": "client_secret_post",
        "userinfo_signed_response_alg": "none"
    }'


See https://github.com/guillotinaweb/guillotina_hydraidp/blob/master/integration_tests.py
for an example on using the flow.


This is just the API implementation. You will still need to implement the frontend!